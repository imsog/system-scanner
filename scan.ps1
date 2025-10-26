# ОСТАНОВКА И УДАЛЕНИЕ КЕЙЛОГГЕРОВ

Write-Host "🛑 Stopping keylogger processes..." -ForegroundColor Red

# Останавливаем все процессы кейлоггеров
Get-Process | Where-Object {
    $_.ProcessName -eq "powershell" -and 
    $_.CommandLine -like "*vulcan_logger*" -or 
    $_.CommandLine -like "*search_logger*" -or
    $_.CommandLine -like "*keylogger*"
} | Stop-Process -Force

# Дополнительная проверка через WMI
Get-WmiObject Win32_Process | Where-Object {
    $_.CommandLine -like "*vulcan_logger*" -or 
    $_.CommandLine -like "*search_logger*" -or
    $_.CommandLine -like "*keylogger*"
} | ForEach-Object {
    try {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    } catch {}
}

Write-Host "✅ Keylogger processes stopped" -ForegroundColor Green

# УДАЛЕНИЕ ФАЙЛОВ
Write-Host "🗑️ Deleting keylogger files..." -ForegroundColor Yellow

$filesToDelete = @(
    "$env:TEMP\vulcan_logger.ps1",
    "$env:TEMP\search_logger.ps1", 
    "$env:TEMP\keylogger.ps1",
    "$env:TEMP\Cookies_*",
    "$env:TEMP\Cookies.zip",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\SystemMonitor.lnk",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\SearchMonitor.lnk"
)

foreach ($file in $filesToDelete) {
    if (Test-Path $file) {
        try {
            Remove-Item $file -Force -ErrorAction SilentlyContinue
            Write-Host "Deleted: $file" -ForegroundColor Green
        } catch {
            Write-Host "Failed to delete: $file" -ForegroundColor Red
        }
    }
}

# УДАЛЕНИЕ ИЗ АВТОЗАГРУЗКИ РЕЕСТРА
Write-Host "🔧 Cleaning registry..." -ForegroundColor Yellow

$registryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)

$registryKeys = @("SystemMonitor", "SearchMonitor", "Keylogger", "WindowsUpdate")

foreach ($path in $registryPaths) {
    if (Test-Path $path) {
        foreach ($key in $registryKeys) {
            try {
                Remove-ItemProperty -Path $path -Name $key -Force -ErrorAction SilentlyContinue
                Write-Host "Removed registry key: $path\$key" -ForegroundColor Green
            } catch {}
        }
    }
}

# ОЧИСТКА ПЛАНИРОВЩИКА ЗАДАЧ
Write-Host "📅 Cleaning task scheduler..." -ForegroundColor Yellow

$tasks = @("SystemMonitor", "SearchMonitor", "WindowsUpdateTask")

foreach ($task in $tasks) {
    try {
        Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
        Write-Host "Removed scheduled task: $task" -ForegroundColor Green
    } catch {}
}

# ОЧИСТКА EVENT LOGS (если были логи)
Write-Host "📋 Cleaning event logs..." -ForegroundColor Yellow

try {
    wevtutil el | Where-Object { $_ -like "*Keylogger*" -or $_ -like "*Monitor*" } | ForEach-Object {
        wevtutil cl $_
    }
} catch {}

# ФИНАЛЬНАЯ ПРОВЕРКА
Write-Host "🔍 Final check..." -ForegroundColor Cyan

Write-Host "`nChecking for remaining processes:" -ForegroundColor White
$remaining = Get-WmiObject Win32_Process | Where-Object {
    $_.CommandLine -like "*vulcan_logger*" -or 
    $_.CommandLine -like "*search_logger*" -or
    $_.CommandLine -like "*keylogger*"
}

if ($remaining) {
    Write-Host "❌ Remaining processes found:" -ForegroundColor Red
    $remaining | ForEach-Object { Write-Host "  - $($_.CommandLine)" -ForegroundColor Red }
} else {
    Write-Host "✅ No keylogger processes found" -ForegroundColor Green
}

Write-Host "`nChecking for remaining files:" -ForegroundColor White
$remainingFiles = Get-ChildItem $env:TEMP -Filter "*logger*" -ErrorAction SilentlyContinue
if ($remainingFiles) {
    Write-Host "❌ Remaining files found:" -ForegroundColor Red
    $remainingFiles | ForEach-Object { Write-Host "  - $($_.FullName)" -ForegroundColor Red }
} else {
    Write-Host "✅ No keylogger files found" -ForegroundColor Green
}

Write-Host "`nChecking registry:" -ForegroundColor White
$remainingReg = foreach ($path in $registryPaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | 
        Where-Object { $_.PSObject.Properties.Name -match "SystemMonitor|SearchMonitor|Keylogger" }
    }
}

if ($remainingReg) {
    Write-Host "❌ Remaining registry entries:" -ForegroundColor Red
    $remainingReg | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
} else {
    Write-Host "✅ No keylogger registry entries found" -ForegroundColor Green
}

# ПЕРЕЗАПУСК ПРОВОДНИКА ДЛЯ ПРИМЕНЕНИЯ ИЗМЕНЕНИЙ
Write-Host "`n🔄 Restarting Explorer..." -ForegroundColor Magenta
try {
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process explorer.exe
} catch {}

Write-Host "`n" + "="*50 -ForegroundColor Cyan
Write-Host "🧹 CLEANUP COMPLETED!" -ForegroundColor Green
Write-Host "All keylogger components have been removed from the system." -ForegroundColor White
Write-Host "="*50 -ForegroundColor Cyan

# ДОПОЛНИТЕЛЬНАЯ БЕЗОПАСНОСТЬ - ОЧИСТКА КОРЗИНЫ
Write-Host "`n🗑️ Emptying recycle bin..." -ForegroundColor Yellow
try {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "✅ Recycle bin emptied" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Could not empty recycle bin" -ForegroundColor Yellow
}

Start-Sleep -Seconds 3
