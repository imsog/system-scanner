# Полная очистка кейлоггера
Write-Host "🧹 Начинаем очистку кейлоггера..." -ForegroundColor Yellow

# 1. Останавливаем все процессы PowerShell (осторожно!)
Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*monitor*" -or 
    $_.CommandLine -like "*vulcan*" -or
    $_.CommandLine -like "*logger*"
} | Stop-Process -Force

# 2. Удаляем все файлы кейлоггера
$filesToDelete = @(
    "system_monitor.ps1",
    "vulcan_monitor.ps1", 
    "vulcan_debug.ps1",
    "vulcan_logger_advanced.ps1",
    "vulcan_logger_timer.ps1",
    "vulcan_simple.ps1"
)

foreach ($file in $filesToDelete) {
    Remove-Item "$env:TEMP\$file" -Force -ErrorAction SilentlyContinue
}

# 3. Удаляем все записи автозагрузки
$registryEntries = @(
    "SystemMonitor",
    "VulcanMonitor", 
    "VulcanDebug",
    "WindowsMonitor"
)

foreach ($entry in $registryEntries) {
    Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $entry -ErrorAction SilentlyContinue
}

# 4. Очищаем временные файлы
Remove-Item "$env:TEMP\Cookies_*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\Cookies_*.zip" -Force -ErrorAction SilentlyContinue

Write-Host "✅ Кейлоггер полностью удален!" -ForegroundColor Green
Write-Host "📁 Файлы удалены из: $env:TEMP" -ForegroundColor Cyan
Write-Host "🔧 Автозагрузка очищена" -ForegroundColor Cyan
