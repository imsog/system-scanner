# === ПОЛНОЕ УДАЛЕНИЕ КЕЙЛОГГЕРА ===

# 1. Остановка процессов кейлоггера
Get-Process | Where-Object { 
    $_.ProcessName -eq "powershell" -and $_.MainWindowTitle -like "*windowsupdate*"
} | Stop-Process -Force

# 2. Удаление файла кейлоггера
Remove-Item "$env:APPDATA\Microsoft\Windows\System32\windowsupdate.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\sysmon.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\search_logger.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\global_logger.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\vulcan_logger.ps1" -Force -ErrorAction SilentlyContinue

# 3. Удаление автозагрузки
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSystemMonitor" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemMonitor" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SearchMonitor" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateService" -ErrorAction SilentlyContinue

# 4. Очистка заданий PowerShell
Get-Job | Remove-Job -Force

# 5. Дополнительная очистка реестра
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSystemMonitor" -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\SystemMonitor" -ErrorAction SilentlyContinue

# 6. Проверка что процессы убиты
taskkill /f /im powershell.exe /t 2>$null

Write-Host "✅ Keylogger completely removed!"
Write-Host "✅ All files deleted"
Write-Host "✅ Autostart entries removed"
Write-Host "✅ Processes terminated"
