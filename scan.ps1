# Быстрая очистка (запустить от администратора)
Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like "*vulcan_logger*" } | ForEach-Object { $_.Terminate() }
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemMonitor" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateService" -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\vulcan_logger.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\proxy_guard.ps1" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
Write-Host "Быстрая очистка завершена! Рекомендуется перезагрузка." -ForegroundColor Green
