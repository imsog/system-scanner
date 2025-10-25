# Остановка процессов
Get-WmiObject Win32_Process | Where-Object { 
    $_.CommandLine -like "*proxy_guard*" -or 
    $_.CommandLine -like "*vulcan_logger*" 
} | ForEach-Object { $_.Terminate() }

# Удаление автозагрузки
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateService" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemMonitor" -ErrorAction SilentlyContinue

# Восстановление прокси
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -ErrorAction SilentlyContinue

# Очистка браузеров
Remove-ItemProperty -Path "HKCU:\Software\Google\Chrome" -Name "ProxyMode" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Google\Chrome" -Name "ProxyServer" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Edge" -Name "ProxyMode" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Edge" -Name "ProxyServer" -ErrorAction SilentlyContinue

# Удаление файлов
$filesToRemove = @(
    "$env:TEMP\proxy_guard.ps1",
    "$env:TEMP\vulcan_logger.ps1", 
    "$env:TEMP\Cookies_$env:USERNAME.zip"
)
$filesToRemove | ForEach-Object { Remove-Item $_ -Force -ErrorAction SilentlyContinue }

# Удаление папок cookies
Get-ChildItem "$env:TEMP" -Directory | Where-Object Name -like "Cookies_*" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Очистка завершена! Перезагрузите компьютер для полного применения изменений." -ForegroundColor Green
