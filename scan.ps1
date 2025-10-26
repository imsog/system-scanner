# Проверяем что процессов нет
$processes = Get-Process | Where-Object { 
    $_.ProcessName -eq "powershell" -and 
    ($_.CommandLine -like "*monitor*" -or $_.CommandLine -like "*vulcan*")
}
if ($processes) {
    Write-Host "❌ Найдены процессы кейлоггера!" -ForegroundColor Red
    $processes | Stop-Process -Force
} else {
    Write-Host "✅ Процессы кейлоггера не найдены" -ForegroundColor Green
}

# Проверяем что файлов нет
$files = Get-ChildItem "$env:TEMP\*vulcan*.ps1" -ErrorAction SilentlyContinue
if ($files) {
    Write-Host "❌ Найдены файлы кейлоггера!" -ForegroundColor Red
    $files | Remove-Item -Force
} else {
    Write-Host "✅ Файлы кейлоггера не найдены" -ForegroundColor Green
}

# Проверяем автозагрузку
$registry = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
$suspiciousEntries = $registry.PSObject.Properties | Where-Object { 
    $_.Name -like "*Monitor*" -or $_.Name -like "*vulcan*"
}
if ($suspiciousEntries) {
    Write-Host "❌ Найдены записи в автозагрузке!" -ForegroundColor Red
} else {
    Write-Host "✅ Автозагрузка чиста" -ForegroundColor Green
}
