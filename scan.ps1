# cleanup_keylogger.ps1 - Полное удаление кейлоггера Vulcan

Write-Host "=== ОЧИСТКА СИСТЕМЫ ОТ КЕЙЛОГГЕРА ===" -ForegroundColor Red

# 1. ОСТАНОВКА ПРОЦЕССОВ КЕЙЛОГГЕРА
Write-Host "`n[1] Остановка процессов кейлоггера..." -ForegroundColor Yellow

# Поиск и завершение процессов кейлоггера
$processes = Get-WmiObject Win32_Process | Where-Object { 
    $_.CommandLine -like "*vulcan_logger*" -or 
    $_.CommandLine -like "*SystemMonitor*" -or
    $_.CommandLine -like "*proxy_guard*" -or
    $_.CommandLine -like "*WindowsUpdateService*"
}

if ($processes) {
    foreach ($process in $processes) {
        try {
            Write-Host "   Завершение процесса: $($process.ProcessId) - $($process.Name)"
            $process.Terminate() | Out-Null
            Start-Sleep -Milliseconds 500
        } catch {
            Write-Host "   Ошибка завершения процесса $($process.ProcessId): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "   ✓ Процессы кейлоггера остановлены" -ForegroundColor Green
} else {
    Write-Host "   ✓ Активных процессов кейлоггера не найдено" -ForegroundColor Green
}

# Дополнительная проверка через Get-Process
Get-Process | Where-Object { 
    $_.ProcessName -eq "powershell" -and 
    $_.MainWindowTitle -eq "" -and 
    $_.StartInfo.Arguments -like "*vulcan_logger*"
} | ForEach-Object {
    try {
        Write-Host "   Завершение скрытого PowerShell: $($_.Id)"
        $_.Kill()
    } catch {}
}

# 2. УДАЛЕНИЕ АВТОЗАГРУЗКИ ИЗ РЕЕСТРА
Write-Host "`n[2] Удаление автозагрузки из реестра..." -ForegroundColor Yellow

$registryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$keysToRemove = @(
    "SystemMonitor",
    "WindowsUpdateService", 
    "ProxyGuard",
    "VulcanLogger"
)

foreach ($regPath in $registryPaths) {
    if (Test-Path $regPath) {
        foreach ($key in $keysToRemove) {
            try {
                Remove-ItemProperty -Path $regPath -Name $key -ErrorAction SilentlyContinue
                Write-Host "   ✓ Удален ключ: $key" -ForegroundColor Green
            } catch {
                Write-Host "   Ключ не найден: $key" -ForegroundColor Gray
            }
        }
    }
}

# 3. УДАЛЕНИЕ ФАЙЛОВ КЕЙЛОГГЕРА
Write-Host "`n[3] Удаление файлов кейлоггера..." -ForegroundColor Yellow

$filesToRemove = @(
    "$env:TEMP\vulcan_logger.ps1",
    "$env:TEMP\proxy_guard.ps1",
    "$env:TEMP\Cookies_*.zip",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vulcan_logger.*",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\SystemMonitor.*"
)

foreach ($file in $filesToRemove) {
    try {
        if (Test-Path $file) {
            Remove-Item -Path $file -Force -ErrorAction Stop
            Write-Host "   ✓ Удален файл: $(Split-Path $file -Leaf)" -ForegroundColor Green
        }
    } catch {
        Write-Host "   Ошибка удаления $file : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Удаление временных папок cookies
Get-ChildItem "$env:TEMP" -Directory | Where-Object Name -like "Cookies_*" | ForEach-Object {
    try {
        Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop
        Write-Host "   ✓ Удалена папка: $($_.Name)" -ForegroundColor Green
    } catch {
        Write-Host "   Ошибка удаления папки $($_.Name)" -ForegroundColor Red
    }
}

# 4. ВОССТАНОВЛЕНИЕ НАСТРОЕК ПРОКСИ
Write-Host "`n[4] Восстановление настроек сети..." -ForegroundColor Yellow

try {
    # Отключение прокси в Internet Settings
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -ErrorAction SilentlyContinue
    
    Write-Host "   ✓ Настройки прокси восстановлены" -ForegroundColor Green
} catch {
    Write-Host "   Ошибка восстановления настроек прокси" -ForegroundColor Red
}

# 5. ОЧИСТКА НАСТРОЕК БРАУЗЕРОВ
Write-Host "`n[5] Очистка настроек браузеров..." -ForegroundColor Yellow

$browserPaths = @(
    "HKCU:\Software\Google\Chrome",
    "HKCU:\Software\Microsoft\Edge", 
    "HKCU:\Software\Mozilla\Firefox"
)

$browserKeys = @("ProxyMode", "ProxyServer", "ProxyEnable")

foreach ($browserPath in $browserPaths) {
    if (Test-Path $browserPath) {
        foreach ($key in $browserKeys) {
            try {
                Remove-ItemProperty -Path $browserPath -Name $key -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-Host "   ✓ Очищены настройки: $(Split-Path $browserPath -Leaf)" -ForegroundColor Green
    }
}

# 6. ПРОВЕРКА ОСТАТОЧНЫХ СЛЕДОВ
Write-Host "`n[6] Проверка остаточных следов..." -ForegroundColor Yellow

# Проверка процессов
$remainingProcesses = Get-WmiObject Win32_Process | Where-Object { 
    $_.CommandLine -like "*vulcan_logger*" -or 
    $_.CommandLine -like "*SystemMonitor*"
}

if ($remainingProcesses) {
    Write-Host "   ⚠ Обнаружены остаточные процессы:" -ForegroundColor Yellow
    $remainingProcesses | ForEach-Object { 
        Write-Host "      - $($_.ProcessId): $($_.Name)" -ForegroundColor Yellow
    }
} else {
    Write-Host "   ✓ Остаточных процессов не найдено" -ForegroundColor Green
}

# Проверка автозагрузки
$remainingKeys = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
    Get-Member -MemberType NoteProperty | 
    Where-Object { $_.Name -in $keysToRemove }

if ($remainingKeys) {
    Write-Host "   ⚠ Обнаружены остаточные ключи автозагрузки:" -ForegroundColor Yellow
    $remainingKeys | ForEach-Object { Write-Host "      - $($_.Name)" -ForegroundColor Yellow }
} else {
    Write-Host "   ✓ Остаточных ключей автозагрузки не найдено" -ForegroundColor Green
}

# 7. ФИНАЛЬНАЯ ПЕРЕЗАГРУЗКА ПРОВОДНИКА
Write-Host "`n[7] Перезагрузка проводника Windows..." -ForegroundColor Yellow

try {
    Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
    Start-Sleep 2
    Start-Process "explorer.exe"
    Write-Host "   ✓ Проводник перезагружен" -ForegroundColor Green
} catch {
    Write-Host "   ⚠ Не удалось перезагрузить проводник" -ForegroundColor Yellow
}

# ИТОГОВОЕ СООБЩЕНИЕ
Write-Host "`n" + "="*50 -ForegroundColor Green
Write-Host "ОЧИСТКА ЗАВЕРШЕНА!" -ForegroundColor Green
Write-Host "="*50 -ForegroundColor Green

Write-Host "`nРекомендуемые действия:" -ForegroundColor Cyan
Write-Host "1. Перезагрузите компьютер для полной очистки" -ForegroundColor White
Write-Host "2. Проверьте настройки сети в Панели управления" -ForegroundColor White  
Write-Host "3. Проверьте автозагрузку в Диспетчере задач" -ForegroundColor White
Write-Host "4. Сканируйте систему антивирусом" -ForegroundColor White

Write-Host "`nДля полной гарантии выполните перезагрузку компьютера!" -ForegroundColor Yellow

# Запрос на перезагрузку
$reboot = Read-Host "`nВыполнить перезагрузку сейчас? (y/n)"
if ($reboot -eq 'y' -or $reboot -eq 'Y') {
    Write-Host "Перезагрузка через 5 секунд..." -ForegroundColor Yellow
    Start-Sleep 5
    Restart-Computer -Force
}
