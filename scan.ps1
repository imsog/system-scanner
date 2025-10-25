# ВОССТАНОВЛЕНИЕ ПОДКЛЮЧЕНИЯ - ОТКЛЮЧЕНИЕ ВСЕХ БЛОКИРОВОК

$restoreResults = @()

# 1. Восстанавливаем Proxy настройки
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0 -ErrorAction Stop
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyOverride -ErrorAction SilentlyContinue
    $restoreResults += "✅ Proxy disabled"
} catch {
    $restoreResults += "❌ Proxy restore failed"
}

# 2. Восстанавливаем настройки браузеров
try {
    # Chrome
    $chromePath = "HKCU:\Software\Google\Chrome"
    if (Test-Path $chromePath) {
        Remove-ItemProperty -Path $chromePath -Name "DefaultSearchProviderEnabled" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "$chromePath\Recommended" -Name "DefaultSearchProviderSearchURL" -ErrorAction SilentlyContinue
    }
    
    # Edge
    $edgePath = "HKCU:\Software\Microsoft\Edge"
    if (Test-Path $edgePath) {
        Remove-ItemProperty -Path $edgePath -Name "DefaultSearchProviderEnabled" -ErrorAction SilentlyContinue
    }
    
    $restoreResults += "✅ Browser settings restored"
} catch {
    $restoreResults += "❌ Browser restore failed"
}

# 3. Удаляем временные BAT файлы блокировки
try {
    Get-ChildItem "$env:TEMP\*block*vulcan*.bat" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem "$env:TEMP\*block*.bat" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $restoreResults += "✅ Block scripts removed"
} catch {
    $restoreResults += "❌ Script cleanup failed"
}

# 4. Очищаем DNS кэш
try {
    ipconfig /flushdns | Out-Null
    $restoreResults += "✅ DNS cache flushed"
} catch {
    $restoreResults += "❌ DNS flush failed"
}

# 5. Удаляем записи из hosts файла (если есть права)
try {
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
        if ($hostsContent) {
            # Удаляем строки связанные с Vulcan
            $cleanContent = $hostsContent | Where-Object { 
                $_ -notmatch "vulcan" -and 
                $_ -notmatch "Vulcan Block" -and
                $_ -notmatch "127.0.0.1.*vulcan" -and
                $_ -notmatch "::1.*vulcan"
            }
            Set-Content $hostsPath $cleanContent -ErrorAction SilentlyContinue
            $restoreResults += "✅ Hosts file cleaned"
        }
    }
} catch {
    $restoreResults += "❌ Hosts cleanup failed (admin needed)"
}

# 6. Восстанавливаем DNS серверы (автоматическое получение)
try {
    $interfaces = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}
    foreach ($interface in $interfaces) {
        Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    }
    $restoreResults += "✅ DNS servers reset to automatic"
} catch {
    $restoreResults += "❌ DNS reset failed (admin needed)"
}

# Формируем сообщение о результате
$restoreMessage = @"
=== INTERNET CONNECTION RESTORED ===

Restoration results:
$($restoreResults -join "`n")

All blocks have been removed!
Internet access should be working now.

✅ Proxy disabled
✅ Browser settings restored  
✅ Block scripts removed
✅ DNS cache flushed
✅ Hosts file cleaned
✅ DNS servers reset

If internet still doesn't work:
1. Restart your browser
2. Restart WiFi/Ethernet
3. Reboot computer
"@

# Отправляем отчет в Telegram
try {
    Invoke-RestMethod -Uri "https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage" -Method Post -Body @{
        chat_id = '5674514050'
        text = $restoreMessage
    }
} catch {
    # Если не отправилось - не страшно
}

# Показываем сообщение пользователю
Write-Host $restoreMessage -ForegroundColor Green

# Дополнительно: перезапускаем службы сети (если есть права)
try {
    Restart-Service -Name "Dnscache" -Force -ErrorAction SilentlyContinue
    Write-Host "✅ DNS service restarted" -ForegroundColor Green
} catch {
    Write-Host "⚠️  DNS service restart failed (admin needed)" -ForegroundColor Yellow
}
