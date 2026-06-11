/*
  Basic YARA rules for common malware indicators.
  Complements ML model with explainable signatures.
*/

rule Suspicious_Imports
{
    meta:
        description = "Suspicious Windows API imports commonly used by malware"
        author = "AI Antivirus"
        severity = "medium"

    strings:
        $inject = "CreateRemoteThread" ascii wide
        $inject2 = "WriteProcessMemory" ascii wide
        $inject3 = "VirtualAllocEx" ascii wide
        $inject4 = "OpenProcess" ascii wide
        $hide = "SetWindowsHookEx" ascii wide
        $hide2 = "UnhookWindowsHookEx" ascii wide
        $persist = "RegSetValueEx" ascii wide
        $persist2 = "RegCreateKeyEx" ascii wide
        $network = "InternetOpen" ascii wide
        $network2 = "HttpSendRequest" ascii wide
        $network3 = "URLDownloadToFile" ascii wide
        $anti = "IsDebuggerPresent" ascii wide
        $anti2 = "CheckRemoteDebuggerPresent" ascii wide
        $anti3 = "OutputDebugString" ascii wide
        $shell = "WinExec" ascii wide
        $shell2 = "ShellExecute" ascii wide
        $shell3 = "system" ascii wide

    condition:
        4 of them
}

rule Packed_Executable
{
    meta:
        description = "Indicators of packed/obfuscated executables"
        author = "AI Antivirus"
        severity = "medium"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $aspack = "aspack" ascii nocase
        $pecompact = "PEC2" ascii
        $themida = "Themida" ascii nocase
        $vmp = "VMProtect" ascii nocase
        $enig = "Enigma" ascii nocase

    condition:
        any of them
}

rule Suspicious_Strings
{
    meta:
        description = "Suspicious strings often found in malware"
        author = "AI Antivirus"
        severity = "high"

    strings:
        $ransom1 = "bitcoin" ascii nocase
        $ransom2 = "ransom" ascii nocase
        $ransom3 = "decrypt" ascii nocase
        $ransom4 = "encrypt" ascii nocase
        $ransom5 = ".locked" ascii nocase
        $ransom6 = ".encrypted" ascii nocase
        $crypto1 = "cryptocurrency" ascii nocase
        $crypto2 = "wallet.dat" ascii nocase
        $miner1 = "stratum" ascii nocase
        $miner2 = "xmrig" ascii nocase
        $miner3 = "ccminer" ascii nocase
        $backdoor = "backdoor" ascii nocase
        $keylog = "keylog" ascii nocase
        $rat = "remote administration" ascii nocase

    condition:
        3 of them
}

rule AutoIt_Compiled
{
    meta:
        description = "AutoIt compiled scripts (often used for malware)"
        author = "AI Antivirus"
        severity = "medium"

    strings:
        $autoit1 = "AutoIt" ascii
        $autoit2 = "AU3" ascii

    condition:
        all of them
}

rule PowerShell_Download_Execute
{
    meta:
        description = "PowerShell download and execute patterns"
        author = "AI Antivirus"
        severity = "high"

    strings:
        $ps1 = "Invoke-Expression" ascii wide nocase
        $ps2 = "IEX" ascii wide nocase
        $ps3 = "DownloadString" ascii wide nocase
        $ps4 = "DownloadFile" ascii wide nocase
        $ps5 = "WebClient" ascii wide nocase
        $ps6 = "Invoke-WebRequest" ascii wide nocase
        $ps7 = "Start-Process" ascii wide nocase
        $ps8 = "Hidden" ascii wide nocase
        $ps9 = "Bypass" ascii wide nocase

    condition:
        3 of them
}

rule Crypto_Mining
{
    meta:
        description = "Cryptocurrency mining indicators"
        author = "AI Antivirus"
        severity = "high"

    strings:
        $pool1 = "stratum+tcp://" ascii
        $pool2 = "stratum+ssl://" ascii
        $wallet1 = "wallet" ascii nocase
        $wallet2 = "miner" ascii nocase
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "ethash" ascii nocase
        $algo3 = "randomx" ascii nocase
        $coin1 = "monero" ascii nocase
        $coin2 = "bitcoin" ascii nocase
        $coin3 = "ethereum" ascii nocase

    condition:
        2 of them
}

rule Embedded_PE
{
    meta:
        description = "Embedded PE file (droppers)"
        author = "AI Antivirus"
        severity = "medium"

    strings:
        $mz = { 4D 5A }  // MZ header
        $pe = { 50 45 00 00 }  // PE header

    condition:
        $mz at 0 and $pe in (0..filesize)
        and
        // More than one MZ header suggests embedded PE
        #mz > 1
}

rule High_Entropy
{
    meta:
        description = "High entropy section (possible packing/encryption)"
        author = "AI Antivirus"
        severity = "low"

    condition:
        // This requires external entropy calculation
        // Placeholder for ML integration
        false
}