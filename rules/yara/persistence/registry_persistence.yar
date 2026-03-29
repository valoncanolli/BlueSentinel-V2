/*
    BlueSentinel v2.0 - Registry Persistence Detection Rules
    Author: Valon Canolli
    Description: Detects registry-based persistence mechanisms
*/

rule Registry_Run_Key_Persistence {
    meta:
        description = "Detects programs adding entries to registry Run keys"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1547.001"
        tags = "persistence, registry, high"
    strings:
        $run1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $run3 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $api_set = "RegSetValueEx" ascii wide
        $api_open = "RegOpenKeyEx" ascii wide
        $api_create = "RegCreateKeyEx" ascii wide
        $suspicious_val1 = "powershell" ascii wide nocase
        $suspicious_val2 = "cmd.exe" ascii wide nocase
        $suspicious_val3 = "wscript" ascii wide nocase
        $suspicious_val4 = "mshta" ascii wide nocase
    condition:
        (1 of ($run*) and $api_set) or
        (1 of ($run*) and $api_open and $api_create) or
        (1 of ($run*) and 1 of ($suspicious_val*))
}

rule Winlogon_Hijack {
    meta:
        description = "Detects Winlogon registry key hijacking for persistence"
        author = "BlueSentinel v2.0"
        severity = "critical"
        mitre_technique = "T1547.004"
        tags = "persistence, winlogon, critical"
    strings:
        $key1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide nocase
        $key2 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot" ascii wide nocase
        $val1 = "Userinit" ascii wide
        $val2 = "Shell" ascii wide
        $val3 = "Notify" ascii wide
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "RegCreateKeyEx" ascii wide
    condition:
        ($key1 or $key2) and ($val1 or $val2 or $val3) and ($api1 or $api2)
}

rule Image_File_Execution_Options_Hijack {
    meta:
        description = "Detects IFEO debugger hijacking for persistence or privilege escalation"
        author = "BlueSentinel v2.0"
        severity = "critical"
        mitre_technique = "T1546.012"
        tags = "persistence, ifeo, critical"
    strings:
        $key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" ascii wide nocase
        $debugger = "Debugger" ascii wide
        $globaldump = "GlobalFlag" ascii wide
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "RegCreateKeyEx" ascii wide
        $payload1 = "cmd.exe" ascii wide nocase
        $payload2 = "powershell" ascii wide nocase
        $payload3 = "mshta" ascii wide nocase
        $payload4 = "wscript" ascii wide nocase
    condition:
        $key and ($debugger or $globaldump) and ($api1 or $api2) and 1 of ($payload*)
}
