/*
    BlueSentinel v2.0 - Scheduled Task Persistence Rules
    Author: Valon Canolli
    Description: Detects scheduled task creation for persistence
*/

rule Scheduled_Task_Creation_API {
    meta:
        description = "Detects scheduled task creation via COM API"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1053.005"
        tags = "persistence, scheduled_tasks, high"
    strings:
        $com1 = "{148BD52A-A2AB-11CE-B11F-00AA00530503}" ascii wide  // Task Scheduler COM
        $com2 = "Schedule.Service" ascii wide
        $com3 = "ITaskService" ascii wide
        $com4 = "ITaskFolder" ascii wide
        $method1 = "RegisterTask" ascii wide
        $method2 = "RegisterTaskDefinition" ascii wide
        $schtasks1 = "schtasks.exe" ascii wide nocase
        $schtasks2 = "/create" ascii wide nocase
        $schtasks3 = "/sc" ascii wide nocase
        $trigger1 = "TASK_TRIGGER_LOGON" ascii wide
        $trigger2 = "TASK_TRIGGER_BOOT" ascii wide
    condition:
        (1 of ($com*) and 1 of ($method*)) or
        ($schtasks1 and $schtasks2 and $schtasks3) or
        (1 of ($trigger*) and 1 of ($method*))
}

rule Malicious_Scheduled_Task_XML {
    meta:
        description = "Detects suspicious scheduled task XML content"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1053.005"
        tags = "persistence, scheduled_tasks, high"
    strings:
        $xml_root = "<?xml version=" ascii
        $task_tag = "<Task version=" ascii
        $exec1 = "<Command>powershell" ascii nocase
        $exec2 = "<Command>cmd.exe" ascii nocase
        $exec3 = "<Command>wscript" ascii nocase
        $exec4 = "<Command>mshta" ascii nocase
        $hidden1 = "<Hidden>true</Hidden>" ascii nocase
        $logon = "<LogonTrigger>" ascii nocase
        $boot = "<BootTrigger>" ascii nocase
        $suspicious_arg1 = "-enc" ascii nocase
        $suspicious_arg2 = "-w hidden" ascii nocase
        $suspicious_arg3 = "downloadstring" ascii nocase
    condition:
        $xml_root and $task_tag and
        1 of ($exec*) and
        (1 of ($hidden1, $logon, $boot) or 1 of ($suspicious_arg*))
}

rule Scheduled_Task_Command_Line {
    meta:
        description = "Detects malicious scheduled task creation via command line"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1053.005"
        tags = "persistence, scheduled_tasks, high"
    strings:
        $schtasks = "schtasks" ascii wide nocase
        $create = "/create" ascii wide nocase
        $onlogon = "/sc onlogon" ascii wide nocase
        $onstartup = "/sc onstart" ascii wide nocase
        $daily = "/sc daily" ascii wide nocase
        $powershell = "powershell" ascii wide nocase
        $encoded = "-EncodedCommand" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase
        $download = "DownloadString" ascii wide nocase
    condition:
        $schtasks and $create and
        ($onlogon or $onstartup or $daily) and
        ($powershell or $encoded or $hidden or $download)
}
