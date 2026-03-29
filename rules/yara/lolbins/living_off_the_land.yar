/*
    BlueSentinel v2.0 - Living off the Land Binary Detection Rules
    Author: Valon Canolli
    Description: Detects abuse of legitimate Windows binaries (LOLBins)
*/

rule CertUtil_Abuse {
    meta:
        description = "Detects certutil abuse for download and decode operations"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1218"
        tags = "lolbin, certutil, high"
    strings:
        $certutil = "certutil" ascii wide nocase
        $decode = "-decode" ascii wide nocase
        $urlcache = "-urlcache" ascii wide nocase
        $split = "-split" ascii wide nocase
        $f_flag = "-f" ascii wide
        $http = "http://" ascii wide nocase
        $https = "https://" ascii wide nocase
        $ftp = "ftp://" ascii wide nocase
        $temp = "\\temp\\" ascii wide nocase
        $appdata = "\\AppData\\" ascii wide nocase
    condition:
        $certutil and (
            ($urlcache and ($http or $https or $ftp)) or
            ($decode and ($temp or $appdata)) or
            ($split and $f_flag and ($http or $https))
        )
}

rule MSHTA_Abuse {
    meta:
        description = "Detects mshta.exe abused for remote script execution (Squiblydoo variant)"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1218.005"
        tags = "lolbin, mshta, high"
    strings:
        $mshta = "mshta" ascii wide nocase
        $vbscript = "vbscript:" ascii wide nocase
        $javascript = "javascript:" ascii wide nocase
        $http_remote = "http://" ascii wide nocase
        $https_remote = "https://" ascii wide nocase
        $hta_ext = ".hta" ascii wide nocase
        $exec1 = "Execute(" ascii wide nocase
        $exec2 = "CreateObject" ascii wide nocase
        $wsh = "WScript.Shell" ascii wide nocase
    condition:
        $mshta and (
            $vbscript or $javascript or
            ($http_remote and $hta_ext) or
            ($https_remote and $hta_ext) or
            ($exec1 and $exec2) or
            ($exec2 and $wsh)
        )
}

rule Regsvr32_Squiblydoo {
    meta:
        description = "Detects regsvr32 squiblydoo COM scriptlet execution"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1218.010"
        tags = "lolbin, regsvr32, high"
    strings:
        $regsvr32 = "regsvr32" ascii wide nocase
        $scrobj = "scrobj.dll" ascii wide nocase
        $scriptlet = ".sct" ascii wide nocase
        $s_flag = "/s" ascii wide
        $u_flag = "/u" ascii wide
        $i_flag = "/i:" ascii wide
        $http = "http://" ascii wide nocase
        $https = "https://" ascii wide nocase
    condition:
        $regsvr32 and (
            ($scrobj and $s_flag) or
            ($u_flag and $scrobj) or
            ($scriptlet and ($http or $https)) or
            ($i_flag and ($http or $https) and $s_flag)
        )
}

rule WMIC_Abuse {
    meta:
        description = "Detects WMIC abuse for process execution and lateral movement"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1047"
        tags = "lolbin, wmic, high"
    strings:
        $wmic = "wmic" ascii wide nocase
        $process_create = "process call create" ascii wide nocase
        $shadowcopy = "shadowcopy delete" ascii wide nocase
        $useraccount = "useraccount" ascii wide nocase
        $format = "/format:" ascii wide nocase
        $xsl_url = "http" ascii wide nocase
        $cmd = "cmd.exe" ascii wide nocase
        $ps = "powershell" ascii wide nocase
    condition:
        $wmic and (
            $process_create or
            $shadowcopy or
            $useraccount or
            ($format and $xsl_url) or
            ($process_create and ($cmd or $ps))
        )
}

rule BITSAdmin_Abuse {
    meta:
        description = "Detects bitsadmin used for file download and persistence"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1197"
        tags = "lolbin, bitsadmin, high"
    strings:
        $bitsadmin = "bitsadmin" ascii wide nocase
        $transfer = "/transfer" ascii wide nocase
        $download = "/download" ascii wide nocase
        $create = "/create" ascii wide nocase
        $setnotify = "/setnotifycmdline" ascii wide nocase
        $resume = "/resume" ascii wide nocase
        $http = "http://" ascii wide nocase
        $https = "https://" ascii wide nocase
    condition:
        $bitsadmin and (
            ($transfer and ($http or $https)) or
            ($download and ($http or $https)) or
            ($setnotify and $create) or
            ($create and $setnotify and $resume)
        )
}
