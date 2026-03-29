/*
    BlueSentinel v2.0 - C2 Network Pattern Detection Rules
    Author: Valon Canolli
    Description: Detects C2 communication patterns in network traffic and files
*/

rule CobaltStrike_Malleable_C2_HTTP {
    meta:
        description = "Detects Cobalt Strike malleable C2 HTTP header patterns"
        author = "BlueSentinel v2.0"
        severity = "critical"
        mitre_technique = "T1071.001"
        tags = "c2, cobalt_strike, network, critical"
    strings:
        $ua1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" ascii
        $ua2 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" ascii
        $header1 = "Accept: text/html,application/xhtml+xml" ascii
        $header2 = "Accept-Language: en-US" ascii
        $pipe_name1 = "msagent_" ascii
        $pipe_name2 = "MSSE-" ascii
        $cobalt_uri1 = "/jquery-3.3.1.slim.min.js" ascii
        $cobalt_uri2 = "/push" ascii
        $cobalt_uri3 = "/activity" ascii
        $cobalt_post1 = "Content-Type: application/octet-stream" ascii
        $checksum8 = { 2F [1-8] 2F [1-8] 41 41 41 41 }  // /AAAA CS URI pattern
    condition:
        ($ua1 or $ua2) and ($header1 or $header2) or
        1 of ($pipe_name*) or
        (2 of ($cobalt_uri*) and $cobalt_post1) or
        $checksum8
}

rule Generic_C2_Beacon_Pattern {
    meta:
        description = "Detects generic C2 beacon HTTP request structures"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1071.001"
        tags = "c2, network, high"
    strings:
        $beacon_interval = "sleep" ascii nocase
        $jitter = "jitter" ascii nocase
        $checkin1 = "checkin" ascii nocase
        $checkin2 = "check-in" ascii nocase
        $beacon_id = "bid=" ascii nocase
        $session_id = "session=" ascii nocase
        $raw_get = "GET / HTTP/1." ascii
        $raw_post = "POST / HTTP/1." ascii
        $base64_header = "Authorization: Basic " ascii
        $cookie_beacon = "Cookie: " ascii
        $accept_any = "Accept: */*" ascii
    condition:
        ($raw_get or $raw_post) and $accept_any and
        (1 of ($beacon_id, $session_id, $checkin1, $checkin2)) or
        (3 of them)
}

rule DNS_Tunneling_Patterns {
    meta:
        description = "Detects DNS tunneling patterns — high entropy subdomains"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1071.004"
        tags = "c2, dns_tunnel, network, high"
    strings:
        $iodine = "iodine" ascii nocase
        $dns2tcp = "dns2tcp" ascii nocase
        $dnscat = "dnscat" ascii nocase
        $encoded_subdomain = /[a-zA-Z0-9+\/]{30,}\./ ascii
        $txt_request = "TXT" ascii
        $null_request = "NULL" ascii
        $cname_chain = /[a-z0-9]{20,}\.[a-z0-9]{20,}\./ ascii
    condition:
        1 of ($iodine, $dns2tcp, $dnscat) or
        ($encoded_subdomain and ($txt_request or $null_request)) or
        $cname_chain
}
