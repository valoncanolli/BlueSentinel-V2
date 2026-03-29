/*
    BlueSentinel v2.0 - DNS Tunneling Detection Rules
    Author: Valon Canolli
    Description: Detects DNS-based data exfiltration and C2 tunneling
*/

rule DNS_Tunnel_Tool_Signatures {
    meta:
        description = "Detects known DNS tunneling tool signatures"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1071.004"
        tags = "dns_tunnel, c2, high"
    strings:
        $iodine_str = "iodine v" ascii
        $dns2tcp_str = "dns2tcp" ascii nocase
        $dnscat_str = "dnscat2" ascii nocase
        $heyoka_str = "heyoka" ascii nocase
        $dnscapy_str = "dnscapy" ascii nocase
        $tuns_str = "TUNS" ascii
        $ozymandns = "OzymanDNS" ascii nocase
        $feederbot = "FeederBot" ascii nocase
    condition:
        1 of them
}

rule High_Entropy_DNS_Query {
    meta:
        description = "Detects unusually long/encoded DNS queries indicative of tunneling"
        author = "BlueSentinel v2.0"
        severity = "medium"
        mitre_technique = "T1071.004"
        tags = "dns_tunnel, medium"
    strings:
        $base32_sub = /[A-Z2-7]{40,}\.[a-z]{2,}/ ascii
        $base64_sub = /[a-zA-Z0-9+\/]{32,}={0,2}\.[a-z]{2,}/ ascii
        $hex_sub = /[a-f0-9]{40,}\.[a-z]{2,}/ ascii
        $long_sub = /[a-z0-9\-]{50,}\.[a-z]{2,6}$/ ascii
        $dns_hdr = { 00 00 01 00 00 01 00 00 00 00 00 00 }  // DNS query header
    condition:
        $dns_hdr and (
            $base32_sub or $base64_sub or $hex_sub or $long_sub
        )
}

rule DNS_Exfiltration_Pattern {
    meta:
        description = "Detects data exfiltration patterns over DNS"
        author = "BlueSentinel v2.0"
        severity = "high"
        mitre_technique = "T1048.003"
        tags = "exfiltration, dns, high"
    strings:
        $encoded_chunk1 = /[a-zA-Z0-9]{20,}\.[a-zA-Z0-9]{20,}\.[a-z]{2,6}/ ascii
        $encoded_chunk2 = /[a-f0-9]{16,}\.[a-f0-9]{16,}\.[a-z]{2,6}/ ascii
        $seq_marker = /\d{4,}\.[a-zA-Z0-9]+\./ ascii
    condition:
        1 of ($encoded_chunk*) or $seq_marker
}
