import "vt"

rule APT32_SOUNDBITE_FQDN_Pattern
{
 meta:
   name = "APT32 SOUNDBITE FQDN pattern"
   reference = "https://www.mandiant.com/resources/blog/cyber-espionage-apt32"
   description = "Matches on the naming scheme used for C2 servers for APT32's SOUNDBITE malware that performs C2 via DNS lookups."
   target_entity = "domain"
 condition:
    vt.net.domain.new_domain and 
    (vt.net.domain.raw matches /^z\.[^.]{4,}\.[^.]+/)
    and for any record in vt.net.domain.dns_records:
    (record.type == "A" and record.value == "127.0.0.1") 
}
