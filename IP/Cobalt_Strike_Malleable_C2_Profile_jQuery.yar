import "vt"

rule Cobalt_Strike_Malleable_C2_Profile_jQuery
{
  meta:
    name = "Cobalt Strike Malleable C2 Profile - jQuery (Masquerade)"
    description = "Identifies IP addresses serving a self-signed SSL certificate consistent with a Cobalt Strike Beacon Malleable C2 profile masquerading as the legitiamte jQuery"
    reference = "https://github.com/threatexpress/malleable-c2/blob/master/jquery-c2.4.0.profile"
  condition:
    vt.net.ip.https_certificate.subject.common_name == "jquery.com" and
    (
      vt.net.ip.https_certificate.subject.organizational_unit == "Certificate Authority" or
      vt.net.ip.https_certificate.subject.organizational_unit == "DigiCertSSL"
    ) and
    vt.net.ip.https_certificate.subject.organization == "jQuery" and
    (
      vt.net.ip.https_certificate.subject.country == "US" or
      vt.net.ip.https_certificate.subject.country == "CN" or
      vt.net.ip.https_certificate.subject.country == "en"
    ) and      
    for any tag in vt.net.ip.tags: 
    (tag == "self-signed")
}
