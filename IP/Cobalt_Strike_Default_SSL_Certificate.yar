import "vt"

rule Cobalt_Strike_Default_SSL_Certificate
{
  meta:
    name = "Default CobaltStrike self-signed SSL Certificate"
    description = "Find IP addresses serving the default SSL certificate used out of the box by Cobalt Strike for C2 comms"
    reference = "https://www.mandiant.com/resources/blog/defining-cobalt-strike-components"
  condition:
    vt.net.ip.https_certificate.thumbprint == "6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
}
