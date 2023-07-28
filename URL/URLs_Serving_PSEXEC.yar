import "vt"

rule URLs_Serving_PSEXEC {
  meta:
    name = "URLs Serving Publicly Available PSEXEC Hash"
    description = "Will be slightly noisy due to public distribution URLs (github, etc) but will identify attacker open directories and other staging infrastructure where the attackers have legit tools like PSExec stored along side malware/etc"
    target_entity = "url"
  condition:
    vt.net.url.downloaded_file.sha256 == "3337e3875b05e0bfba69ab926532e3f179e8cfbf162ebb60ce58a0281437a7ef"
}
