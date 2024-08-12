import "vt"

rule VT_LNK_HTTP_MSHTA {
  meta:
    target_entity = "file"
    disclaimer = "Please note that this YARA was created from a presentation and study done in a presentation. Before using it, make sure it meets your detection needs."
    purpose = "hunting"
    description = "This YARA rule detects LNK files that are hidding HTTP communications and mshta executions during the sandbox detonation"
    author = "@Joseliyo_Jstnk - VirusTotal"
    hash = "0cee6c7fbe37cb12a8c4416bc916aed3644ad5c09f02641477522a940bfb8d9e"
    //metadata:"'??ht??t?p?://" or metadata:"\\W*\\S*2\\m*h?a."
  condition:
     vt.metadata.new_file and
     (vt.metadata.exiftool["CommandLineArguments"] icontains "??ht??t?p?://" or vt.metadata.exiftool["CommandLineArguments"] icontains "\\W*\\S*2\\m*h?a.")
     // you can add more ways observed to encode http and mshta calls.
}
