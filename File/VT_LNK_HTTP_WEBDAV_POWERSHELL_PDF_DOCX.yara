import "vt"

rule VT_LNK_HTTP_WEBDAV_POWERSHELL_PDF_DOCX {
  meta:
    target_entity = "file"
    disclaimer = "Please note that this YARA was created from a presentation and study done in a presentation. Before using it, make sure it meets your detection needs."
    purpose = "hunting"
    description = "This YARA rule use LNK metadata to detect HTTP and WebDAV connections made by LNK files. PowerShell is executed and finally a decoy .docx or .pdf file is also used during the intrusion"
    author = "@Joseliyo_Jstnk - VirusTotal"
    hash = "19d0c55ac466e4188c4370e204808ca0bc02bba480ec641da8190cb8aee92bdc"
    // 9724cecaa8ca38041ee9f2a42cc5a297 5f126b2279648d849e622e4be910b96c 47f4b4d8f95a7e842691120c66309d5b 8d1b91e8fb68e227f1933cfab99218a4 6fdd416a768d04a1af1f28ecaa29191b 5db75e816b4cef5cc457f0c9e3fc4100 6128d9bf34978d2dc7c0a2d463d1bcdd 825a12e2377dd694bbb667f862d60c43 acd9fc44001da67f1a3592850ec09cb7
  condition:
     vt.metadata.new_file and
    (
        vt.metadata.exiftool["CommandLineArguments"] icontains "http" or 
        vt.metadata.exiftool["CommandLineArguments"] icontains "file://"
    ) and 
    (
        vt.metadata.exiftool["CommandLineArguments"] icontains "powershell" or  
        vt.metadata.exiftool["RelativePath"] icontains "powershell"
    ) and
    (
        vt.metadata.exiftool["CommandLineArguments"] icontains ".pdf" or  //this can be removed
        vt.metadata.exiftool["CommandLineArguments"] icontains ".docx"  //this can be removed
    )
}