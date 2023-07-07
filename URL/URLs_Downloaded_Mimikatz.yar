import "vt"

rule URLs_Downloaded_Mimikatz {
  meta:
    name = "URLs Serving Files Detected as Mimikatz"
    description = "Using engine names/labels, identify new URLs that serve files detected as Mimikatz. This could include Mimikatz itself, or files that contain Mimi (or it's capabilities) embedded within"
  condition:
    for any engine, signature in vt.net.url.downloaded_file.signatures: (
      signature icontains "mimikatz"
    )
}
