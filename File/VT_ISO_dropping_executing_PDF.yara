import "vt"

rule VT_ISO_dropping_executing_PDF {
  meta:
    target_entity = "file"
    disclaimer = "Please note that this YARA was created from a presentation and study done in a presentation. Before using it, make sure it meets your detection needs."
    purpose = "hunting"
    description = "This YARA rule detects mounted ISO Images and DMG files, that are also executing a decoy PDF file during the sandbox detonation."
    author = "@Joseliyo_Jstnk - VirusTotal"
    hash = "f9f2ff85bb4523a5ebd6e3e66f2d768596d0b52f5e03db62af70b7136c0f9d81"
  condition:
    vt.metadata.new_file and
    (
        for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
         vt_behaviour_processes_created icontains "cmd.exe /c powershell.exe -ex bypass -command Mount-DiskImage -ImagePath (gc C:\\Windows\\path.txt) > tmp.log 2>&1"
        ) or
        for any vt_behaviour_command_executions in vt.behaviour.command_executions: (
            vt_behaviour_command_executions icontains "cmd.exe /c powershell.exe -ex bypass -command Mount-DiskImage -ImagePath (gc C:\\Windows\\path.txt) > tmp.log 2>&1"
        ) or
        for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
            vt_behaviour_processes_terminated icontains "cmd.exe /c powershell.exe -ex bypass -command Mount-DiskImage -ImagePath (gc C:\\Windows\\path.txt) > tmp.log 2>&1"
        )
    ) and
    (
        for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
            vt_behaviour_processes_created icontains "AcroRd32.exe" and vt_behaviour_processes_created icontains ".pdf"
        ) or
        for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
            vt_behaviour_processes_terminated icontains "AcroRd32.exe" and vt_behaviour_processes_terminated icontains ".pdf"
        ) or
        for any vt_behaviour_command_executions in vt.behaviour.command_executions: (
            vt_behaviour_command_executions icontains "AcroRd32.exe" and vt_behaviour_command_executions icontains ".pdf"
        )
    ) and
    vt.metadata.analysis_stats.malicious >= 3

    // Other ideas to add in your livehunt
    
    //for any vt_behaviour_files_dropped in vt.behaviour.files_dropped: (
    //    vt_behaviour_files_dropped.path icontains "\\Device\\" and vt_behaviour_files_dropped.path iendswith ".dll"
    //)

    //for any vt_behaviour_files_dropped in vt.behaviour.files_dropped: (
    //  vt_behaviour_files_dropped.path icontains "\\Device\\" and vt_behaviour_files_dropped.type == vt.FileType.PDF
    //)

}

