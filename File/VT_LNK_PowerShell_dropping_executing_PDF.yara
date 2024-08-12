import "vt"

rule VT_LNK_PowerShell_dropping_executing_PDF {
  meta:
    target_entity = "file"
    disclaimer = "Please note that this YARA was created from a presentation and study done in a presentation. Before using it, make sure it meets your detection needs."
    purpose = "hunting"
    description = "This YARA rule detects LNK files that are executing PowerShell in order to drop and load a decoy PDF file. This technique is commonly used by some APT groups and cybercriminals."
    author = "@Joseliyo_Jstnk - VirusTotal"
    hash = "c6398b5ca98e0da75c7d1ec937507640037ce3f3c66e074c50a680395ecf5eae"
  condition:
  vt.metadata.new_file and
  for any vt_metadata_tags in vt.metadata.tags: ( vt_metadata_tags == "lnk") and
    (
        for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
            vt_behaviour_processes_created icontains "powershell"
        ) or
        for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
            vt_behaviour_processes_terminated icontains "powershell"
        ) or
        for any vt_behaviour_command_executions in vt.behaviour.command_executions: (
            vt_behaviour_command_executions icontains "powershell"
        )
    )
    and
    (
        for any vt_behaviour_files_written in vt.behaviour.files_written: (
            vt_behaviour_files_written endswith ".pdf"
        ) or
        for any vt_behaviour_files_dropped in vt.behaviour.files_dropped: (
            vt_behaviour_files_dropped.path endswith ".pdf" and vt_behaviour_files_dropped.process_name icontains "powershell"
        )
    )
    and
    (
        for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
            vt_behaviour_processes_created icontains "AcroRd32.exe" and vt_behaviour_processes_created icontains ".pdf"
        ) or
        for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
            vt_behaviour_processes_terminated icontains "AcroRd32.exe" and vt_behaviour_processes_terminated icontains ".pdf"
        ) or
        for any vt_behaviour_command_executions in vt.behaviour.command_executions: (
            vt_behaviour_command_executions icontains "AcroRd32.exe" and vt_behaviour_command_executions icontains ".pdf"
        ) or
        for any vt_behaviour_files_opened in vt.behaviour.files_opened: (
            vt_behaviour_files_opened icontains "AcroRd32.dll"
        )
    )
}

