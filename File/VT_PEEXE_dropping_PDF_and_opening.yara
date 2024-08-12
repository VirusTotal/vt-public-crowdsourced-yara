import "vt"

rule VT_PEEXE_dropping_executing_PDF {
  meta:
    target_entity = "file"
    disclaimer = "Please note that this YARA was created from a presentation and study done in a presentation. Before using it, make sure it meets your detection needs."
    purpose = "hunting"
    description = "This YARA rule detects PEEXE that are dropping and executing decoy PDF files. Most of the files detected are fake docs trojanized."
    author = "@Joseliyo_Jstnk - VirusTotal"
    hash = "6d48c8b9caa754587fdd1412139fba9820dbf02fe30e70156b0a597f8b7a4665"
    // entity:file (behavior_files:"\\Users\\Public\\" and behavior_files:"*.pdf") fs:2024-01-01+ p:5+ (behavior_processes:"C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe" and behavior_processes:"*.pdf") and not tag:pdf
  condition:
  vt.metadata.new_file and vt.metadata.analysis_stats.malicious >= 5 and
  (
    for any vt_behaviour_files_opened in vt.behaviour.files_opened: (
      (vt_behaviour_files_opened icontains "C:\\Users\\Public\\" or vt_behaviour_files_opened icontains "\\AppData\\Local\\Temp\\" or vt_behaviour_files_opened icontains "\\Downloads\\" or vt_behaviour_files_opened icontains "\\Desktop\\") and vt_behaviour_files_opened endswith ".pdf"
    ) or
    for any vt_behaviour_files_written in vt.behaviour.files_written: (
      (vt_behaviour_files_written icontains "C:\\Users\\Public\\" or vt_behaviour_files_written icontains "\\AppData\\Local\\Temp\\" or vt_behaviour_files_written icontains "\\Downloads\\" or vt_behaviour_files_written icontains "\\Desktop\\") and vt_behaviour_files_written endswith ".pdf"
    ) or
    for any vt_behaviour_files_dropped in vt.behaviour.files_dropped: (
      (vt_behaviour_files_dropped.path icontains "C:\\Users\\Public\\" or vt_behaviour_files_dropped.path icontains "\\AppData\\Local\\Temp\\" or vt_behaviour_files_dropped.path icontains "\\Downloads\\" or vt_behaviour_files_dropped.path icontains "\\Desktop\\") and vt_behaviour_files_dropped.path endswith ".pdf"
    )
  ) and
  (
    for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
      vt_behaviour_processes_created icontains "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe" and vt_behaviour_processes_created endswith ".pdf"
    ) or
    for any vt_behaviour_command_executions in vt.behaviour.command_executions: (
      vt_behaviour_command_executions icontains "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe" and vt_behaviour_command_executions endswith ".pdf"
    ) or
    for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
      vt_behaviour_processes_terminated icontains "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe" and vt_behaviour_processes_terminated endswith ".pdf"
    )
  ) and not for any vt_metadata_tags in vt.metadata.tags: (vt_metadata_tags == "pdf")
}

