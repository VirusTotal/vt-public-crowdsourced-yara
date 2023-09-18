import "vt"

rule APT_Bitter_chm_files {
  meta:
    name = "APT_Bitter_chm_files"
    author = "Joseliyo Sanchez - VirusTotal"
    description = "Find chm files related to APT Bitter used during their operations"
    target_entity = "file"
    //vt_intelligence_query = behavior_processes:"%Comspec%" behavior_processes:"schtasks.exe" tag:chm
    
  condition:
    (
        for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
            vt_behaviour_processes_created contains "schtasks"
        )

        or

        for any vt_behaviour_command_executions in vt.behaviour.command_executions: (
            vt_behaviour_command_executions contains "schtasks"
        )
    )
    
    and

    (
        for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
            vt_behaviour_processes_created contains "coMSPec" or vt_behaviour_processes_created contains "comspec"
        )

        or

        for any vt_behaviour_command_executions in vt.behaviour.command_executions: (
            vt_behaviour_command_executions contains "coMSPec" or vt_behaviour_command_executions contains "comspec"
        )
    )

    and

    for any vt_metadata_tags in vt.metadata.tags: (
      vt_metadata_tags == "chm"
    )

    and

    vt.metadata.new_file
}