import "vt"

rule PowerShell_BitsTransfer_Execution {
  meta:
    name = "PowerShell_BitsTransfer_Execution"
    target_entity = "file"
    description = "Behavior identified by Kaspersky CTI Team in their - Modern Asian APT Groups report"
    reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2023/11/09055246/Modern-Asian-APT-groups-TTPs_report_eng.pdf"
    author = "Joseliyo Sanchez - @Joseliyo_Jstnk"
    sha256 = "464e1847b4fd20aa49a1928a25b64281a62de5e542a6610b75bb5f3835a3a451"
    //behavior_processes:"Start-BitsTransfer -Source" (behavior_processes:"[System.Convert]::FromBase64String" or behavior_processes:"[System.IO.File]::WriteAllBytes")

  condition:
  vt.metadata.new_file and
  (
    for any vt_behaviour_processes_created in vt.behaviour.processes_created: ( vt_behaviour_processes_created icontains "Start-BitsTransfer -Source" )
    or
    for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: ( vt_behaviour_processes_terminated icontains "Start-BitsTransfer -Source" )
    or
    for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "Start-BitsTransfer -Source" )
  )

  and

  (
    for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
      vt_behaviour_processes_created icontains "[System.Convert]::FromBase64String"
      or 
      vt_behaviour_processes_created icontains "[System.IO.File]"
    )

    or

    for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
        vt_behaviour_processes_terminated icontains "[System.Convert]::FromBase64String"
        or
        vt_behaviour_processes_terminated icontains "[System.IO.File]"
    )

    or

    for any vt_behaviour_command_executions in vt.behaviour.command_executions : (
        vt_behaviour_command_executions icontains "[System.Convert]::FromBase64String"
        or
        vt_behaviour_command_executions icontains "[System.IO.File]"
    )
  )
}