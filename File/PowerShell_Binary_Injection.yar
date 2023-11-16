import "vt"

rule PowerShell_Binary_Injection {
  meta:
    name = "PowerShell_Binary_Injection"
    target_entity = "file"
    description = "Behavior identified by Kaspersky CTI Team in their - Modern Asian APT Groups report"
    reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2023/11/09055246/Modern-Asian-APT-groups-TTPs_report_eng.pdf"
    author = "Joseliyo Sanchez - @Joseliyo_Jstnk"
    sha256 = "676e2d67ab2de186b1e5375d30530e4c45006e793fb229ad906d6c820b9ab575"
    //behavior_processes:"{$b='PowerShell.exe'}" behavior_processes:"-nop -w hidden -noni -c" behavior_processes:"{$b=$env:windir+"

  condition:
  vt.metadata.new_file and
  (
    for any vt_behaviour_processes_created in vt.behaviour.processes_created: ( vt_behaviour_processes_created icontains "-nop -w hidden -noni -c" )
    or
    for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "-nop -w hidden -noni -c" )
    or
    for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: ( vt_behaviour_processes_terminated icontains "-nop -w hidden -noni -c" )
    or
    for any vt_behaviour_sigma_analysis_results in vt.behaviour.sigma_analysis_results: (
      for any vt_behaviour_sigma_analysis_results_match_context in vt_behaviour_sigma_analysis_results.match_context: (
        vt_behaviour_sigma_analysis_results_match_context.values["CommandLine"] icontains "-nop -w hidden -noni -c"
      )
    )
  )
  
  and

  (
    
      for any vt_behaviour_processes_created in vt.behaviour.processes_created: ( vt_behaviour_processes_created icontains "{$b=$env:windir+" )
      or
      for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "{$b=$env:windir+" )
      or
      for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: ( vt_behaviour_processes_terminated icontains "{$b=$env:windir+" )
      or
      for any vt_behaviour_sigma_analysis_results in vt.behaviour.sigma_analysis_results: (
        for any vt_behaviour_sigma_analysis_results_match_context in vt_behaviour_sigma_analysis_results.match_context: (
          vt_behaviour_sigma_analysis_results_match_context.values["CommandLine"] icontains "{$b=$env:windir+"
        )
      )
  )

  and

  (
      for any vt_behaviour_processes_created in vt.behaviour.processes_created: ( vt_behaviour_processes_created icontains "{$b='PowerShell.exe'}" )
      or
      for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "{$b='PowerShell.exe'}" )
      or
      for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: ( vt_behaviour_processes_terminated icontains "{$b='PowerShell.exe'}" )
      or
      for any vt_behaviour_sigma_analysis_results in vt.behaviour.sigma_analysis_results: (
        for any vt_behaviour_sigma_analysis_results_match_context in vt_behaviour_sigma_analysis_results.match_context: (
          vt_behaviour_sigma_analysis_results_match_context.values["CommandLine"] icontains "{$b='PowerShell.exe'}"
        )
      )
  )
}