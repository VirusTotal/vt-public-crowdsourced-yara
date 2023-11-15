import "vt"

rule WMI_Event_Subscription_Behaviors {
  meta:
    name = "WMI_Event_Subscription_Behaviors"
    target_entity = "file"
    description = "Behavior identified by Kaspersky CTI Team in their - Modern Asian APT Groups report"
    reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2023/11/09055246/Modern-Asian-APT-groups-TTPs_report_eng.pdf"
    author = "Joseliyo Sanchez - @Joseliyo_Jstnk"
    sha256 = "8b7b38ec56a9dc0b73e3078ea22070dfe32c99ec836182393b8dbe62ca8f2018"
    //(behavior:"EventNamespace =") (behavior:"Name =") behavior:"QueryLanguage = \"WQL\"" (behavior:"__EventFilter" behavior:"CommandLineEventConsumer") behavior:"ExecutablePath ="

  condition:
  vt.metadata.new_file and
  (
    (
      for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: ( vt_behaviour_processes_terminated icontains "QueryLanguage=WQL" or vt_behaviour_processes_terminated icontains "QueryLanguage=\"WQL\"" )
      or
      for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "QueryLanguage=WQL" or vt_behaviour_command_executions icontains "QueryLanguage=\"WQL\"" )
      or
      for any vt_behaviour_processes_created in vt.behaviour.processes_created : ( vt_behaviour_processes_created icontains "QueryLanguage=WQL" or vt_behaviour_processes_created icontains "QueryLanguage=\"WQL\"" )
    )
    or
    (
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "QueryLanguage=WQL" or vt_behaviour_system_property_lookups icontains "QueryLanguage=\"WQL\"" )
      or
      for any vt_behaviour_text_highlighted in vt.behaviour.text_highlighted: ( vt_behaviour_text_highlighted icontains "QueryLanguage=WQL" or vt_behaviour_text_highlighted icontains "QueryLanguage=\"WQL\"" )
      or
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "__EventFilter" or vt_behaviour_system_property_lookups icontains "QueryLanguage=\"WQL\"" )
    )
  )

  and

  (
    (
      for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: ( vt_behaviour_processes_terminated icontains "EventNameSpace=" )
      or
      for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "EventNameSpace=" )
      or
      for any vt_behaviour_processes_created in vt.behaviour.processes_created : ( vt_behaviour_processes_created icontains "EventNameSpace=" )
    )
    or
    (
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "EventNameSpace="  )
      or
      for any vt_behaviour_text_highlighted in vt.behaviour.text_highlighted: ( vt_behaviour_text_highlighted icontains "EventNameSpace=" )
      or
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "EventNameSpace=" )
    )
  )

  and

  (
    (
      for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (vt_behaviour_processes_terminated icontains "ExecutablePath=" or vt_behaviour_processes_terminated icontains "ExecutablePath<>")
      or
      for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "ExecutablePath=" or vt_behaviour_command_executions icontains "ExecutablePath<>" )
      or
      for any vt_behaviour_processes_created in vt.behaviour.processes_created : ( vt_behaviour_processes_created icontains "ExecutablePath=" or vt_behaviour_processes_created icontains "ExecutablePath<>" )
    )
    or
    (
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "ExecutablePath="  )
      or
      for any vt_behaviour_text_highlighted in vt.behaviour.text_highlighted: ( vt_behaviour_text_highlighted icontains "ExecutablePath=" )
      or
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "ExecutablePath=" )
    )
  )

  and

  (
    (
      for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (vt_behaviour_processes_terminated icontains "CommandLineEventConsumer" )
      or
      for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "CommandLineEventConsumer" )
      or
      for any vt_behaviour_processes_created in vt.behaviour.processes_created : ( vt_behaviour_processes_created icontains "CommandLineEventConsumer" )
    )
    or
    (
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "CommandLineEventConsumer"  )
      or
      for any vt_behaviour_text_highlighted in vt.behaviour.text_highlighted: ( vt_behaviour_text_highlighted icontains "CommandLineEventConsumer" )
      or
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "CommandLineEventConsumer" )
    )
  )

  and

  (
    (
      for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (vt_behaviour_processes_terminated icontains "Name=" )
      or
      for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "Name=" )
      or
      for any vt_behaviour_processes_created in vt.behaviour.processes_created : ( vt_behaviour_processes_created icontains "Name=" )
    )
    or
    (
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "Name="  )
      or
      for any vt_behaviour_text_highlighted in vt.behaviour.text_highlighted: ( vt_behaviour_text_highlighted icontains "Name=" )
      or
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "Name=" )
    )
  )

  and

  (
    (
      for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (vt_behaviour_processes_terminated icontains "__EventFilter" )
      or
      for any vt_behaviour_command_executions in vt.behaviour.command_executions : ( vt_behaviour_command_executions icontains "__EventFilter" )
      or
      for any vt_behaviour_processes_created in vt.behaviour.processes_created : ( vt_behaviour_processes_created icontains "__EventFilter" )
    )
    or
    (
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "__EventFilter"  )
      or
      for any vt_behaviour_text_highlighted in vt.behaviour.text_highlighted: ( vt_behaviour_text_highlighted icontains "__EventFilter" )
      or
      for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: ( vt_behaviour_system_property_lookups icontains "__EventFilter" )
    )
  )
}