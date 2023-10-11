import "vt"

rule Gamaredon_Documents_DavSetCookie_RU {
  meta:
    name = "Gamaredon_Documents_DavSetCookie_RU"
    author = "Joseliyo Sanchez - @Joseliyo_Jstnk"
    description = "Documents related to Gamaredon threat actor abusing of DavSetCookie to load remote templates"
    target_entity = "file"
    // vt_intelligence_query = (behavior_processes:*.ru* and behavior_processes:*DavSetCookie* and behavior_processes:*http*) and (behavior_network:*.ru* or embedded_domain:*.ru* or embedded_url:*.ru*) and not (type:document)

  condition:

    (
        for any vt_behaviour_processes_terminated in vt.behaviour.processes_terminated: (
            vt_behaviour_processes_terminated icontains ",DavSetCookie" and
            vt_behaviour_processes_terminated contains "http" and
            vt_behaviour_processes_terminated contains ".ru"
        ) 
        
        or

        for any vt_behaviour_command_executions in vt.behaviour.command_executions : (
            vt_behaviour_command_executions icontains ",DavSetCookie" and
            vt_behaviour_command_executions contains "http" and
            vt_behaviour_command_executions contains ".ru"
        )

        or

        for any vt_behaviour_processes_created in vt.behaviour.processes_created : (
            vt_behaviour_processes_created icontains ",DavSetCookie" and
            vt_behaviour_processes_created contains "http" and
            vt_behaviour_processes_created contains ".ru"
           
        )
    ) 
    
    and

    (
        for any vt_behaviour_http_conversations in vt.behaviour.http_conversations: (
        vt_behaviour_http_conversations.url contains ".ru"
        ) or 
        for any vt_behaviour_dns_lookups in vt.behaviour.dns_lookups: (
            vt_behaviour_dns_lookups.hostname contains ".ru"
        )
    )

    and 

    for any vt_metadata_file_type_tags in vt.metadata.file_type_tags: (
      vt_metadata_file_type_tags == "document"
    )
}


