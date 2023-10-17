import "vt"

rule RomCom_MustangPanda_Similar_Behaviors
{
    meta:
        name = "RomCom_MustangPanda_Similar_Behaviors"
        description = "Rule to detect samples related to RomCom RAT and also Mustang Panda, since both are sharing common behaviors"  
        author = "Joseliyo Sanchez - @Joseliyo_Jstnk"
        target_entity  = "file"
        sha256 = "6d3ab9e729bb03ae8ae3fcd824474c5052a165de6cb4c27334969a542c7b261d"
        // vt_intelligence_query1 = ((behavior_processes:".dll,fwdTst") OR (behavior_processes:"dll\",#1" behavior_processes:"\\Public\\Libraries\\") OR (behavior_processes:*.dll0* behavior_processes:"\\Public\\Libraries\\")) AND ((behaviour_files:*\\Public\\Libraries\\*) AND (behavior:*rundll32.exe*))
        // vt_intelligence_query2 = ((behavior_processes:".dll,fwdTst") OR (behavior_processes:"dll\",#1" behavior_processes:"\\Public\\Libraries\\") OR (behavior_processes:*.dll0* behavior_processes:"\\Public\\Libraries\\") OR (behavior_processes:*.dll,main* behavior_processes:"\\Public\\Libraries\\")) AND ((behaviour_files:*\\Public\\Libraries\\*) AND (behavior:*rundll32.exe*))

    condition:
    
        (
            vt.metadata.file_type == vt.FileType.PE_DLL or 
            vt.metadata.file_type == vt.FileType.PE_EXE or 
            vt.metadata.file_type == vt.FileType.MSI
        )

        and not
        
        (
            vt.metadata.analysis_stats.malicious <= 1
        )

        and

        (
            for any files_writt in vt.behaviour.files_written : (
                files_writt icontains "\\Public\\Libraries"
            )
        )

        and

        (
            for any proc in vt.behaviour.processes_created : (
                proc icontains "rundll32"
            )
            or
            for any cmd in vt.behaviour.command_executions : (
                cmd icontains "rundll32"
            )
            or
            for any term in vt.behaviour.processes_terminated: (
                term icontains "rundll32"
            )
        )

        and

        (
            
            for any cmdexec in vt.behaviour.command_executions : (
                (cmdexec contains ",#1" or cmdexec icontains ",fwdTst" or cmdexec icontains ",main") and
                cmdexec contains ".dll"
            )
            or
            for any proc in vt.behaviour.processes_created : (
                (proc contains ",#1" or proc icontains ",fwdTst" or proc icontains ",main") and
                proc contains ".dll"
            )
            or
            for any terminated in vt.behaviour.processes_terminated : (
                (terminated contains ",#1" or terminated icontains ",fwdTst" or terminated icontains ",main") and
                terminated contains ".dll"
            )

        )

    and vt.metadata.new_file
}