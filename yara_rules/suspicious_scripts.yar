rule Suspicious_PowerShell_Execution
{
    meta:
        description = "Detects multiple indicators associated with PowerShell execution"
        severity = "medium"

    strings:
        $powershell = "powershell" ascii nocase
        $encoded = "-enc" ascii nocase
        $download = "downloadstring" ascii nocase
        $iex = "iex" ascii nocase
        $invoke = "invoke-expression" ascii nocase

    condition:
        $powershell and 1 of ($encoded, $download, $iex, $invoke)
}

rule Suspicious_Script_Host_Execution
{
    meta:
        description = "Detects Windows Script Host combined with script execution indicators"
        severity = "medium"

    strings:
        $wscript = "wscript.shell" ascii nocase
        $execute = "execute" ascii nocase
        $run = ".run" ascii nocase
        $powershell = "powershell" ascii nocase
        $cmd = "cmd.exe" ascii nocase

    condition:
        $wscript and 1 of ($execute, $run, $powershell, $cmd)
}
rule Suspicious_Memory_Injection
{
    meta:
        description = "Detects a combination of APIs commonly associated with process injection"
        severity = "high"

    strings:
        $virtualalloc = "VirtualAlloc" ascii nocase
        $remote_thread = "CreateRemoteThread" ascii nocase
        $write_memory = "WriteProcessMemory" ascii nocase

    condition:
        2 of them
}
rule Suspicious_Download_Execution
{
    meta:
        description = "Detects combinations associated with downloading and executing content"
        severity = "medium"

    strings:
        $download1 = "downloadstring" ascii nocase
        $download2 = "invoke-webrequest" ascii nocase
        $download3 = "curl " ascii nocase
        $download4 = "wget " ascii nocase

        $execute1 = "powershell" ascii nocase
        $execute2 = "cmd.exe" ascii nocase
        $execute3 = "iex" ascii nocase
        $execute4 = "execute" ascii nocase

    condition:
        1 of ($download*) and 1 of ($execute*)
}