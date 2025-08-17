rule RulesA
{
    strings:
        $a = "GetCurrentProcessId" wide ascii
        $b = "GetModuleFileNameW" wide ascii
        $c = "CreateProcessA" wide ascii
        $d = "GetExitCodeProcess" wide ascii
        $e = "The debugger was detected" wide ascii
        $f = "[FATAL ERROR]" wide ascii
    
    condition:
        all of them
}

// Useless but why not
rule RulesB
{
    strings:
        $a = "OpenProcessToken" wide ascii
        $b = "LookupPrivilegeValueW" wide ascii
        $c = "AdjustTokenPrivileges" wide ascii
        $d = "Please run" wide ascii
        $e = "this program" wide ascii
        $f = "as an Admin" wide ascii
    
    condition:
        all of them
}

// Detect ExitProcess, GetProcAddress, LoadLibraryA, VirtualProtect, and CommandLineToArgvW from packed file (idk why works LOL)
rule RulesC
{
    strings:
        $a = { 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 43 6F 6D 6D 61 6E 64 4C 69 6E 65 54 6F 41 72 67 76 57 }
    
    condition:
        all of them
}
