# DbgChildProcess - Debug Child Process Tool 

![[Images/DbgChildProcess.png]] DbgChildProcess by David Reguera Garcia - Dreg, is a plugin for the x86/x64 x64dbg debugger. DbgChildProcess allows you to debug child processes in another x64dbg instance.

# Features

* Hook process creation for x86 or x64 child processes
* Patching and unpatching of NTDLL process creation for x86 and x64 child processes
* Process watcher for auto launching of new x64dbg instance when child process detected
* Modify the suspend (pre) and resume (post) logic to adapt to your own requirements

# Content
The DbgChildProcess comprises a number of components to accomplish the task of launching a new x64dbg instance when a child process is hooked and detected. These components are:

* CreateProcessPatch.exe - Hook ZwCreateUserProcess (two separate exe files for x86 and x64) and loads DbgChildHookDLL.dll
* DbgChildHookDLL.dll - (two separate dll files for x86 and x64) - outputs process id's to CPIDS folder
* NTDLLEntryPatch.exe - Patches or unpatches LdrInitializeThunk (two separate exe files for x86 and x64)
* DbgChildProcess.dp32 - x64dbg plugin x86 
* DbgChildProcess.dp64 - x64dbg plugin x64
* NewProcessWatcher.exe - Watches for new child processes from the CPIDS folder
* x64_post.unicode.txt - Support file
* x64_pre.unicode.txt - Support file
* x86_post.unicode.txt - Support file
* x86_pre.unicode.txt - Support file

# Download
Download the latest release of DbgChildProcess [here](https://github.com/David-Reguera-Garcia-Dreg/DbgChild/releases)

# Installation

* Download the latest version of x64dbg [here](https://github.com/x64dbg/x64dbg/releases)
* Extract the contents of the latest release archive to your x64dbg folder

Once extracted the contents should look something like this:

```
\x64dbg\NewProcessWatcher.exe
\x64dbg\x64_post.unicode.txt
\x64dbg\x64_pre.unicode.txt
\x64dbg\x86_post.unicode.txt
\x64dbg\x86_pre.unicode.txt
\x64dbg\x32\CreateProcessPatch.exe
\x64dbg\x32\DbgChildHookDLL.dll
\x64dbg\x32\NTDLLEntryPatch.exe
\x64dbg\x32\plugins\DbgChildProcess.dp32
\x64dbg\x32\CPIDS\
\x64dbg\x64\CreateProcessPatch.exe
\x64dbg\x64\DbgChildHookDLL.dll
\x64dbg\x64\NTDLLEntryPatch.exe
\x64dbg\x64\plugins\DbgChildProcess.dp64
\x64dbg\x64\CPIDS\
```

* Menu options for the DbgChildProcess plugin is available under the "Plugins" menu in the main x64dbg window


# Plugin Menu Overview

[[Images/HookProcess.png]] Hook Process Creation - CreateProcessPatch.exe hooks ZwCreateUserProcess and loads DbgChildHookDLL.dll. There is a x86 version and x64 version of CreateProcessPatch.exe

[[Images/Checkmark.png]] Auto from x32dbg/x64dbg Hook Process Creation - Toggle option to switch on or off the automatic hooking of the process creation. If it is off, then user must manually select Hook Process Creation at some point before child processes are spawned.

[[Images/ClearCPIDS.png]] Clear x32|x64\CPIDS - Clear all process id file entries from the x32\CPIDS or x64\CPIDS folder

[[Images/BrowseCPIDS.png]] Open x32|x64\CPIDS - Opens in explorer the x32\CPIDS or x64\CPIDS folder 

[[Images/AddCPIDS.png]] Create New Entry x32|x64\CPIDS - Adds a new entry to the x32\CPIDS or x64\CPIDS folder 

[[Images/UnpatchNTDLL.png]] Unpatch NTDLL Entry - Patches the ntdll.dll LdrInitializeThunk function.

[[Images/PatchNTDLL.png]] Patch NTDLL Entry - Unpatches the ntdll.dll LdrInitializeThunk if it has previously been patched

[[Images/Checkmark.png]] Auto From x32dbg|x64dbg Unpatch NTDLL Entry - Toggle option to switch on or off the automatic unpatch of the NTDLL entry when 2nd x64dbg instance is launched for child process. If it is off, then user must manually select Unpatch NTDLL Entry in the 2nd x64dbg instance after it has launched

[[Images/NewProcessWatcher.png]] Launch NewProcessWatcher - Starts NewProcessWatcher.exe which monitors the x32\CPIDS or x64\CPIDS folder for new process id files that are created by DbgChildHookDLL.dll when a child process is detected and is about to be spawned

[[Images/NewProcessWatcher.png]] Launch NewProcessWatcher With Old Processes - 

[[Images/Checkmark.png]] Launch from x32dbg|x64dbg NewProcessWatcher Without Ask - Toggle option to switch on or off the automatic prompt to launch NewProcessWatcher. If on then when Hook Process Creation is selected, NewProcessWatcher will automatically launch. If off, then it will display a prompt asking user if they wish to launch NewProcessWatcher

[[Images/GotoHook.png]] Go to Hook Process Creation - Shows in the x32dbg|x64dbg cpu disassembly window the location of the hook code

[[Images/GotoNTDLL.png]] Go to NTDLL Patch - Shows in the x32dbg|x64dbg cpu disassembly window the location of the ntdll.dll patch

[[Images/EditSuspended.png]] Edit x32|x64 Suspended Command - Opens x86_pre.unicode.txt or x64_pre.unicode.txt in notepad for editing

[[Images/EditResumed.png]] Edit x32|x64 Resumed Command - Opens x86_post.unicode.txt or x64_post.unicode.txt in notepad for editing

[[Images/RemoteHookProcess.png]] Remote x32|x64 PID Hook Process Creation - Asks for a process id to remotely hook process creation for

[[Images/RemoteNTDLLPatch.png]] Remote x32|x64 PID Patch NTDLL Entry - Asks for a process id to remotely patch the ntdll.dll LdrInitializeThunk function for

[[Images/RemoteNTDLLUnpatch.png]] Remote x32|x64 PID Unpatch NTDLL Entry - Asks for a process id to remotely unpatch the ntdll.dll LdrInitializeThunk if it has previously been patched

[[Images/OpenLogs.png]] Open Logs - Open log files

[[Images/ClearLogs.png]] Clear Logs - Clear log files

[[Images/Checkmark.png]] Auto From x32|x64 Open Logs - Toggle option to switch on or off the automatic opening of the log file

[[Images/Help.png]] Help - Displays information on the usage of the plugin and its operations

[[Images/DbgChildProcess.png]] Plugin Info By Dreg - About dialog box showing information about this plugin






