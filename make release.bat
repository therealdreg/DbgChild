SET vcvarsall="C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86

cd %~dp0

rmdir /S /Q DbgChild_Release
rmdir /S /Q NewProcessWatcher\Release
rmdir /S /Q NewProcessWatcher\x64
rmdir /S /Q NTDLLEntryPatch\Release
rmdir /S /Q NTDLLEntryPatch\x64
rmdir /S /Q CreateProcessPatch\Release
rmdir /S /Q CreateProcessPatch\x64
rmdir /S /Q DbgChildHookDLL\Release
rmdir /S /Q DbgChildHookDLL\x64
rmdir /S /Q x64dbgplugin\bin

call %vcvarsall%
devenv "NewProcessWatcher\NewProcessWatcher.sln" /rebuild "Release|x86"
devenv "x64dbgplugin\dbgchild.sln" /rebuild "Release|Win32" 
devenv "x64dbgplugin\dbgchild.sln" /rebuild "Release|x64" 
devenv "NTDLLEntryPatch\NTDLLEntryPatch.sln" /rebuild "Release|x86" 
devenv "NTDLLEntryPatch\NTDLLEntryPatch.sln" /rebuild "Release|x64"
devenv "CreateProcessPatch\CreateProcessPatch.sln" /rebuild "Release|x86"
devenv "CreateProcessPatch\CreateProcessPatch.sln" /rebuild "Release|x64"
devenv "DbgChildHookDLL\DbgChildHookDLL.sln" /rebuild "Release|x86" 
devenv "DbgChildHookDLL\DbgChildHookDLL.sln" /rebuild "Release|x64" 

mkdir DbgChild_Release
mkdir DbgChild_Release\release
mkdir DbgChild_Release\release\dbgchildlogs
mkdir DbgChild_Release\release\x32
mkdir DbgChild_Release\release\x32\plugins
mkdir DbgChild_Release\release\x32\CPIDS
mkdir DbgChild_Release\release\x64
mkdir DbgChild_Release\release\x64\plugins
mkdir DbgChild_Release\release\x64\CPIDS

copy readme_dbgchild.txt DbgChild_Release\release\readme_dbgchild.txt

copy NewProcessWatcher\Release\NewProcessWatcher.exe DbgChild_Release\release\
copy NewProcessWatcher\*.txt DbgChild_Release\release\

copy NTDLLEntryPatch\Release\NTDLLEntryPatch.exe DbgChild_Release\release\x32
copy CreateProcessPatch\Release\CreateProcessPatch.exe DbgChild_Release\release\x32
copy DbgChildHookDLL\Release\DbgChildHookDLL.dll DbgChild_Release\release\x32
copy x64dbgplugin\bin\x32\dbgchild.dp32 DbgChild_Release\release\x32\plugins

copy NTDLLEntryPatch\x64\Release\NTDLLEntryPatch.exe DbgChild_Release\release\x64
copy CreateProcessPatch\x64\Release\CreateProcessPatch.exe DbgChild_Release\release\x64
copy DbgChildHookDLL\x64\Release\DbgChildHookDLL.dll DbgChild_Release\release\x64
copy x64dbgplugin\bin\x64\dbgchild.dp64 DbgChild_Release\release\x64\plugins

pause