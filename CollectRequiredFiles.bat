rem Run this script from a x64 Native Tools Command Prompt

copy DumpertResearch\x64\Release\Outflank-Dumpert.exe RequiredFiles\UHPR.exe
copy ShellycoatResearch\Bin\shellycoat_x64.exe RequiredFiles\UHSR.exe
copy HookDetectorTM\x64\Release\InterProcessFunctionCopying.exe RequiredFiles\UHIF.exe
copy HookDetectorTM\x64\Release\InterProcessSectionCopying.exe RequiredFiles\UHIS.exe
copy HookDetectorTM\x64\Release\HookDetector.exe RequiredFiles\HooDet.exe
copy HookDetectorTM\x64\Release\PerunsFart.exe RequiredFiles\UHPF.exe

call "HookDetectorTM\compile_slightly_different_payloads.bat"
copy HookDetectorTM\*.exe RequiredFiles

copy ExperimentScript\*.* RequiredFiles
 

