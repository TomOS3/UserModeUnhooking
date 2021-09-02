# User Mode Unhooking test script
This project is created for research into antivirus evasion by unhooking. The paper containing additional information and references can be found here: https://rp.os3.nl/2020-2021/p68/report.pdf. The repo contains scripts and source code for running unhooking techniques on different payloads to test the resilience of an antivirus product to such unhooking techniques. 

Two of the five implemented techniques are novell techniques that can be used if an antivirus product hooks different functions on different processes of the same user:
- Interprocess Function Copying
- Interprocess Section Copying

## Usage

### Preparation
- The output filename at the top of the RunAllExperiments.ps1 PowerShell script can be adjusted to specify the right output filename.
- Make sure the Visual Studio projects for unhooking techniques are compiled.
- Compile different payloads for every experiment and collect the files needed for the experiments by running exportFiles.bat.
- Create a baseline file containing unhooked .dll info by running "HookFinder -1" on a system without antivirus.
- Copy the files to the target machine.

### Running The Experiments
- Make sure you are logged in with user permissions (or use "runas /trustlevel:0x20000").
- Run powershell ./RunAllExperiments.ps1
- The hooks in memory will be written to txt files and the status of return codes of payloads and unhooking applications will be displayed in the output of the script.
- Because every antivirus product is different, a manual check is required to see which antivirus alerts are generated.

### Troubleshooting
- The payloads created trigger specific functions. If other functions are hooked, you have to manually adjust Prologue Restoring.
- Required hardcoded bytes of Prologue Restoring depend on the targeted Windows version.
- Perun's Fart is limited to unhooking ntdll.dll.

## Directory Content
- "CustomCode" contains code for payloads and unhooking techniques that were created for this research.
- "DumpertResearch" and "ShellycoatResearch" contain adjusted versions of Dumpert and ShellyCoat respectively. Both unhooking techniques target an other process.
- "ExperimentScript" contains the PowerShell script that runs different techniques on different payloads.
- "ApplicationsToCheckForHooks" contain Visual Studio boilerplate code for applications that can be run on antivirus software to see if these are getting hooked.
- "HookCorruptor" contains code, based on Dumpert, for checking if hooks are triggered (see Troubleshooting that we mentioned earlier).

## Acknowledgements
This research is based on some of the valuable tools, blogs and proof-of-concepts on unhooking that are published by members of the security community.
The implemented unhooking techniques, e.g., were, where possible, created by using and adjusting parts of existing code from projects like Shellycoat and Dumpert. References to these projects can be found in the paper that we mentioned above

