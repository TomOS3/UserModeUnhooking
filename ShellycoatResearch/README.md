# Shellycoat
[![](https://img.shields.io/badge/Category-Defense%20Evasion-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-C%20%2f%20C++%20%2f%20Python3-E5A505?style=flat-square)]()

## Introduction
`Shellycoat` is a utility designed to aid in **bypassing User-Mode hooks** utilised by **AV/NGAV/EDR/Sandboxes/DLP** etc. to gain visibility into potentially suspicious actions since **SSDT hooking** was made obsolete with the advent of `Kernel Patch Protection(KPP)/Patch Guard` in **x64** systems.

## How To Use `Shellycoat`
### Using the pre-built binary
Grab the latest version from [here](https://github.com/slaeryan/AQUARMOURY/releases).
### Compiling yourself
Make sure you have a working VC++ 2019 dev environment set up beforehand and `Git` installed. Execute the following from an x64 Developer Command Prompt.
```
1. git clone https://github.com/slaeryan/AQUARMOURY
2. cd AQUARMOURY/Shellycoat
3. compile64.bat
```

`shellycoat_x64.dll` is the name of the module and it is quite small(about `7 kB` in size). It is compiled to a DLL and converted to a PIC blob(shellcode) with the help of [sRDI](https://github.com/monoxgas/sRDI) courtesy of [@monoxgas](https://twitter.com/monoxgas?lang=en) which can then be executed in-memory via your favourite loader.

This is how it looks internally in-action:

![Shellycoat Internal](https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/Screenshots/shellycoat-internal.gif "Shellycoat Internal")

The way I intend it to be used is for it to be injected into the sacrificial process spawned by the loader to "cleanse" the loaded DLL before the C2 payload is executed but it can be used to protect any sacrificial process by undoing PSP hooks.

When executed, **it creates a section out of a fresh/untainted copy of the hooked DLL from disk and maps a view of the section containing the image in the local process to overwrite the hooked `.text` section of the loaded DLL with the `.text` section of the fresh copy before unmapping the secondary DLL again. This way we can ensure all PSP hooks are removed from our hooked DLL and we can freely perform our implant(ish) activities now without any fear of getting caught!**

It will be integrated with the `Wraith` loader sometime in the near future.

Read below to know more about the tool, its motivation, design choices etc.

## OPSEC Concerns when our threat model includes PSPs that do UM hooking(which is most of them!)
Before I begin my rant, If you need a refresher about how or why PSPs perform hooking, these two articles should suffice:
1) [https://breakdev.org/defeating-antivirus-real-time-protection-from-the-inside/](https://breakdev.org/defeating-antivirus-real-time-protection-from-the-inside/) by [Kuba Gretzky](https://twitter.com/mrgretzky?)
2) [https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6) by [Hoang Bui](https://twitter.com/specialhoang?lang=en)

Now that is out of the way, let's talk about what we as wannabe attackers can do to protect our tooling against this problem and the assumption here being that we have our custom loader but the C2 agent is proprietary and the source unavailable for modification such as [Cobalt Strike's C2 payload - Beacon](https://www.cobaltstrike.com/help-beacon).

Our first contender in the list is the MS mitigation policy known as `CIG/Code Integrity Guard` or more famously known as `blockdlls` thanks to `Cobalt Strike`. But how does this help us?

**`CIG` prevents any non-MS signed third-party DLL(Ex: EDR Hooking DLL) from being loaded into our spawned sacrificial "trusted" process which now contains the C2 payload**.

But many EDRs(ex: `CrowdStrike Falcon`) were rather quick to get their _evil_ DLL signed by MS which renders this technique useless. Bummer :(

**Implant - 0 | EDR - 1**

Our second contender is the possibly lesser-known(or abused) MS mitigation policy known as `ACG/Arbitrary Code Guard` that **prevents dynamic code from being executed by taking away a process's ability to allocate new executable pages and/or change existing executable page protections which is required for EDR trampolines to work**. This means that EDR _evil_ DLL hooking would fail even if it were signed ;)

But wait that sounds too good to be true, what's the big catch?

I'm glad you asked cause here it goes:

As [@_xpn_](https://twitter.com/_xpn_) writes in his [blog](https://blog.xpnsec.com/protecting-your-malware/)
```
It should be noted that injecting something like Cobalt Strike beacon will not currently work with this method due to the reliance on allocating and modifying pages of memory to RWX.
```

But let's say for argument's sake that we are using a custom in-house developed Implant framework for our engagement which is compatible with `ACG`.

Problem solved eh? Not quite.

One of the most crucial aspects of maintaining OPSEC is **possessing the ability to `inline-execute` or locally execute code in the main implant process without spawning and/or injecting to remote processes which is severely hindered by `ACG`**.

So you see it is too effective to the point that it even takes away our ability to execute modules/plug-ins on-the-fly without some hacks.

**Implant - 1 | EDR - 2**

Enter our third contender in the list - `Section Remapping`!

![Bypass Techniques](https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/Screenshots/bypass-techniques.png "Bypass Techniques")

The flow of the technique is as follows:
1) [NtCreateFile()](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) - To get a handle to the clean and unhooked DLL on disk
2) [NtCreateSection(..., SEC_IMAGE, ...)](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection) - To create a section object out of this image
3) [NtMapViewOfSection()](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection) - To map this section containing the unhooked image into the local process

Essentially, what we are doing here is mapping a fresh copy of `Ntdll.dll` from disk into the local process that is guaranteed to be unhooked.

But what do we do now that we have a pristine copy of `Ntdll.dll` loaded in memory?

We can directly parse the freshly loaded `Ntdll`'s `EAT/Export Address Table` and use it to call the functions however we cannot do that here since we want to protect the payload whose source we do not control.

The second option is to attempt to "cleanse" the already loaded `Ntdll` by **overwriting the `.text` section of hooked `Ntdll.dll` with the `.text` section of the fresh copy of `Ntdll.dll`**. This way we can undo the PSP hooks and protect our process.

Here is a diagram that was shamelessly stolen from [ired.team](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++) that should make this clear:

![Section Remapping](https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/Screenshots/section-remapping.png "Section Remapping")

This mapping can also be done using **memory-mapped files** using [CreateFileMappingA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga) and [MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile) as shown in various PoCs by [@spotheplanet](https://twitter.com/spotheplanet), [@dtm](https://twitter.com/0x00dtm), [Solomon Sklash](https://github.com/SolomonSklash) etc. I have decided to implement it using their lower-level cousins and **section objects**.

The reason being:

![Why Syscalls](https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/Screenshots/why-syscall.png "Why Syscalls")

As shown in the above screenshot from a [blog post](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/) by [CyberBit](https://www.cyberbit.com/), this technique itself can be potentially detected using hooks(although unlikely!)

Fret not because [Direct Hard-Coded Syscalls/BYOI](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) to the rescue!

What we are doing here essentially is **using direct syscalls to invoke the functions related to the process of unhooking itself as opposed to using the loaded and hooked `Ntdll` to perform `Section Remapping`**.

The pros of this method as compared to `Lagos Island method`/using NtReadFile and manually mapping a fresh copy of `ntdll.dll` from the disk is that the **secondary DLL will be mapped as an image and it will appear loaded in a typical fashion by the PE loader**.

The following snippet of a table from [CyberBit's blog post]() might make it clearer:

![Reading Ntdll](https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/Screenshots/reading-ntdll.png "Reading Ntdll")

Furthermore, in the unlikely event that **Blue Teams decide to monitor for open handles to `Ntdll.dll` on disk**, **it is quite short-lived and we unmap the section view and close the handles as soon as we finish undoing the hooks**.

Some of the important things I want to point out here are:
1) **It only "unhooks" `Ntdll.dll` functions that are hooked by security products. This is intentionally by-design as those functions are most commonly hooked by PSPs. However, the source can be modified to clean hooks from any loaded DLL Ex: `Kernel32.dll`**
2) **All the threads need to be suspended while this process is underway due to the race condition which I presume shouldn't be too much of a problem since it is designed to be used by an implant loader**
3) **It does not handle relocations which could result in loss of bytes and hence cause problems when calling certain APIs**
4) **The secondary DLL won't have `PEB` entry for loaded module list**

While this is not a new or novel technique having been (ab)used in the past by commodity malware such as `Osiris`, our technique is slightly different in the sense that it doesn't call functions from the secondary mapped DLL directly but rather uses it to get rid of hooks from the loaded DLL.

**Implant - 2 | EDR - 2** :)

## Screenshots
Because screenshots or it didn't happen ;)

The GIF below shows inline hooking `NtCreateFile` with [Detours](https://github.com/microsoft/Detours) to pop a MessageBox every time the user tries to save a file by injecting the hooking DLL(`edr.dll`) into `notepad.exe`.

![Hooking](https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/Screenshots/hooking.gif "Hooking")

And this demonstrates how we undo the hooks by injecting `shellycoat_x64.dll` to map a clean copy of `Ntdll` from disk and overwrite the hooked `.text` section of loaded `Ntdll` thereby regaining the ability to save files again.

![Unhooking](https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/Screenshots/unhooking.gif "Unhooking")

And lastly, here is a mandatory [CAPA](https://github.com/fireeye/capa) scan result of `shellycoat` DLL:

![CAPA](https://github.com/slaeryan/AQUARMOURY/blob/master/Shellycoat/Screenshots/capa.PNG "CAPA")

## Credits
1. [@dtm](https://twitter.com/0x00dtm) for [https://0x00sec.org/t/defeating-userland-hooks-ft-bitdefender/12496](https://0x00sec.org/t/defeating-userland-hooks-ft-bitdefender/12496)
2. [@spotheplanet](https://twitter.com/spotheplanet) for [https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)
3. [Solomon Sklash](https://github.com/SolomonSklash) for [https://www.solomonsklash.io/pe-parsing-defeating-hooking.html](https://www.solomonsklash.io/pe-parsing-defeating-hooking.html)
4. [@OutflankNL](https://twitter.com/outflanknl?lang=en) for [https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
5. [CyberBit](https://www.cyberbit.com/) for [https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/](https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/)
6. [enSilo](https://www.fortinet.com/products/fortinet-acquires-ensilo) for [https://www.first.org/resources/papers/telaviv2019/Ensilo-Omri-Misgav-Udi-Yavo-Analyzing-Malware-Evasion-Trend-Bypassing-User-Mode-Hooks.pdf](https://www.first.org/resources/papers/telaviv2019/Ensilo-Omri-Misgav-Udi-Yavo-Analyzing-Malware-Evasion-Trend-Bypassing-User-Mode-Hooks.pdf) & [https://www.youtube.com/watch?v=4r5I6kaDAIw](https://www.youtube.com/watch?v=4r5I6kaDAIw)
7. [@hasherezade](https://twitter.com/hasherezade) for [https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/](https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/)
8. [@monoxgas](https://twitter.com/monoxgas?lang=en) for [sRDI](https://github.com/monoxgas/sRDI)
9. As usual, [@reenz0h](https://twitter.com/Sektor7Net) and [RTO: MalDev course](https://institute.sektor7.net/red-team-operator-malware-development-essentials) for the templates that I keep using to this date

## Author
Upayan ([@slaeryan](https://twitter.com/slaeryan)) [[slaeryan.github.io](https://slaeryan.github.io)]

## License
All the code included in this project is licensed under the terms of the GNU GPLv2 license.

#

[![](https://img.shields.io/badge/slaeryan.github.io-E5A505?style=flat-square)](https://slaeryan.github.io) [![](https://img.shields.io/badge/twitter-@slaeryan-00aced?style=flat-square&logo=twitter&logoColor=white)](https://twitter.com/slaeryan) [![](https://img.shields.io/badge/linkedin-@UpayanSaha-0084b4?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/upayan-saha-404881192/)
