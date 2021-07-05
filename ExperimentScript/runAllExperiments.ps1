#=====================================================================
#Vars for running
#=====================================================================
$AV = "your-prefix" #Prepended to output filenames

$SIdllShortName = "kernelbase" 
$SIdllLongName = "kernelbase.dll" 
$SIdllFunction = "CreateRemoteThreadEx" 

$SSdllShortName = "ntdll" 
$SSdllLongName = "ntdll.dll" 
$SSdllFunction = "NtMapViewOfSection" 

$CFdllShortName = "kernelbase" 
$CFdllLongName = "kernelbase.dll" 
$CFdllFunction = "CopyFileExW" 

#=====================================================================
#Filter declaration
#=====================================================================
filter timestamp {"$(Get-Date -Format HH:mm:ss.fff): $_"}


#=====================================================================
#Function declarations
#=====================================================================
function Success
{
	Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
	Write-Host "[SUCCESS] " -fore green -NoNewline 
}

function IntroApp 
{
    param( $name )
    if ($name -eq "SI")
    {
        $fullName = "Shellcode Injection, Basic (SI)"
    }
    else
    {
        if ($name -eq "SS")
        {
            $fullName = "Shellcode Injection, Section Mapping (SS)"
        }
        else
        {
            if ($name -eq "CF")
            {
                $fullName = "Copying Files (SF)"
            }
        }
    }

	Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
	Write-Host "===========================================================" -fore cyan 
	Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
	Write-Host "[$fullName]" -fore cyan 
}

function IntroTech
{
    param($name)
    Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
    Write-Host "***********************************************************" -fore blue  
    Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
    Write-Host ">>> Run tests for unhook technique $name on AV $AV     " -fore blue
    Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
    Write-Host "***********************************************************" -fore blue
}

function SkippedUnhooking
{
	Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
	Write-Host "[SKIPPED UNHOOKING]" -fore yellow
}

function Failure
{
	Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
	Write-Host "[FAILURE] " -fore red -NoNewline 
}

function WithUnhooking
{
    Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
    Write-Host "-----------------------------------------------------------" -fore white 
	Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
	Write-Host "[With Unhooking] " -fore white
}

function WithoutUnhooking
{
    Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
    Write-Host "-----------------------------------------------------------" -fore white 
	Write-Host "$(Get-Date -Format HH:mm:ss.fff): $_" -NoNewLine
	Write-Host "[Without Unhooking] " -fore white
}

function StoreHooks
{
    param( $procID, $textfile )

  echo "Storing hooks in hooks-$textfile.txt for $procID..." | timestamp 
  ./HooDet.exe $procID > hooks-$textfile.txt 
  echo "Done." | timestamp
  return;
}

Function RunTest
{
    param( $technique, $app, $AV, $doUnhook )

    #Run target of app that is hooked
    echo "Running target notepad application." | timestamp
    $notepadInfo = Start-Process notepad.exe  -passthru
    $notepad_pid = $notepadInfo.Id
    Start-Sleep -s 5 #Make sure it is up before working on it 

    #App name depends on technique since files can get quarantined.
    $appNameTemp = "$app"+"$technique"

    #For unhooking and non-unhooking tests, different exe's are used (because portentially quarantined)
    if ($doUnhook -eq "true")
    {
        $appName = $appNameTemp+"1.exe"
    }
    else
    {
        $appName = $appNameTemp+"2.exe"
    }
    
    echo "Running target application '$appName'." | timestamp
    $appInfo = Start-Process $appName $notepad_pid -passthru
    $app_pid = $appInfo.Id
    #Make sure it is up before working on it
    Start-Sleep -s 10 #Make sure it is up before working on it 
    
    #Store before hooks on app
    StoreHooks -procID $app_pid -textfile $AV-$technique-$app-before-$doUnhook 
    Start-Sleep -s 10 #Make sure it is down before continuing 

    if ($doUnhook -eq "true")
    {
        #Use unhooking technique
        $techExe = "UH$technique.exe"
        echo "Unhooking $appName." | timestamp
        $techInfo = ""
        if ($technique -eq "IF")
        {
	        echo "Running $techExe $notepad_pid $app_pid $dllLongName $dllFunction..." | timestamp 	
            $arguments = "$notepad_pid $app_pid $dllLongName $dllFunction"
            $techInfo = Start-Process $techExe $arguments -passthru
        }
        else
        {
            if ($technique -eq "SR")
            {
                echo "Running $techExe $app_pid $dllShortName ..." | timestamp
                $arguments = "$app_pid $dllShortName"
                $techInfo = Start-Process $techExe $arguments  -passthru
            }
            else
            {
                if ($technique -eq "PR")
                {
                    echo "Running $techExe $app_pid $dllLongName $dllFunction..." | timestamp
                    $arguments = "$app_pid $dllLongName $dllFunction"
                    $techInfo = Start-Process $techExe $arguments  -passthru 
                }
                else
                {
                    if ($technique -eq "PF")
                    {
                        echo "Running $techExe $app_pid ..." | timestamp
                        $arguments = "$app_pid"
                        $techInfo = Start-Process $techExe $arguments  -passthru 
                    }
                    else
                    {
                        if ($technique -eq "IS")
                        {
                            echo "Running $techExe $notepad_pid $app_pid $dllLongName..." | timestamp
                            $arguments = "$notepad_pid $app_pid $dllLongName"
                            $techInfo = Start-Process $techExe $arguments  -passthru 
                        }                        
                    }
                }
            }
        }

        #Make sure it is down before continuing
        $techInfo.WaitForExit()

        if ($techInfo.ExitCode -eq 0) {
            Success
            echo "Technique $technique successfully executed on $appName."
        }
        else
        {
            $exCode = $techInfo.ExitCode
            Failure
            echo "Technique $technique failed: $exCode "
        }    
    }
    else
    {
        SkippedUnhooking
    }

    #Store after hooks on app (one second and 60 seconds after unhooking)
    Start-Sleep -s 1
    StoreHooks -procID $app_pid -textfile $AV-$technique-$app-after1-$doUnhook
    echo "Waiting for a minute..." | timestamp
    Start-Sleep -s 60
    StoreHooks -procID $app_pid -textfile $AV-$technique-$app-after60-$doUnhook

    echo "Waiting for app to exit..." | timestamp
    $appInfo.WaitForExit()
    if ($appInfo.ExitCode -eq 0) {
        Success
        echo "App $app successfully executed."
    }
    else
    {
        $exCode = $appInfo.ExitCode
        Failure
        echo "App $app failed: $exCode "
    }    

    #Killing app
    #echo "Killing $app application." | timestamp
    #Stop-Process -ID $app_pid -Force
    echo "Killing notepad.exe application." | timestamp
    Stop-Process -ID $notepad_pid -Force
}

#=====================================================================
#Script start
#=====================================================================

$un = [Environment]::UserName
echo "User '$un' is running the script."

echo "Starting tests for $AV." | timestamp

foreach ($technique in "PF","IS","IF", "SR", "PR","NO")
{
    IntroTech -name $technique

    foreach ($app in "CF", "SS", "SI")
    {
        IntroApp -name $app
		$dllShortName = ""
		$dllLongName = ""
		$dllFunction = ""

		if ($app -eq "SI")
        {
			$dllShortName = $SIdllShortName
			$dllLongName = $SIdllLongName
			$dllFunction = $SIdllFunction
        }
        else
        {
            if ($app -eq "SS")
            {
				$dllShortName = $SSdllShortName
				$dllLongName = $SSdllLongName
				$dllFunction = $SSdllFunction
            }
            else
            {
                if ($app -eq "CF")
                {
					$dllShortName = $CFdllShortName
					$dllLongName = $CFdllLongName
					$dllFunction = $CFdllFunction
                }
            }
        }

        #Makes no sense to test without unhooking more than once
        if ($technique -eq "NO")
        {
            WithoutUnhooking
            RunTest -technique $technique -app $app -AV $AV -doUnhook false
        }
        else
        {
            WithUnhooking
            RunTest -technique $technique -app $app -AV $AV -doUnhook true
        }

    }
}

echo "All tests finished!" | timestamp
exit
