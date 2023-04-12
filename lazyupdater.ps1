Set-ExecutionPolicy Unrestricted
cls

# Script created by Louis Kraimer
# C | 2022-2023 - All Rights Reserved

$text = @"
 _____ _            _                       _   _           _       _            
|_   _| |          | |                     | | | |         | |     | |           
  | | | |__   ___  | |     __ _ _____   _  | | | |_ __   __| | __ _| |_ ___ _ __ 
  | | | '_ \ / _ \ | |    / _` |_  / | | | | | | | '_ \ / _` |/ _` | __/ _ \ '__|
  | | | | | |  __/ | |___| (_| |/ /| |_| | | |_| | |_) | (_| | (_| | ||  __/ |   
  \_/ |_| |_|\___| \_____/\__,_/___|\__, |  \___/| .__/ \__,_|\__,_|\__\___|_|   
                                     __/ |       | |                             
                                    |___/        |_|                             
"@
Write-Host $text
Write-Host Version 1.0.1
Write-Host Script Created by Louis Kraimer
Write-Host Make sure you run this script as an Administrator else it WILL NOT WORK!!!
Write-Host Its Recommended to Shutdown ALL Apps and its processes before running this script!!
Write-Host Make sure you are running this script in your Desktop Folder!
do {
Write-Host "`t1. '1' to Update your Computer with the latest Windows + App updates"
Write-Host "`t2. '2' to Tune-Up Your System"
Write-Host "`t3. '3' to Secure your system from Viruses, PUPs, etc."
Write-Host "`t4. '4' to Run Hardware Diagnostics"
Write-Host "`tQ. 'Q to Quit'"
$choice = Read-Host "Select one of The Options above..."
} until (
($choice -eq '1') -or 
($choice -eq '2') -or 
($choice -eq '3') -or
($choice -eq '4') -or 
($choice -eq 'Q') 
)
switch ($choice) {
   '1'{
cls
Write-Host "Starting..."
# Creating a Log File
Write-Host Creating a Log File
$logfilepath="lazyupdaterupdate.log"
Start-Transcript -Path $logfilepath
Write-Host Log File Created
Write-Host Log file is located where the powershell script is stored...
# Updates/Upgrades
Write-Host Downloading Prerequisites/Modules
Install-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue
Install-Module -Name PSWindowsUpdate -Force -ErrorAction SilentlyContinue
Import-Module -Name PSWindowsUpdate -Force -ErrorAction SilentlyContinue
Install-Module -Name WingetTools -Force -ErrorAction SilentlyContinue
Install-WinGet -ErrorAction SilentlyContinue
winget source update
if (Test-Path 'C:\ProgramData\chocolatey\bin\chocolatey.exe') {
    Write-Host "Chocolatey is installed. Updating Chocolatey..."
} else {
    Write-Host "Chocolatey is not installed. Installing..."
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
    choco install --ignore-dependencies --yes "chocolatey-core.extension" "chocolatey-fastanswers.extension" "dependency-windows10"
}
choco upgrade chocolatey "chocolatey-core.extension" "chocolatey-fastanswers.extension" "dependency-windows10"
Write-Host Done!
Write-Host Downloading/Installing Windows Updates...
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll 
Get-WuInstall -AcceptAll -IgnoreReboot 
Get-WuInstall -AcceptAll -Install -IgnoreReboot
Write-Host Successfully Updated Computer with the latest Windows Updates!
Write-Host Forcing Group Policy Updates...
gpupdate /force
Write-Host Updating Drivers...
choco install sdio --force -y
choco upgrade sdio --force -y
xcopy C:\ProgramData\chocolatey\lib\sdio\tools\SDIO_1.12.10.750\ .\SDIO_1.12.10.750 /c /h /e /s
New-Item .\SDIO_1.12.10.750\scripts\update-install.txt -Force
Set-Content .\SDIO_1.12.10.750\scripts\update-install.txt "verbose 384 `nenableinstall on `nkeeptempfiles off `ninit `n`ncheckupdates `nonerror goto :end `nget indexes `nselect missing newer better `ninstall `nonerror goto :end `n:end `nend"
New-NetFirewallRule -DisplayName "SDIO-Drivers" -Enabled True -Direction Outbound -Profile Any -Action Allow -Program ".\SDIO_1.12.9.750\SDIO_x64_R750.exe" | Out-Null
cd .\SDIO_1.12.10.750
.\SDIO_x64_R750.exe /script:.\scripts\update-install.txt
Start-Sleep -Seconds 10
.\SDIO_x64_R750.exe /script:.\scripts\update-install.txt
Get-NetFirewallRule -DisplayName "SDIO-Drivers" | Remove-NetFirewallRule
cd ..
choco uninstall sdio -y
Remove-Item .\SDIO_1.12.10.750 -Recurse -Force
Write-Host Downloading Microsoft Store/App Updates...
winget upgrade --all --silent
choco upgrade all --ignore-dependencies --yes
Write-Host Enabiling automatic Windows Store Updates...
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
    }
If ((Get-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore").GetValueNames() -like "AutoDownload") {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload"
    }
Write-Host Done!
Write-Host Successfully Updated your Computer! -BackgroundColor Green
Stop-Transcript
Write-Host To Run another Option, Rerun the script...
   }
   '2'{
cls
Write-Host "Starting..."
# Creating a Log File
Write-Host Creating a Log File
$logfilepath="lazyupdatertuneup.log"
Start-Transcript -Path $logfilepath
Write-Host Log File Created
Write-Host Log file is located where the powershell script is stored...
# Performance Optimization
Write-Host Optimizing Performance...
Write-Host This will optimize multiple aspects of your system...
$PathToLMPoliciesPsched = "HKLM:\SOFTWARE\Policies\Microsoft\Psched"
$PathToLMPoliciesWindowsStore = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$PathToCUGameBar = "HKCU:\SOFTWARE\Microsoft\GameBar"
Set-ItemProperty -Path "$PathToCUGameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
Set-ItemProperty -Path "$PathToCUGameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type DWord -Value 4
$RamInKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $RamInKB
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched" -Force | Out-Null
    }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff
powercfg -DuplicateScheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -Hibernate off
$Key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
$Data = (Get-ItemProperty -Path $Key -Name DefaultConnectionSettings).DefaultConnectionSettings
$Data[8] = 3
Set-ItemProperty -Path $Key -Name DefaultConnectionSettings -Value $Data
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type DWord -Value 100
Write-Host Done!
# Windows Fixes
Write-Host Applying Windows Fixes...
Write-Host Fixing Network Sharing...
$registryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$key = "restrictanonymous"
$value = 0
Set-ItemProperty -Path $registryPath -Name $key -Value $value -Type DWORD
$registryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$key = "everyoneincludesanonymous"
$value = 1
Set-ItemProperty -Path $registryPath -Name $key -Value $value -Type DWORD
Write-Host Resetting WinSock Catalog...
$adapters = Get-NetAdapter
foreach ($adapter in $adapters) {
  Disable-NetAdapter -Name $adapter.Name -Confirm:$false
  Enable-NetAdapter -Name $adapter.Name -Confirm:$false
}
netsh winsock reset catalog
Write-Host Resetting the TCP/IP Stack...
netsh int ip reset
Write-Host Resetting WinHTTP Proxy...
netsh winhttp reset proxy
Write-Host Resetting Hosts File...
$hostsFile = "$env:windir\System32\drivers\etc\hosts"
Set-Content -Path $hostsFile -Value "127.0.0.1 localhost"
$lmhostsFile = "$env:windir\System32\drivers\etc\lmhosts"
Set-Content -Path $lmhostsFile -Value ""
Write-Host Fixing Windows Installer Files...
Stop-Service msiserver
Start-Process -FilePath msiexec -ArgumentList '/unregister' -Wait
Start-Process -FilePath msiexec -ArgumentList '/regserver' -Wait
Start-Service msiserver
Write-Host Cleaning Print Spooler Folder...
Stop-Service spooler
$folder = "C:\Windows\System32\spool\printers"
Remove-Item -Recurse -Force $folder -Verbose
Start-Service spooler
Write-Host Resetting Guest Account Network Privileges...
$guestAccountName = "Guest"
$guestSID = $null

try {
    $guestSID = Get-WmiObject -Class Win32_UserAccount -Filter "Name='$guestAccountName'" | Select-Object -ExpandProperty SID
}
catch {
    Write-Host "An error occurred while getting the guest account SID: $_" -ForegroundColor Red
}

if (!$guestSID) {
    Write-Host "The guest account SID could not be retrieved." -ForegroundColor Red
    Exit
}

try {
    if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff") {
        $guestAcl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"
        $guestAccessRule = New-Object System.Security.AccessControl.RegistryAccessRule($guestSID, "ReadAndExecute", "Deny")
        $guestAcl.SetAccessRule($guestAccessRule)
        Set-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" $guestAcl

        Write-Host "Guest account network privileges have been reset." -ForegroundColor Green
    }
    else {
        Write-Host "The registry key for network access does not exist. Skipping..." -ForegroundColor Red
    }
}
catch {
    Write-Host "An error occurred while resetting the guest account network privileges: $_ Skipping..." -ForegroundColor Red
}
Write-Host Resetting DMA/PIO Mode on ATA Devices...
$ataDevices = Get-WmiObject -Class Win32_DiskDrive | Where-Object { $_.InterfaceType -eq "ATA" }
foreach ($device in $ataDevices) {
    $deviceId = $device.DeviceID
    $result = Invoke-WmiMethod -Class Win32_IDEControllerDevice -Name ConfigureDMA -ArgumentList $deviceId
    if ($result.ReturnValue -eq 0) {
        Write-Host "DMA/PIO mode reset for device '$deviceId' successful"
    } else {
        Write-Error "Error resetting DMA/PIO mode for device '$deviceId': $($result.ReturnValue)"
    }
}
Write-Host Done!
# Drive Optimization/Cleanup
Write-Host Removing Bloatware...
Function RemoveBloat {

    $Bloatware = @(

        "Microsoft.3DBuilder"                    # 3D Builder
        "Microsoft.Microsoft3DViewer"
        "Microsoft.549981C3F5F10"                # Cortana
        "Microsoft.Appconnector"
        "Microsoft.BingFinance"                  # Finance
        "Microsoft.BingFoodAndDrink"             # Food And Drink
        "Microsoft.BingHealthAndFitness"         # Health And Fitness
        "Microsoft.BingNews"                     # News
        "Microsoft.BingSports"                   # Sports
        "Microsoft.BingTranslator"               # Translator
        "Microsoft.BingTravel"                   # Travel
        "Microsoft.BingWeather"                  # Weather
        "Microsoft.CommsPhone"
        "Microsoft.ConnectivityStore"
        "Microsoft.GamingServices"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftPowerBIForWindows"
        "Microsoft.MicrosoftSolitaireCollection" # MS Solitaire
        "Microsoft.MinecraftUWP"
        "Microsoft.MixedReality.Portal"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.Office.OneNote"               # MS Office One Note
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"                       # People
        "Microsoft.MSPaint"                      # Paint 3D
        "Microsoft.Print3D"                      # Print 3D
        "Microsoft.SkypeApp"                     # Skype (Who still uses Skype? Use Discord)
        "Microsoft.Todos"                        # Microsoft To Do
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"                   # Microsoft Whiteboard
        "Microsoft.WindowsAlarms"                # Alarms
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsMaps"                  # Maps
        "Microsoft.WindowsPhone"
        "Microsoft.WindowsReadingList"
        "Microsoft.WindowsSoundRecorder"         # Windows Sound Recorder
        "Microsoft.XboxApp"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxSpeechToTextOverlay"                   
        "Microsoft.YourPhone"                    # Your Phone
        "Microsoft.ZuneMusic"                    # Groove Music / (New) Windows Media Player
        "Microsoft.ZuneVideo"                    # Movies & TV
        "2FE3CB00.PicsArt-PhotoStudio"
        "46928bounde.EclipseManager"
        "4DF9E0F8.Netflix"
        "613EBCEA.PolarrPhotoEditorAcademicEdition"
        "6Wunderkinder.Wunderlist"
        "7EE7776C.LinkedInforWindows"
        "89006A2E.AutodeskSketchBook"
        "9E2F88E3.Twitter"
        "A278AB0D.DisneyMagicKingdoms"
        "A278AB0D.MarchofEmpires"
        "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
        "CAF9E577.Plex"  
        "ClearChannelRadioDigital.iHeartRadio"
        "D52A8D61.FarmVille2CountryEscape"
        "D5EA27B7.Duolingo-LearnLanguagesforFree"
        "DB6EA5DB.CyberLinkMediaSuiteEssentials"
        "DolbyLaboratories.DolbyAccess"
        "DolbyLaboratories.DolbyAccess"
        "Drawboard.DrawboardPDF"
        "Facebook.Facebook"
        "Fitbit.FitbitCoach"
        "Flipboard.Flipboard"
        "GAMELOFTSA.Asphalt8Airborne"
        "KeeperSecurityInc.Keeper"
        "NORDCURRENT.COOKINGFEVER"
        "Playtika.CaesarsSlotsFreeCasino"
        "ShazamEntertainmentLtd.Shazam"
        "SlingTVLLC.SlingTV"
        "SpotifyAB.SpotifyMusic"
        "ThumbmunkeysLtd.PhototasticCollage"
        "TuneIn.TuneInRadio"
        "WinZipComputing.WinZipUniversal"
        "XINGAG.XING"
        "flaregamesGmbH.RoyalRevolt2"
        "king.com.*"
        "king.com.BubbleWitch3Saga"
        "king.com.CandyCrushSaga"
        "king.com.CandyCrushSodaSaga"

    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Output "Trying to remove $Bloat."
    }
}

RemoveBloat
Write-Host Done!
Write-Host Checking Disk for any errors...
$Vols = Get-Volume
"There are $($Vols.Count) volumes. Starting CHKDSK...."
For ($Cntr = 0 ; $Cntr -lt $Vols.Count; $Cntr++) { 
 Repair-Volume -ObjectId "$($Vols[$($Cntr)].ObjectId)" -Scan -Verbose
}
Write-Host Done!
Write-Host Optimizing Drive...
defrag /C /O
Write-Host Done!
Write-Host Deleting Temporary Files and Cleaning Up Drive...
Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue -Verbose
Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Verbose -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -ErrorAction SilentlyContinue -Verbose
Remove-Item -Path $env:windir\Temp\* -Recurse -Verbose -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue -Verbose
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue -Verbose
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue -Verbose
Remove-Item -Path $env:TEMP\* -Recurse -Verbose -Force -ErrorAction SilentlyContinue
Clear-RecycleBin -Force -ErrorAction SilentlyContinue -Verbose
Clear-BCCache -Force -ErrorAction SilentlyContinue -Verbose
vssadmin delete shadows /all /quiet
cleanmgr /VERYLOWDISK /AUTOCLEAN
Write-Host Done!
Write-Host Cleaning Up Drive via DISM...
DISM.exe /Online /CleanUp-Image /StartComponentCleanup
DISM.exe /Online /CleanUp-Image /SPSuperSeded
Write-Host Running DISM/SFC Repairs...
DISM.exe /Online /CleanUp-Image /RestoreHealth
SFC.exe /ScanNow
Write-Host Running Again...
DISM.exe /Online /CleanUp-Image /RestoreHealth
SFC.exe /ScanNow
Write-Host Done!
Write-Host Successfully Tuned-Up your Computer! -BackgroundColor Green
Stop-Transcript
Write-Host To Run another Option, Rerun the script...
   }
   '3'{
cls
# Creating a Log File
Write-Host Creating a Log File
$logfilepath="lazyupdatermalwarescan.log"
Start-Transcript -Path $logfilepath
Write-Host Log File Created
Write-Host Log file is located where the powershell script is stored...
Write-Host "Starting..."
# Security Tweaks
Write-Host Running Microsoft Defender Virus Scans...
Write-Host WARNING!: This will take awhile!
Write-Host Updating Defender with the Latest Updates...
Update-MpSignature -Verbose
Write-Host Done!
Write-Host Disabling Certain Features to Avoid Vulnerable Attacks...
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Type "DWORD" -Value 72 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Type "DWORD" -Value 3 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" -Name MinVmVersionForCpuBasedMitigations -Type "String" -Value "1.0" -Force
New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -Force
Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force
netsh int tcp set global timestamps=disabled
BCDEDIT /set "{current}" nx OptOut
Set-Processmitigation -System -Enable DEP
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableHHDEP" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Type "DWORD" -Value 0 -Force
$key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $key | ForEach-Object { 
        Write-Host("Modify $key\$($_.pschildname)")
        $NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
        Write-Host("NetbiosOptions updated value is $NetbiosOptions_Value")
    }
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\" -Name "Wpad" -Force
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "Wpad" -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type "DWORD" -Value 1 -Force
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "LSASS.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Type "DWORD" -Value 8 -Force
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\" -Name "Settings" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Wdigest" -Name "UseLogonCredential" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" -Name "MitigationOptions" -Type "QWORD" -Value "1000000000000" -Force
$officeversions = '16.0', '15.0', '14.0', '12.0'
ForEach ($officeversion in $officeversions) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\" -Name "Security" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\$officeversion\Outlook\Security\" -Name "ShowOLEPackageObj" -Type "DWORD" -Value "0" -Force
    }
Write-Host Done!
Write-Host Configuring Windows Defender for Optimal Protection...
Write-Host Creating Config, and Temp Files...
New-Item -Path "C:\" -Name "Temp" -ItemType "directory" -Force | Out-Null
New-Item -Path "C:\Temp\" -Name "Windows Defender" -ItemType "directory" -Force | Out-Null
Copy-Item -Path .\Files\"Windows Defender Configuration Files"\* -Destination "C:\Temp\Windows Defender\" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Write-Host Configuring Windows Defender...
Set-MpPreference -DisableRealtimeMonitoring 0
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
Set-MpPreference -DisableBehaviorMonitoring 0
Set-MpPreference -DisableIOAVProtection 0
Set-MpPreference -DisableScriptScanning 0
Set-MpPreference -DisableRemovableDriveScanning 0
Set-MpPreference -DisableBlockAtFirstSeen 0
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -SignatureUpdateInterval 8
Set-MpPreference -DisableArchiveScanning 0
Set-MpPreference -DisableEmailScanning 0
Set-MpPreference -EnableFileHashComputation 1
Set-MpPreference -DisableIntrusionPreventionSystem $false
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudExtendedTimeout 50
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions AuditMode
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions AuditMode
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
Write-Host Done!
do {
Write-Host "`t1. 'Q' to Run a Quick Scan (Fast)"
Write-Host "`t2. 'F' to Run a Full Scan (Long)"
$wdchoice = Read-Host "Select one of The Options above..."
} until (
($wdchoice -eq 'Q') -or 
($wdchoice -eq 'F'))
switch ($wdchoice) {
'Q' {
Write-Host Running Quick Scan...
Start-MpScan -ScanType QuickScan -Verbose
Get-MpThreat
Remove-MpThreat
Write-Host Done!
}
'F' {
Write-Host Running Full Scan...
Start-MpScan -ScanType FullScan -Verbose
Get-MpThreat
Remove-MpThreat
Write-Host Done!
    }
}
Write-Host To Run a Full Offline Scan, Please Save your files before continuing...
do {
Write-Host "`t1. '1' to Run the Offline Scan"
Write-Host "`t2. '2' to Not Run the Offline Scan (NOT RECOMMENDED)"
$avchoice = Read-Host "Select one of The Options above..."
} until (
($avchoice -eq '1') -or 
($avchoice -eq '2'))
switch ($avchoice) {
'1' {
Write-Host Successfully Added More Protection to your Computer!
Write-Host WARNING: About to start Offline Scan, your system will shut down momentarily -BackgroundColor Yellow
Stop-Transcript
Write-Host Running Offline Scan...
Start-MpWDOScan
}
'2' {
Write-Host Cancelling Offline Scan...
Write-Host Done!
Write-Host Successfully Added More Protection to your Computer and Checked for Malware! -BackgroundColor Green
Stop-Transcript
Write-Host To Run another Option, Rerun the script...
    }
}
}
   '4'{
cls
# Creating a Log File
Write-Host Creating a Log File
$logfilepath="lazyupdaterdiags.log"
Start-Transcript -Path $logfilepath
Write-Host Log File Created
Write-Host Log file is located where the powershell script is stored...
Write-Host WARNING!: The diagnostics option is still a WORK IN PROGRESS! Not all features are currently complete as of this release! -BackgroundColor Yellow
Write-Host WARNING!: These hardware diagnostics are for INFORMATIONAL USE ONLY! This will only provide you with the necessary information and if the diagnostics here reports a failure, its recommended to use another tool to further diagnose that specific piece of hardware! -BackgroundColor Yellow
do {
    $inputKey = Read-Host "Press any key to continue the diagnostics or press 'Q' to quit"
    if ($inputKey -eq "Q" -or $inputKey -eq "q") {
        Write-Host "Cancelling Diagnostics..."
        break
    }
    Write-Host "Continuing with Diagnostics..."
} while ($true)
Write-Host Updating Powershell...
Install-Module -Name WingetTools -Force
Install-WinGet
winget source update
winget install --id Microsoft.Powershell --source winget
Write-Host Starting Hardware Diagnostics...
Write-Host This will take a LONG Time!
Write-Host Getting Battery Life...
$battery = Get-WmiObject -Class Win32_Battery
$charge = $battery.EstimatedChargeRemaining
$time = $battery.EstimatedRunTime
if ($charge -lt 50) {
  Write-Output "WARNING: Battery charge is low! ($charge%)"
} else {
  Write-Output "Battery charge remaining: $charge%"
  Write-Output "Battery time remaining: $time seconds"
}
Write-Host Done!
Write-Host Determining if Computer is Running via Battery or Not...
$batteryStatus = (Get-WmiObject -Class Win32_Battery).BatteryStatus
if($batteryStatus -eq 2) {
    Write-Host "Computer is running on battery power. Please connect to AC power to continue using the computer."
}
Write-Host Done!
Write-Host Determining if PCI Devices are Configured Correctly...
function Test-PCIConfiguration {
  $pciDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -match 'PCI' }
  foreach ($device in $pciDevices) {
    if ($device.Status -ne 'OK') {
      Write-Error "PCI device '$($device.Name)' is not properly configured!"
    } else {
    Write-Host "PCI device '$($device.Name)' is Configured Correctly!"
  }
}
}
Test-PCIConfiguration
Write-Host Done!
Write-Host Checking Status of PCI Express Devices...
if (!(Get-WmiObject -Class Win32_PnPEntity | Where-Object {$_.DeviceID -like "PCI\*"})) {
    Write-Error "This computer does not have any PCI Express devices."
    return
}
$pcieDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object {$_.DeviceID -like "PCI\*"}
foreach ($device in $pcieDevices) {
    Write-Host "Checking status of PCI Express device: $($device.Caption)"
    if ($device.Status -eq "OK") {
        Write-Host "Status: OK"
    } else {
        Write-Host "Status: NOT OK"
    }
}
Write-Host Done!
Write-Host Checking Status of any PCMCIA Bridge Devices Currently Connected...
$pcmciaBridge = Get-WmiObject -Class Win32_PCMCIAController
$status = $pcmciaBridge.Status
if (!$pcmciaBridge) {
Write-Host There is no PCMCIA Bridge Connected. Skipping...
} else {
Write-Output "The status of the $pcmciaBridge device is: $pcmciaBridgeStatus"
}
Write-Host Done!
Write-Host Checking Status of any CardBus Bridge Devices Currently Connected...
$cardbusBridge = Get-WmiObject -Class Win32_PCMCIAController
$status = $cardbusBridge.Status
if (!$cardbusBridge) {
    Write-Host There is no CardBus Bridge Connected. Skipping...
} else {
Write-Output "CardBus bridge status: $status"
}
Write-Host Done!
Write-Host Resetting Bus on IEEE1394PCI Device...
$ieee1394 = Get-PnpDevice | Where-Object {$_.DeviceId -match 'IEEE1394PCI'}
if ($ieee1394 -eq $null) {
    Write-Host There is no IEEE1394PCI Device Connected. Skipping...
} else {
$ieee1394 | Reset-PnpDevice
$ieee1394 | Get-PnpDeviceStatus
} 
Write-Host Done!
Write-Host Running Config ROM Test on IEE1394PCI Device...
$ieee1394 = Get-PnpDevice | Where-Object {$_.DeviceId -match 'IEEE1394PCI'}
if ($ieee1394pci) {
  $result = $ieee1394pci | Test-PnpDevice -ConfigROM
  if ($result.Pass) {
    Write-Host "The Config ROM Test passed."
  } else {
    Write-Host "The Config ROM Test failed."
  }
} else {
  Write-Host There is no IEEE1394PCI Device Connected. Skipping...
}
Write-Host Done!
Write-Host Getting Status of USB Devices...
$usbDevices = Get-WmiObject -Class Win32_USBHub
foreach ($device in $usbDevices)
{
    $name = $device.Name
    $status = $device.Status
    Write-Output "USB device name: $name"
    Write-Output "USB device status: $status"
}
Write-Host Done!
Write-Host Getting Connection Speed of USB Devices...
$usbDevices = Get-WmiObject -Class Win32_USBHub
foreach ($device in $usbDevices)
{
    $name = $device.Name
    $result = Test-NetConnection -ComputerName $name -InformationLevel Detailed
    $speed = $result.CurrentConnectionType.NetworkConnectionType
    Write-Output "USB device name: $name"
    Write-Output "USB device connection speed: $speed"
}
Write-Host Done!
Write-Host Getting Storage Performance of USB Devices...
function Get-USBDriveLetter {
  $usbDrives = Get-WmiObject Win32_DiskDrive |
               Where-Object {$_.InterfaceType -eq "USB"} |
               Select-Object DeviceID
  if ($usbDrives.Count -eq 0) {
    return ""
  } else {
    $usbDrive = Get-WmiObject Win32_LogicalDisk |
                Where-Object {$_.DeviceID -eq $usbDrives[0].DeviceID} |
                Select-Object DeviceID
    return $usbDrive.DeviceID
  }
}
$drive = Get-USBDriveLetter
if ($drive -eq "") {
  Write-Output "No USB drives found"
} else {
$iterations = 10
$blockSize = 1024
$testFileSize = 50
$totalElapsedTime = 0
$totalThroughput = 0
for ($i = 0; $i -lt $iterations; $i++) {
  $testFilePath = "$drive\test.dat"
  $testData = New-Object Byte[] $($testFileSize * 1MB)
  [System.IO.File]::WriteAllBytes($testFilePath, $testData)
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
  $readData = [System.IO.File]::ReadAllBytes($testFilePath)
  $elapsedTime = $stopwatch.Elapsed
  $totalElapsedTime += $elapsedTime.TotalSeconds
  $throughput = [math]::Round(($testFileSize / $elapsedTime.TotalSeconds) / 1MB, 2)
  $totalThroughput += $throughput
  Remove-Item $testFilePath -Force
}
$avgElapsedTime = [math]::Round($totalElapsedTime / $iterations, 2)
$avgThroughput = [math]::Round($totalThroughput / $iterations, 2)
Write-Output "Average elapsed time: $avgElapsedTime seconds"
Write-Output "Average throughput: $avgThroughput MB/s"
}
Write-Host Done!
Write-Host Checking Accuracy of RTC...
$startTime = Get-Date
Start-Sleep -Seconds 10
$endTime = Get-Date
$elapsedTime = $endTime - $startTime
Write-Output "Elapsed time: $elapsedTime"
Write-Host Done!
Write-Host Testing RTC Rollover Event...
$startDate = Get-Date
$days = 365
$endDate = $startDate.AddDays($days)
Write-Output "Start date: $startDate"
Write-Output "End date: $endDate"
$elapsedDays = ($endDate - $startDate).TotalDays
Write-Output "Elapsed time: $elapsedDays days"
Write-Host Done!
Write-Host Running TPM Self Test...
Write-Host Need to get TPM Status before Running Self Test...
$tpmStatus = (Get-Tpm).TpmEnabled
if ($tpmStatus -eq "True") {
    Write-Host TPM is Enabled, Running Self-Test...
    Initialize-Tpm   
} else {
    Write-Host TPM is Not Enabled, Skipping...
}
Write-Host Done!
Write-Host Testing External Loopback on your Serial Port...
$ports = Get-WmiObject -Class Win32_SerialPort

if ($ports) {
    foreach ($port in $ports) {
        if($port.DeviceID -eq "COM1") {
            if ($port.IsConnected -eq "True") {
                $serialPort = new-Object System.IO.Ports.SerialPort $port.DeviceID,$port.BaudRate,$port.Parity,$port.DataBits,$port.StopBits
                $serialPort.Open()
                $serialPort.WriteLine("Testing external loopback...")
                $received = $port.ReadLine()

                if ($received -eq "Testing external loopback...") {
                    Write-Host "Test passed. Received: $received"
                } else {
                    Write-Host "Test failed. Received: $received"
                }

                $serialPort.Close()
            } else {
                Write-Host "Serial port $($port.DeviceID) is not connected"
            }
        }
    }
} else {
    Write-Host "No serial ports detected on this computer."
}
Write-Host Done!
Write-Host Testing External Register on your Serial Port...
$ports = Get-WmiObject -Class Win32_SerialPort

if ($ports) {
    foreach ($port in $ports) {
        if($port.DeviceID -eq "COM1") {
            if ($port.IsConnected -eq "True") {
                $serialPort = new-Object System.IO.Ports.SerialPort $port.DeviceID,$port.BaudRate,$port.Parity,$port.DataBits,$port.StopBits
                $serialPort.Open()
                # Send command to device
                $serialPort.WriteLine("Read Register")

                # Read response from device
                $received = $serialPort.ReadLine()

                # Parse response and extract register value
                $registerValue = $received.Split(" ")[1]

                # Compare register value with expected value
                if ($registerValue -eq "0xAA") {
                    Write-Host "Test passed. Register value: $registerValue"
                } else {
                    Write-Host "Test failed. Register value: $registerValue"
                }

                $serialPort.Close()
            } else {
                Write-Host "Serial port $($port.DeviceID) is not connected"
            }
        }
    }
} else {
    Write-Host "No serial ports detected on this computer."
}
Write-Host Done!
Write-Host Testing Internal Control Signals on your Serial Port...
$ports = Get-WmiObject -Class Win32_SerialPort

if ($ports) {
    foreach ($port in $ports) {
        if($port.DeviceID -eq "COM1") {
            if ($port.IsConnected -eq "True") {
                $serialPort = new-Object System.IO.Ports.SerialPort $port.DeviceID,$port.BaudRate,$port.Parity,$port.DataBits,$port.StopBits
                $serialPort.Open()
                
                # Test RTS signal
                $serialPort.RtsEnable = $true
                if ($serialPort.CtsHolding -eq $true) {
                    Write-Host "RTS signal test passed"
                } else {
                    Write-Host "RTS signal test failed"
                }

                # Test DTR signal
                $serialPort.DtrEnable = $true
                if ($serialPort.DsrHolding -eq $true) {
                    Write-Host "DTR signal test passed"
                } else {
                    Write-Host "DTR signal test failed"
                }
                $serialPort.Close()
            } else {
                Write-Host "Serial port $($port.DeviceID) is not connected"
            }
        }
    }
} else {
    Write-Host "No serial ports detected on this computer."
}
Write-Host Done!
Write-Host Testing Internal Register on your Serial Port...
$ports = Get-WmiObject -Class Win32_SerialPort

if ($ports) {
    foreach ($port in $ports) {
        if($port.IsConnected -eq "True") {
            $serialPort = new-Object System.IO.Ports.SerialPort $port.DeviceID,$port.BaudRate,$port.Parity,$port.DataBits,$port.StopBits
            $serialPort.Open()
            
            # Send command to device to read internal register
            $serialPort.WriteLine("Read Internal Register")

            # Read response from device
            $received = $serialPort.ReadLine()

            # Parse response and extract register value
            $registerValue = $received.Split(" ")[1]

            # Compare register value with expected value
            if ($registerValue -eq "0xAA") {
                Write-Host "Test passed. Internal register value: $registerValue"
            } else {
                Write-Host "Test failed. Internal register value: $registerValue"
            }
            $serialPort.Close()
        } else {
            Write-Host "Serial port $($port.DeviceID) is not connected"
        }
    }
} else {
    Write-Host "No serial ports detected on this computer."
}
Write-Host Done!
Write-Host Testing Internal Send and Receive on your Serial Port...
$ports = Get-WmiObject -Class Win32_SerialPort

if ($ports) {
    foreach ($port in $ports) {
        if($port.IsConnected -eq "True") {
            $serialPort = new-Object System.IO.Ports.SerialPort $port.DeviceID,$port.BaudRate,$port.Parity,$port.DataBits,$port.StopBits
            $serialPort.Open()
            
            # Send data to device
            $serialPort.WriteLine("Test Data")
            # Read response from device
            $received = $serialPort.ReadLine()

            # Compare received data with sent data
            if ($received -eq "Test Data") {
                Write-Host "Test passed. Received data: $received"
            } else {
                Write-Host "Test failed. Received data: $received"
            }
            $serialPort.Close()
        } else {
            Write-Host "Serial port $($port.DeviceID) is not connected"
        }
    }
} else {
    Write-Host "No serial ports detected on this computer."
}
Write-Host Done!
Write-Host Running Linear Seek Test on your HDD...
$disk = Get-PhysicalDisk | Where-Object { $_.MediaType -eq 'HDD' } -ErrorAction SilentlyContinue
if ($disk) {
    Write-Host "Performing Linear Seek Test on your HDD..."
    $stopwatch = [diagnostics.stopwatch]::StartNew()
    $partition = $disk | Get-Partition -ErrorAction SilentlyContinue
    if ($partition) {
        $driveLetter = $partition.DriveLetter
        $path = "$($driveLetter)\"
        $ErrorActionPreference = "SilentlyContinue"
        Get-ChildItem -Path $path -Recurse -Force | Get-Content -Encoding byte -ErrorAction SilentlyContinue 
        $stopwatch.Stop()
        $elapsedTime = $stopwatch.Elapsed
        Write-Host "Linear seek test completed in $elapsedTime"
    } else {
        Write-Host "No partitions found on the HDD. Skipping test."
    }
} else {
    Write-Host "No HDD found. Skipping test."
}
Write-Host Done!
Write-Host More diagnostics coming soon!...
}
   'Q'{
Write-Host "Exiting..."
Return
   }
}