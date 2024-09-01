##
##  Script to deploy VMs from templates
##
##
## Change log: 
##     Initial version                          07/27/2020
##     Updated PS modules installation          07/27/2020
##     Completed testing on Win2012 R2          07/31/2020
##     Completed testing on Win2016             07/31/2020
##     v5 converted to single loop
##     Fixed formatting issues
##     SolarWinds - Add Server                  08/03/2020
##     Implemented Log File                     08/18/2020
##     Added Datastore Capacity Check           08/18/2020
##     Added start-transcript output            08/24/2020
##     Changed Domain to join                   09/20/2020
##     Add-WindowsFeature RSAT-DNS-Server       09/20/2020
##     Disabled Windows Visual Effects          09/25/2020
##     Added SolarWinds auth error check        09/25/2020
##     check for duplicate template names       09/25/2020
##     Enable Remote Desktop connections        09/25/2020
##     Disable NIC power managment              11/23/2020
##     Converted to be used via Build_VMs.exe   12/29/2020
##     Fixed Windows Updates function           01/07/2021
##     Fixed SolarWinds Node Name               01/08/2021
##     Fixed Power Plan Settings                01/08/2021
##     Script Cleanup                           01/08/2021
##     Disable IPV6                             01/10/2021
##     Add Memory and CPU Reservation function  01/11/2021
##     Add timer to wait message                01/11/2021
##     Datastore Capacity Check enhancements    01/15/2021
##     VMware Command Timing adjustments        01/15/2021
##     Add pagefile settings                    01/17/2021
##     Add VMware Folder Location setting       01/25/2021
##     Pagefile setting bug fix                 01/25/2021
##     Handle extended first boot delay         01/25/2021
##     SolarWinds - Add Server Resources        01/26/2021
##     Changed version to 21                    01/27/2021
##     modified to use secure credentials       01/27/2021
##     fixed DNS host A record creation         01/27/2021
##     Resource Pool error checking added       01/27/2021
##     VMware Tools -NoReboot flag set          01/27/2021
##     v22 testing no windows updates parameter 02/03/2021
##     Changed to use Get-WinOSname function    02/04/2021
##     Added Created On ($date) to VM Notes     02/10/2021
##     Fix for trusted hosts code               02/22/2021
##     Rework Windows Update installation       06/19/2021
##     Add Disable TLS1 SSL3 etc.               06/19/2021
##     Add AD check for wrong OU                06/19/2021
##     Check if IP is in use!                   06/19/2021
##     Verify Solarwinds is added               06/19/2021
##     Added CrowdStrike installation check     06/21/2021
##     Updated to handle template clone timeout 07/07/2021
##     Reset Windows Update before use          07/07/2021
##     Set TLS1.2 to enable NuGet download      07/08/2021
##     Modified Filecopy error handling         07/08/2021
##     Changed Pending Win update list format   07/08/2021
##     Added error checking for powercli copy   08/12/2021
##     added Reset-WindowsUpdate Function       08/16/2021
##     Changed Windows Update timer to 60 min   08/16/2021
##     if OS customizations fail restart VM     08/16/2021
##     Reworked Windows Update installation     08/16/2021
##
##     Begin PowerShell 7 version               11.19.2021
##     PowerShell v7 support added and tested   01/13/2022
##     Remove Windows Defender Anti-Virus       01/24/2022
##     Added DNS mis-match checking             02/23/2022
##     Added AD server_admins group creation    03/03/2022
##     Added support for VMHost name instead    
##         of Resource Pool name                04/13/2022
##     Check LAPS for Admin Password            04/14/2022
##     Added trim for servernames               06/17/2022
##     Added resourcepool check                 06/18/2022
##     Added support for Cohesity Backups       07/15/2022
##     Enable getting updates from Microsoft    08/01/2022
##     Set local account for PSEXEC.exe use     08/01/2022
##     Disable Services recommended by MS       08/01/2022
##     Changed SolarWinds Polling engine to use 08/01/2022
##     Changed Active Directory OU code         08/01/2022
##     Block Cortana in Firewall rules          08/01/2022
##     Change to winupdate check                08/01/2022
##     Install Hotfix to allow no pagefile on C 08/01/2022
##     changed final winupdate check logic      08/01/2022
##     Fixed Cohesity Refresh & connection      08/03/2022
##     Added WSUS Patch Label assignment        08/12/2022
##     Fixed adding VM to Cohesity job          08/23/2022
##     Remove duplicate Firewall rule entries   08/24/2022
##     Install PSEXEC.EXE by itself and unblock 09/08/2022
##     Fixed installing updates from WSUS and
##         from microsoft at the same time      09/08/2022
##     Fixed pagefile still on C:\ for 2019     09/09/2022
##     Added support for deep level VM folders  09/21/2022
##     If Server exists in Solarwinds, remove   12/30/2022
##     Powershell modules check both locations  03/06/2023
##     Added WSUS "OS" patch labels             03/07/2023
##     Added Solarwinds Manually add Drives     03/17/2023
##     Fixed pagefile on D: or P: drives        04/07/2023
##     Fixed VMware Tools install/update        10/20/2023
##     reworked Windows Patching (again)        10/20/2023
##     USB Removal                              03/11/2024
##     Fixed pagefile on P: drives              04/18/2024
##     Added .NET v3.5 installation option      04/20/2024
##     
##



## Set Namespace for VCenter Menu function
using namespace System.Management.Automation.Host


## Parameters from AutoIT or Python
param ([Parameter(Mandatory=$true)][Alias('Server')][string]$Name, 
    [Parameter(Mandatory=$true)][string]$IP, 
    [Parameter(Mandatory=$true)][string]$SubnetMask, 
    [Parameter(Mandatory=$true)][string]$Gateway, 
    [Parameter(Mandatory=$true)][string]$DNS1, 
    [Parameter(Mandatory=$true)][string]$DNS2, 
    [Parameter(Mandatory=$False)][string]$description,
	[Parameter(Mandatory=$true)][string]$OU, 
    [Parameter(Mandatory=$False)][string]$contact, 
    [Parameter(Mandatory=$False)][Alias('WSUS-RebootPolicy')][string]$RebootPolicy, 
    [Parameter(Mandatory=$False)][string]$TicketNumber,
    [Parameter(Mandatory=$true)][string]$Template, 
    [Parameter(Mandatory=$true)][string]$Cluster, 
    [Parameter(Mandatory=$true)][string]$Datastore, 
    [Parameter(Mandatory=$true)][string]$ResourcePool, 
    [Parameter(Mandatory=$False)][string]$vmFolder,
    [Parameter(Mandatory=$False)][string]$vCPU, 
    [Parameter(Mandatory=$False)][string]$Memory, 
    [Parameter(Mandatory=$False)][string]$harddrive, 
    [Parameter(Mandatory=$False)][string]$harddrive2, 
	[Parameter(Mandatory=$False)][string]$Network, 
    [Parameter(Mandatory=$False)]$Location, 
	[Parameter(Mandatory=$False)][string]$analyst, 
    [Parameter(Mandatory=$False)][Alias('application')][string]$applications, 
    [Parameter(Mandatory=$False)][string]$City, 
    [Parameter(Mandatory=$False)][string]$DataCenter,
	[Parameter(Mandatory=$False)][string]$Customer, 
    [Parameter(Mandatory=$False)][string]$PrimaryAdmin, 
    [Parameter(Mandatory=$False)][string]$SecondaryAdmin,
    [Parameter(Mandatory=$False)][string]$ProductionState, 
    [Parameter(Mandatory=$False)][string]$Rank, 
	[Parameter(Mandatory=$False)][string]$ServerFunction, 
    [Parameter(Mandatory=$False)][Alias('ServerHWType')][string]$ServerHardwareType, 
    [Parameter(Mandatory=$False)]$harddrive3, 
    [Parameter(Mandatory=$False)]$harddrive4, 
    [Parameter(Mandatory=$False)]$harddrive5, 
    [Parameter(Mandatory=$False)]$harddrive6,
    [parameter(Mandatory=$False)][Alias('Reservation')][string]$Reservations, 
    [Parameter(Mandatory=$False)]$EdgeInstall,
    [parameter(Mandatory=$False)][string]$CohesityJob,
    [Parameter(Mandatory=$true)][string]$vCenter,
    [Parameter(Mandatory=$False)][alias('NET_3.5')][string]$NetInstall
)
##  Old parameter $WinUpdate is no longer optional
$winupdate = $true

## Self-elevate the script if required
#if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
#    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
#        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
#        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
#        Exit
#    }
#}

write-host "setting variables..."
start-sleep -seconds 2
## remove leading or trailing spaces from Server Name
$server = $name.trim()
if($Server -like "None"){
    break
}

## OS customization name
$custom = "PowerCLI_only_$server"


## Template P: Drive flag
$UsePdrive = $true


## WSUS server IP address
$WSUSserver = "10.180.23.49"

## $FQDNVIserver is Vcenter Server
$FQDNVIserver = "$vCenter.valleymed.net"

## CrowdStrike path
$CSpath = (Get-ChildItem -Path '\\techhaus\software\CrowdStrike\Servers_N-1' -Include WindowsSensor.exe -Recurse -ErrorAction Silentlycontinue).DirectoryName

## Set Solarwinds Server name
$swissvr = "SWSAMSVR1.valleymed.net"

# $date is used for logging and file naming. Suggest to not use within scripts unless exact 
# string format is suitable (not suitable for calculations!)
$date = (Get-Date).ToString("yyyyMMdd-hhmm")

$Error.Clear()
Start-Transcript -Path "\\techhaus\software\PowerShell\Scripts\VMware\VM_deploy_30_Logs\VMBuild.$server.$date.log"


## get credentials from encrypted file
$error.Clear()
Write-Host "loading credential files"
start-sleep -seconds 3
$namefolder = (Get-ChildItem Env:\USERNAME).value
$namefile = "C:\temp\$namefolder\name.txt"
$file = "C:\temp\$namefolder\password.txt"
$Cred = New-Object System.Management.Automation.PSCredential ((Get-Content $namefile), (Get-Content $file | ConvertTo-SecureString))

$usernamefile = "C:\temp\$namefolder\user_name.txt"
$userpassfile = "C:\temp\$namefolder\user_password.txt"
$SWCred = New-Object System.Management.Automation.PSCredential ((Get-Content $usernamefile), (Get-Content $userpassfile | ConvertTo-SecureString))

$adminpass = "C:\temp\$namefolder\Local_Password.txt"
$adminName = ".\Administrator"
if (!$adminpass -or !$adminName){
    $AdminCred = Get-Credential -Message "Please Enter your Local Administrator Credentials"
    $AdminCred.UserName | Out-File "C:\temp\$namefolder\Local_Admin.txt"
    $AdminCred.Password | ConvertFrom-SecureString | Out-File "C:\temp\$namefolder\Local_Password.txt"
    $adminpass = "C:\temp\$namefolder\Local_Password.txt"
    $adminName = "C:\temp\$namefolder\Local_Admin.txt"
}
$localPassword = (Get-Content $adminpass) | ConvertTo-SecureString
$Adminlocal = (Get-Content $adminpass) | ConvertTo-SecureString
$localAdmin = New-Object System.Management.Automation.PSCredential ("Administrator", (Get-Content $adminpass | ConvertTo-SecureString))
if($Error.exception.message) {
    Write-host "Unable to load credentials."
    Start-Sleep -Seconds 30
    exit
}

## PSEXEC credentials
$username = (get-content $namefile)
$auth = (Get-Content $file | ConvertTo-SecureString)

Write-Host ""
Write-Host "  Begin Building $server" -BackgroundColor Black -ForegroundColor Green
Write-Host ""
Write-Host "Network: "$network
Write-Host "IP Address:  "$IP
Write-Host "OS customization: "$custom
Write-Host "Resource Pool:  " $resourcePool
Write-Host "DataStore:  " $datastore
Write-Host "Base Template:  "$template
Start-Sleep -Seconds 5


## Functions

Function Force-WSUSCheckin($server){
    Invoke-Command -computername $server -scriptblock {param($server)
        Start-Service wuauserv -Verbose 
        # Have to use psexec with the -s parameter as otherwise we receive an "Access denied" message loading the comobject
        #$criteria = ( IsInstalled = 0 and IsHidden = 0 )
        }
    $Cmd = '$updateSession = new-object -com "Microsoft.Update.Session";$updates=$updateSession.CreateupdateSearcher().Search($criteria).Updates' 
    C:\Windows\System32\PSexec.exe -h -s -accepteula \\$server powershell.exe -command $Cmd
    #} -argumentlist $server
    Write-host "Waiting 30 seconds for SyncUpdates webservice to complete to add to the wuauserv queue so that it can be reported on"
    Start-sleep -seconds 30
    Invoke-Command -computername $server -scriptblock {
        # Now that the system is told it CAN report in, run every permutation of commands to actually trigger the report in operation
        wuauclt /detectnow
        (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
        wuauclt /reportnow
        c:\windows\system32\UsoClient.exe startscan
        wuauclt /reportnow
    }
}


Function DoWindowsUpdates {
    param ($server, $cred)
    $namefolder = (Get-ChildItem Env:\USERNAME).value
    $adminpass = "C:\temp\$namefolder\Local_Password.txt"
    $namefile = "C:\temp\$namefolder\name.txt"
    $file = "C:\temp\$namefolder\password.txt"

    $username = (get-content $namefile)
    $auth = (Get-Content $file | ConvertTo-SecureString)
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Credential $cred -value '*' -Force
    if($error.exception.message){
        Clear-Item -Path WSMan:\localhost\Client\TrustedHosts -Force
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Credential $cred -value $server -Force
    }
    ## Install SSU update manually on 2019 servers
    #
    Function ConnectPSsession {
        Param ($server, $cred)
        $b = New-PSSession -Credential $cred -ComputerName $server -ErrorAction SilentlyContinue
        while ($null -eq $b) {
            $loopcount = 1
            While ( $error.exception.message -and $loopcount -lt 6 ){
                $loopcount = $loopcount + 1
                $error.clear()
                Start-Sleep -Seconds 60
                Write-host "Connecting..." -ForegroundColor Yellow -BackgroundColor Black
                $b = New-PSSession -Credential $cred -ComputerName $server -ErrorAction SilentlyContinue
            }
    
            if ($loopcount -ge 6){
                $error.Clear()
                Restart-Computer -Credential $cred -ComputerName $server -Force -Wait -For WinRM -Timeout 300
                if ( $error.exception.message ){
                    $error.clear()
                    Restart-Computer -Credential $cred -Computername $server -Force -Wait -For Wmi -Timeout 300
                    if ( $error.exception.message ) {
                        Write-Host "Windows patching reboot failure. Please investigate."
                        $restartfailure = $true
                        Break
                    }
                }
            }
        }
    
        if ($restartfailure -eq $true){
            Write-Error "Script failure!" 
            Start-Sleep -Seconds 120
            break
        }
        Return $b
    }
    
    $b = ConnectPSsession $server $cred
    Invoke-Command -Session $b -ScriptBlock {
        param($cred, $username, $auth, $server)
        $computer = $server
        Write-Host "  `
         Return Codes:  -2145124329  = not needed `
         Return Codes:  3010  = Success `
         Return Codes:  0  = Success `
         `
         " -ForegroundColor Green -BackgroundColor Black
        Write-Host "Executing on:  $server" -ForegroundColor Green -BackgroundColor Black
        #$OSname = Get-CimInstance -ComputerName $computer -class Win32_operatingsystem
        #if ($osname.caption -like "*2016*"){
            New-PSDrive -Name modpath -PSProvider FileSystem -Root "\\techhaus\software\PowerShell\Scripts\Modules" -Credential $cred
            Start-Sleep -Seconds 5
            Copy-Item modpath:\windows10.0-kb5031362-x64_d5547372d929a0cfcd12559f75d03507ce6c5d8b.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031362-x64_d5547372d929a0cfcd12559f75d03507ce6c5d8b.msu' -Force
            Copy-Item modpath:\windows10.0-kb5031364-x64_03606fb9b116659d52e2b5f5a8914bbbaaab6810.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031364-x64_03606fb9b116659d52e2b5f5a8914bbbaaab6810.msu' -Force
            Copy-Item modpath:\windows10.0-kb4589210-v2-x64_bbbf54336d6e22da5de8d63891401d8f6077d2ce.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb4589210-v2-x64_bbbf54336d6e22da5de8d63891401d8f6077d2ce.msu' -Force
            Copy-Item modpath:\vcredist_x64_a7c83077b8a28d409e36316d2d7321fa0ccdb7e8.exe -Destination 'C:\Program Files\WindowsPowershell\Modules\vcredist_x64_a7c83077b8a28d409e36316d2d7321fa0ccdb7e8.exe' -Force
            Start-Sleep -Seconds 2
            Unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031362-x64_d5547372d929a0cfcd12559f75d03507ce6c5d8b.msu'
            Unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031364-x64_03606fb9b116659d52e2b5f5a8914bbbaaab6810.msu'
            Unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb4589210-v2-x64_bbbf54336d6e22da5de8d63891401d8f6077d2ce.msu'
            Unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\vcredist_x64_a7c83077b8a28d409e36316d2d7321fa0ccdb7e8.exe'
            Start-Sleep -Seconds 2
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031362-x64_d5547372d929a0cfcd12559f75d03507ce6c5d8b.msu' /wait /norestart
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031364-x64_03606fb9b116659d52e2b5f5a8914bbbaaab6810.msu' /wait /norestart
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb4589210-v2-x64_bbbf54336d6e22da5de8d63891401d8f6077d2ce.msu' /wait /norestart
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer 'C:\Program Files\WindowsPowershell\Modules\vcredist_x64_a7c83077b8a28d409e36316d2d7321fa0ccdb7e8.exe /quiet' 
        #}
        #if ($osname.caption -like "*2019*"){
            #New-PSDrive -Name modpath -PSProvider FileSystem -Root "\\techhaus\software\PowerShell\Scripts\Modules" -Credential $cred
            Start-Sleep -Seconds 5
            Copy-Item modpath:\windows10.0-kb4589208-v2-x64_fa90a4bdc1da0f5758cdfa53c58187d9fc894fa0.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb4589208-v2-x64_fa90a4bdc1da0f5758cdfa53c58187d9fc894fa0.msu' -Force
            Copy-Item modpath:\windows10.0-kb5005112-x64_81d09dc6978520e1a6d44b3b15567667f83eba2c.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5005112-x64_81d09dc6978520e1a6d44b3b15567667f83eba2c.msu' -Force
            Copy-Item modpath:\windows10.0-kb5031005-x64_7d20d682b053ea80c24b076dd57069724406fb75.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031005-x64_7d20d682b053ea80c24b076dd57069724406fb75.msu' -Force
            Copy-Item modpath:\windows10.0-kb5031361-x64_961e82abaca6fa50073f65c96143730824956f7d.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031361-x64_961e82abaca6fa50073f65c96143730824956f7d.msu' -Force
            Copy-Item modpath:\windows10.0-kb5030999-x64-ndp48_b31fe632e1c53a8057febdbe0665acd6fc38adb5.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5030999-x64-ndp48_b31fe632e1c53a8057febdbe0665acd6fc38adb5.msu' -Force
            Start-Sleep -Seconds 3
            Unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb4589208-v2-x64_fa90a4bdc1da0f5758cdfa53c58187d9fc894fa0.msu'
            Unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5005112-x64_81d09dc6978520e1a6d44b3b15567667f83eba2c.msu'
            unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031005-x64_7d20d682b053ea80c24b076dd57069724406fb75.msu'
            unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031361-x64_961e82abaca6fa50073f65c96143730824956f7d.msu'
            unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5030999-x64-ndp48_b31fe632e1c53a8057febdbe0665acd6fc38adb5.msu'
            Start-Sleep -Seconds 3
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb4589208-v2-x64_fa90a4bdc1da0f5758cdfa53c58187d9fc894fa0.msu' /wait /norestart
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5005112-x64_81d09dc6978520e1a6d44b3b15567667f83eba2c.msu' /wait /norestart
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031005-x64_7d20d682b053ea80c24b076dd57069724406fb75.msu' /wait /norestart
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031361-x64_961e82abaca6fa50073f65c96143730824956f7d.msu' /wait /norestart
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5030999-x64-ndp48_b31fe632e1c53a8057febdbe0665acd6fc38adb5.msu' /wait /norestart
            Start-Sleep -Seconds 30
        #}
        #if($osname.caption -like "*2022*"){
        #    New-PSDrive -Name modpath -PSProvider FileSystem -Root "\\techhaus\software\PowerShell\Scripts\Modules" -Credential $cred
            #Start-Sleep -Seconds 5
            Copy-Item modpath:\windows10.0-kb5031364-x64_03606fb9b116659d52e2b5f5a8914bbbaaab6810.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031364-x64_03606fb9b116659d52e2b5f5a8914bbbaaab6810.msu' -Force
            Start-Sleep -Seconds 2
            unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031364-x64_03606fb9b116659d52e2b5f5a8914bbbaaab6810.msu'
            Start-Sleep -Seconds 2
            PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5031364-x64_03606fb9b116659d52e2b5f5a8914bbbaaab6810.msu' /wait /norestart
            Start-Sleep -Seconds 60
        #}
        write-host " "
        Import-Module -name PSWindowsUpdate
        Write-Host " "
        Write-Host "Hide specific updates..."
        psexec.exe  -accepteula \\$server -s -i powershell.exe 'Get-WindowsUpdate -Hide -KBArticleID "KB2538243", "KB890830", "KB4589210", "KB4589208", "KB5034439" -Confirm:$false'
        #Get-WindowsUpdate -computername $server -Hide -KBArticleID "KB2538243", "KB890830", "KB4589210", "KB4589208" -Confirm:$false
        #Hide-WindowsUpdate -ComputerName $server -KBArticleID "KB2538243", "KB890830", "KB4589210", "KB4589208" -Confirm:$false

        ## Check LAPS is installed
        Import-Module -Name AdmPwd.PS
        if (!$?){
            install-module -name AdmPwd.PS -force -Confirm:$False
            Import-module -name AdmPwd.PS
        } 
        $LAPS = (Get-AdmPwdPassword -computername $server).password
        Write-Host " "
        Write-Host "Add Windows Update Service Manager..."
        Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -AddServiceFlag 7 -Confirm:$False 
        Write-host " "
    } -ArgumentList $cred, $username, $auth, $server 
    #

    Import-Module -Name PSWindowsUpdate
    Enable-WURemoting

    $b = ConnectPSsession $server $cred
    Invoke-Command -Session $b -ScriptBlock {
        param($cred)
        $server = $ENV:COMPUTERNAME
        Write-Host "Executing on:  $server" -ForegroundColor Green -BackgroundColor Black

        Write-Host "Reset Windows Update Components..." -foregroundcolor Green -BackgroundColor Black
        Function Reset-WindowsUpdate { 
            Write-Host "Resetting Windows Update Components..." -ForegroundColor Yellow -BackgroundColor Black
            Write-Host " "
            $error.clear()
    
            [Net.ServicePointManager]::SecurityProtocol = ([Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12) 
            Get-PackageProvider -ListAvailable
            Import-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 
            if (!$?) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -confirm:$False
                Import-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 
            }
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Import-Module -Name PSWindowsUpdate -Force 
            if (!$?) {
                Install-Module -Name PSWindowsUpdate -AllowClobber -Force
                Import-Module -Name PSWindowsUpdate -Force 
            }
            Enable-WURemoting
            $error.Clear()
            Reset-WUComponents -verbose -erroraction Continue
            start-sleep -Seconds 3
            if ($error.Exception.Message){
                Write-Host "Retrying..." -ForegroundColor Yellow -BackgroundColor Black
                Start-Sleep -Seconds 60
                $error.clear()
                $b = New-PSSession -credential $cred -computername $server
                Invoke-Command -Session $b -scriptblock {
                    param($cred)
                    Import-Module -Name PSWindowsUpdate -Force 
                    Reset-WUComponents -credential $cred -verbose -erroraction Continue
                } -argumentlist $cred
            }
        }

        $error.clear()
        Reset-WindowsUpdate 
        Start-Sleep -Seconds 30
        Write-Host ""
        Write-host "Importing Windows Update Module..." -foregroundcolor Green -backgroundcolor black
        start-sleep -seconds 3
        Import-Module -name PSWindowsUpdate 
        start-sleep -seconds 10
        Write-Host " "
        Write-Host "Enable Windows Update Remote Execution"
        Enable-WURemoting
        Start-Sleep -Seconds 30

    } -argumentlist $cred
    Write-host "Restarting $server" -foregroundcolor Green -backgroundcolor Black
    Restart-Computer -Credential $cred -ComputerName $server -Force -Wait -For WinRM -Timeout 600
    if(!$?){
        Restart-Computer -Credential $cred -ComputerName $server -Force -Wait -For WinRM -Timeout 600
    }

    ## If updates are needed, install them
    $installpass = 1
    do {
        $b = ConnectPSsession $server $cred
    
        $shortlist = $null
        write-host "[WARNING] Install Windows Updates - Pass number $installpass" -ForegroundColor Yellow -BackgroundColor Black
        
        invoke-command -session $b -ScriptBlock {
            param($server, $cred, $file, $username, $auth)
            write-host " "
            Import-Module -name PSWindowsUpdate
            Write-Host " "
            psexec.exe  -accepteula \\$server -s -i powershell.exe 'Get-WindowsUpdate -Hide -KBArticleID "KB2538243", "KB890830", "KB4589210", "KB4589208", "KB5034439" -Confirm:$false'
            Write-host "Getting List of Updates..." -ForegroundColor yellow -BackgroundColor black
            $list = New-Object -TypeName "System.Collections.ArrayList"
            $wuverbose = Get-WUList 
            ForEach ($KB in $wuverbose.KB) {
                if($KB -notlike "KB2538243" -and  $KB -notlike "KB890830" -and $KB -notlike "KB4589210" -and $KB -notlike "KB4589208" -and $KB -notlike "KB5034439" -and $KB -notlike "" -and $KB -ne $null){
                    $list.Add($KB) 
                }
            }
            $wuverboseMSFT = Get-WUList -microsoftupdate 
            ForEach ($KB in $wuverboseMSFT.KB) {
                if($KB -notlike "KB2538243" -and  $KB -notlike "KB890830" -and $KB -notlike "KB4589210" -and $KB -notlike "KB4589208" -and $KB -notlike "KB5034439" -and $KB -notlike "" -and $KB -ne $null){
                    $list.Add($KB) 
                }
            }
            $shortlist = $list | Where-Object {$_ -notlike ""} | Sort-Object -Unique 
            Write-Host "Updates Needed: " $shortlist
            Start-Sleep -Seconds 10
            $loopcount = 1
            While ($shortlist.count -ge 1 -and $loopcount -le 3){
                $lastitem = "none"
                forEach ($item in $shortlist){
                    if ($shortlist.count -ge 1){
                        $loopcount = $loopcount + 1
                        Write-host "installing: " $item
                        Write-host "last KB: " $lastitem
                        if ($item -eq $lastitem) {
                            $restart = "Exit"
                            break
                        }
                        $lastitem = $item
                        write-host "Installing" $lastitem
                        #invoke-WUInstall -ComputerName $server -Script {
                        #    ipmo PSWindowsUpdate; Get-WUInstall -KBArticleID $item -noreboot
                        #} -confirm:$false -Verbose -skipmoduletest -runnow
                        #Import-Module -Name AdmPwd.PS
                        #$LAPS = (Get-AdmPwdPassword -ComputerName $server).password
                        # get-windowsupdate -forceinstall -KBArticleID $item -ignorereboot -confirm:$false"
                        #psexec -u valleymed\$username -p $auth -accepteula \\$server -s -i powershell.exe "ipmo PSWindowsUpdate; start-sleep -seconds 5; get-windowsupdate -forceinstall -acceptall -ignorereboot"
                        invoke-wuJob -ComputerName $server -Credential $cred -taskname WUinstaller -Script { 
                            ipmo PSWindowsUpdate; Install-WindowsUpdate -acceptall -ForceInstall
                        } -runnow -Confirm:$false -verbose 
                        
                        Start-Sleep -Seconds 60
                        $timer = [Diagnostics.Stopwatch]::StartNew()
                        do {
                            #$restart = "False"
                            $jobnames = (Get-WuJob -Taskname WUinstaller -ComputerName $server -Credential $cred | where-object {$_.Statename -like "Running"}).action
                            $tiworker = Get-Process -name tiworker -ErrorAction SilentlyContinue
                            $trustedinstaller = Get-process -name trustedinstaller -ErrorAction SilentlyContinue
                            if($null -notlike $jobnames){
                                write-host "Install Job is: " $jobnames[0]
                            } elseif ($null -notlike $tiworker) {
                                Write-Host "TiWorker is running"
                            } elseif ($null -notlike $trustedinstaller){
                                Write-Host "TrustedInstaller is running"
                            }
                            start-sleep -seconds 60
                        } While($jobnames -like "Running" -or $tiworker -ne $null -or $trustedinstaller -ne $null -or $timer.elapsed.totalseconds -lt 900)
                        $timer.stop()
                        $wuverboseMSFT = Get-WUList -microsoftupdate 
                        $list = New-Object -TypeName "System.Collections.ArrayList"
                        ForEach ($KB in $wuverboseMSFT.KB) {
                            if($KB -notlike "KB2538243" -and  $KB -notlike "KB890830" -and $KB -notlike "KB4589210" -and $KB -notlike "KB4589208" -and $KB -notlike "KB5034439" -and $KB -notlike "" -and $KB -ne $null){
                                $list.Add($KB) 
                            }
                        }
                    }
                    $shortlist = $list | Where-Object {$_ -notlike ""} | Sort-Object -Unique 
                    Write-Host "Updates Needed: " $shortlist
                    Start-Sleep -Seconds 10
                }
            }
        } -ArgumentList $server, $cred, $file, $username, $auth -outvariable restart
        Write-host "Restart Status: " $restart
        Restart-Computer -Credential $cred -ComputerName $server -Force -Wait -For WinRM -Timeout 600

        #            $bootuptime = (Get-CimInstance -ComputerName $server -ClassName Win32_OperatingSystem).LastBootUpTime
        #            #$jobnames = (Get-WuJob -Taskname WUinstaller -ComputerName $server -Credential $cred | where-object {$_.Statename -like "Running"}).action
        #            #$tiworker = Get-Process -name tiworker -ErrorAction SilentlyContinue
        #            #$trustedinstaller = Get-process -name trustedinstaller -ErrorAction SilentlyContinue
        #            do {
        #                $CurrentDate = Get-Date
        #                $uptime = $CurrentDate - $bootuptime
        #                Write-Host "Current Uptime:  " ($uptime).totalminutes
        #                
        #                $cpu = Get-Counter '\Processor(_Total)\% Processor Time'
        #                Write-host "CPU % used: " $cpu.CounterSamples.cookedvalue
        #                $cpuPercentUsed = $cpu.CounterSamples.CookedValue
        #
        #                $jobnames = Get-WuJob -Taskname WUinstaller -ComputerName $server -Credential $cred | where-object {$_.Statename -like "Running"}
        #                if ((($uptime).totalminutes -ge 35 -and $cpuPercentUsed -lt 2 -and $jobnames -notlike "Running") ) {
        #                    Write-Host "We've been trying, Time to restart..." -ForegroundColor Yellow -BackgroundColor Black
        #                    Clear-WUJob -TaskName WUinstaller -ComputerName $server -Credential $cred
        #                    $restart = " true"
        #                    break
        #                } Elseif($jobnames -like $null) {
        #                    $restart = " exit"
        #                } else {
        #                    $restart = "False"
        #                }    
        #                write-host "Current State: " $jobnames.statename  -foregroundcolor Yellow -Backgroundcolor Black
        #                start-sleep -seconds 60
        #                $restart = [string]$restart 
        #                $restart = $restart.substring($restart.length - 5, 5)
        #                return $restart
        #            } While($restart -like "*alse")
        #        #}
        #    } else { 
        #        $restart = " Exit" 
        #        return $restart
        #    }
        #} -ArgumentList $server, $cred -OutVariable restart
        #$restart = [string]$restart 
        #$restart = $restart.substring($restart.length - 5, 5)
        #if ($restart -like "*true"){
        #    Write-Host "Installing Windows Updates Now..." -foregroundcolor green -backgroundcolor black
        #    Restart-Computer -Credential $cred -ComputerName $server -Force -Wait -For WinRM -Timeout 600
        #}
        #
        #write-host "restart is: "$restart
        #Write-Host "Checking for Windows Updates..." -ForegroundColor Green -BackgroundColor Black
        $installpass = $installpass + 1
    } While ($restart -notlike "Exit" -and $installpass -le 5)

    #Restart-Computer -Credential $cred -ComputerName $server -Force -Wait -For WinRM -Timeout 600

    $b = ConnectPSsession $server $cred
    Invoke-Command -Session $b -ScriptBlock {
        $list = New-Object -TypeName "System.Collections.ArrayList"
        Import-Module -Name PSWindowsUpdate -Force
        psexec.exe  -accepteula \\$server -s -i powershell.exe 'Get-WindowsUpdate -Hide -KBArticleID "KB2538243", "KB890830", "KB4589210", "KB4589208", "KB5034439" -Confirm:$false'
        $wuverbose = Get-WUList 
        ForEach ($KB in $wuverbose.KB) {
            if($KB -notlike "KB2538243" -and  $KB -notlike "KB890830" -and $KB -notlike "KB4589210" -and $KB -notlike "KB4589208" -and $KB -notlike "KB5034439" -and $null -ne $KB){
                $list.Add($KB) 
            }
        }
        $shortlist = $list | Where-Object {$_ -notlike ""}
        if($shortlist -eq $null){
            $shortlist = "Success"
        }
        Return ([string]$shortlist).Trim()
    } -OutVariable shortlist
    $shortlist
    if($shortlist -like "Success"){
        Write-host " "
        Write-host " "
        Write-Host "[SUCCESS] Windows is up to date" -ForegroundColor Green -BackgroundColor Black
        Write-host " "
        Write-host " "
    }Else {
        Write-host " "
        Write-host " "
        write-host "[ERROR] ! ! ! WINDOWS UPDATES NEED MANUAL INTERVENTION ! ! !" -ForegroundColor Red -BackgroundColor Black
        Start-Sleep -Seconds 20
        Write-host " "
        Write-host " "
    }
    Write-Host ""
}


function Get-WinOSname {
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline, Mandatory )]
    [string]$computer
    )
    $error.Clear()
    $OSname = Get-CimInstance -ComputerName $computer -class Win32_operatingsystem
    if ($error.exception.message){
        $opt = New-CimSessionOption -Protocol Dcom
        $cimsession = New-CimSession -ComputerName $computer -SessionOption $opt 
        $OSname = Get-CimInstance -CimSession $cimsession -ClassName Win32_OperatingSystem 
    }
    $error.Clear()
    Return $OSname.Caption
}


Function Show-PopUp{ 
    [CmdletBinding()][OutputType([int])]Param( 
        [parameter(Mandatory=$true, ValueFromPipeLine=$true)][Alias("Msg")][string]$Message, 
        [parameter(Mandatory=$false, ValueFromPipeLine=$false)][Alias("Ttl")][string]$Title = $null, 
        [parameter(Mandatory=$false, ValueFromPipeLine=$false)][Alias("Duration")][int]$TimeOut = 0, 
        [parameter(Mandatory=$false, ValueFromPipeLine=$false)][Alias("But","BS")][ValidateSet( "OK", "OC", "AIR", "YNC" , "YN" , "RC")][string]$ButtonSet = "OK", 
        [parameter(Mandatory=$false, ValueFromPipeLine=$false)][Alias("ICO")][ValidateSet( "None", "Critical", "Question", "Exclamation" , "Information" )][string]$IconType = "None" 
         ) 
     
    $ButtonSets = "OK", "OC", "AIR", "YNC" , "YN" , "RC" 
    $IconTypes  = "None", "Critical", "Question", "Exclamation" , "Information" 
    $IconVals = 0,16,32,48,64 
    if((Get-Host).Version.Major -ge 3){ 
        $Button   = $ButtonSets.IndexOf($ButtonSet) 
        $Icon     = $IconVals[$IconTypes.IndexOf($IconType)] 
    } else { 
        $ButtonSets|ForEach-Object -Begin{$Button = 0;$idx=0} -Process{ if($_.Equals($ButtonSet)){$Button = $idx           };$idx++ } 
        $IconTypes |ForEach-Object -Begin{$Icon   = 0;$idx=0} -Process{ if($_.Equals($IconType) ){$Icon   = $IconVals[$idx]};$idx++ } 
    }
    $objShell = New-Object -com "Wscript.Shell" 
    $objShell.Popup($Message,$TimeOut,$Title,$Button+$Icon) 

}
 

function Start-TimeoutDialog {
    Param (
    [Parameter(Mandatory=$false)][String]$Title = "Timeout",
    [Parameter(Mandatory=$false)][String]$Message = "Timeout Message",
    [Parameter(Mandatory=$false)][String]$Message2 = "Timeout Message",
    [Parameter(Mandatory=$false)][String]$Message3 = "Timeout Message",
    [Parameter(Mandatory=$false)][String]$Button1Text = "OK",
    [Parameter(Mandatory=$false)][String]$Button2Text = "Cancel",
    [Parameter(Mandatory=$false)][Int]$Seconds = 30
    )

    Write-Verbose -Message "Function initiated: $($MyInvocation.MyCommand)"
    
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName System.Windows.Forms
    
    $window = $null
    $button1 = $null
    $label = $null
    $timerTextBox = $null
    $timer = $null
    $timeLeft = New-TimeSpan -Seconds $Seconds
    $oneSec = New-TimeSpan -Seconds 1
    
    # Windows Form
    $window = New-Object -TypeName System.Windows.Window
    $window.Title = $Title
    $window.SizeToContent = "Height"
    $window.MinHeight = 160
    $window.Width = 310
    $window.WindowStartupLocation = "CenterScreen"
    $window.Topmost = $true
    $window.ShowInTaskbar = $false
    $window.ResizeMode = "NoResize"
    
    # Form Layout
    $grid = New-Object -TypeName System.Windows.Controls.Grid
    $topRow = New-Object -TypeName System.Windows.Controls.RowDefinition
    $topRow.Height = "25"
    $secondRow = New-Object -TypeName System.Windows.Controls.RowDefinition
    $secondRow.Height = "Auto"
    $thirdRow = New-Object -TypeName System.Windows.Controls.RowDefinition
    $thirdRow.Height = "*"
    $fourthRow = New-Object -TypeName System.Windows.Controls.RowDefinition
    $fourthRow.Height = "Auto"
    $fifthRow = New-Object -TypeName System.Windows.Controls.RowDefinition
    $fifthRow.Height = "Auto"
    $grid.RowDefinitions.Add($topRow)
    $grid.RowDefinitions.Add($secondRow)
    $grid.RowDefinitions.Add($thirdRow)
    $grid.RowDefinitions.Add($fourthRow)
    $grid.RowDefinitions.Add($fifthRow)
    
    $buttonStack = New-Object -TypeName System.Windows.Controls.StackPanel
    $buttonStack.Orientation = "Horizontal"
    $buttonStack.VerticalAlignment = "Bottom"
    $buttonStack.HorizontalAlignment = "Right"
    $buttonStack.Margin = "0,5,5,5"
    [System.Windows.Controls.Grid]::SetRow($buttonStack,4)
    $grid.AddChild($buttonStack)
    $window.AddChild($grid)
    
    
    # Message Label
    $label = New-Object -TypeName System.Windows.Controls.Label
    $label.Margin = "20,0,0,0"
    $label.Content = $Message
    [System.Windows.Controls.Grid]::SetRow($label,0)
    $grid.AddChild($label)
    
    # Message Label
    $label2 = New-Object -TypeName System.Windows.Controls.Label
    $label2.Margin = "20,0,0,0"
    $label2.Content = $Message2
    [System.Windows.Controls.Grid]::SetRow($label2,1)
    $grid.AddChild($label2)
    
    # Message Label
    $label3 = New-Object -TypeName System.Windows.Controls.Label
    $label3.Margin = "20,0,0,0"
    $label3.Content = $Message3
    [System.Windows.Controls.Grid]::SetRow($label3,2)
    $grid.AddChild($label3)
    
    # Count Down Textbox
    $timerTextBox = New-Object -TypeName System.Windows.Controls.TextBox
    $timerTextBox.Width = "150"
    $timerTextBox.TextAlignment = "Center"
    $timerTextBox.IsReadOnly = $true
    $timerTextBox.Text = $timeLeft.ToString()
    [System.Windows.Controls.Grid]::SetRow($timerTextBox,3)
    $grid.AddChild($timerTextBox)
    
    # Button One
    $button1 = New-Object -TypeName System.Windows.Controls.Button
    $button1.MinHeight = 23
    $button1.MinWidth = 75
    $button1.VerticalAlignment = "Bottom"
    $button1.HorizontalAlignment = "Right"
    $button1.Margin = "0,0,0,0"
    $button1.Content = $Button1Text
    $button1.Add_Click({$window.Tag=$Button1Text;$window.Close()})
    $button1.IsDefault = $true
    $buttonStack.AddChild($button1)
    
    # Windows Timer
    $timer = New-Object -TypeName System.Windows.Threading.DispatcherTimer
    
    $timer.Interval = New-TimeSpan -Seconds 1
    $timer.Tag = $timeLeft
    $timer.Add_Tick({
      $timer.Tag = $timer.Tag - $oneSec
      $timerTextBox.Text = $timer.Tag.ToString()
      if ($timer.Tag.TotalSeconds -lt 1) { $window.Tag = "TIMEOUT"; $window.Close() }
    })
    $timer.IsEnabled = $true
    $timer.Start()
    
    # Show
    $window.Activate() | Out-Null
    $window.ShowDialog() | Out-Null
    $window.Tag
    $timer.IsEnabled = $false
    $timer.Stop()
    $window = $null
    $button1 = $null
    $label = $null
    $timerTextBox = $null
    $timer = $null
    $timeLeft = $null
    $oneSec = $null
    
    Write-Verbose -Message "Function completed: $($MyInvocation.MyCommand)"
}


function logAndWrite ([Parameter(Mandatory=$True)]$logPath, [Parameter(Mandatory=$True)]$logText) {
    switch -regex ($logText) {
        # Based on flag, color text
        '\[SUCCESS\]' {Write-Host $logText.Substring(10) -BackgroundColor Black -ForegroundColor Green}
        '\[INFO\]' {Write-Host $logText.Substring(7) -BackgroundColor Black -ForegroundColor White}
        '\[WARNING\]' {Write-Host $logText.Substring(10) -BackgroundColor Black -ForegroundColor Yellow}
        '\[ERROR\]' {Write-Host $logText -BackgroundColor Black -ForegroundColor Red}
        default {Write-Host $logText}
    }
    
    # add datestamped log text to file
    $logText = ((Get-Date).ToString("yyyyMMdd-hh:mm:ss")) + ": $logText"
    # write comment to log file
    Add-Content -Path $logPath -Value $logText -Force
}


# Creates the specified folder if it does not already exist. Takes a single input parameter
function createLogFolder { Param($folderPath)
	
    if (!(Test-Path $folderPath)) {
		Write-Output "[INFO] Folder path, $folderPath, does not exist. Creating directory..."
		mkdir $folderPath

		if (!(Test-Path $folderPath)) {
			Write-Output "[ERROR] Directory creation failed. Exiting script..."
			return
		} else {
			Write-Output "[SUCCESS] Log directory $folderPath creation succeeded..."
		}
	}
    <# 
    else {
        # Clean up old logs
        $limit = (Get-Date).AddDays(-365)
        $logFiles = Get-ChildItem -Path $folderPath -Recurse -Force
        if ( $logFiles.Count -ge 200 ) {
            #clean up logs older than $limit 
            $logFiles | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $limit } | Remove-Item -Force
        }
    }
    #>
}


## Reset Windows Update Components
Function Reset-WindowsUpdate { param($server, $cred)
    Write-Host "Resetting Windows Update Components..." -ForegroundColor Yellow -BackgroundColor Black
    Write-Host " "
    $error.clear()
    $b = New-PSSession -credential $cred -computername $server -ErrorAction SilentlyContinue
    While($error.exception.message){
        Start-Sleep -Seconds 60
        $error.clear()
        $b = New-PSSession -credential $cred -computername $server
    }

    invoke-command -session $b -scriptblock {param($cred)
        New-PSDrive -Name nugetfolder -PSProvider FileSystem -Root "\\techhaus\software\PowerShell\scripts\Modules" -Credential $cred
        copy-item nugetfolder:\nuget -Container -Destination 'C:\Program Files\PackageManagement\ProviderAssemblies\' -Recurse -Force
        #Remove-PSDrive Nugetfolder
    } -ArgumentList $cred

    #Invoke-Command -Session $b -ScriptBlock {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}
    Invoke-Command -Session $b -ScriptBlock {Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -confirm:$False}
    Invoke-Command -Session $b -ScriptBlock {Get-PackageProvider -ListAvailable}
    Invoke-Command -Session $b -ScriptBlock {Import-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 }
    Invoke-Command -Session $b -ScriptBlock {Set-PSRepository -Name PSGallery -InstallationPolicy Trusted }
    Invoke-Command -session $b -ScriptBlock {Import-Module -Name PSWindowsUpdate -Force }
    $error.Clear()
    Invoke-Command -Session $b -ScriptBlock {Reset-WUComponents -verbose -erroraction Continue}
    if ($error.Exception.Message){
        Write-Host "Retrying..."
        Start-Sleep -Seconds 60
        $error.clear()
        $b = New-PSSession -credential $cred -computername $server
        Invoke-Command -session $b -ScriptBlock {Import-Module -Name PSWindowsUpdate -Force }
        Invoke-Command -Session $b -ScriptBlock {Reset-WUComponents -verbose -erroraction Continue}
    }
    #Remove-PSSession $b
}


function WaitForReboot {
    param($wait)
    logAndWrite $logPath "[WARNING] Please Wait for reboot..." 
    $Message = "$server - Please Wait for reboot..."
    $Title = 'Wait for Reboot'
    $TimeOut = [int]$wait
    $ButtonSet = 'OK'
    $IconType = 'Exclamation'

    Show-PopUp -Message $Message -Title $Title -TimeOut $TimeOut -ButtonSet $ButtonSet -IconType $IconType 
}


Function SWISaddResources {

[CmdletBinding()]
Param(
    [Parameter(Position=0,mandatory=$true)]
    # Swis connection created via Connect-Swis command
    [Object]$swis,
    [Parameter(Position=1,mandatory=$true)]
    # ID of node to import resources
    [int]$nodeId,
    [Parameter(Position=2,mandatory=$false)]
    # Timeout in seconds for wait for 'ReadyForImport' status
    [int]$timeout = 360,
    [Parameter(Position=3,mandatory=$false)]
    # Time to wait before next status check
    [int]$timeBetweenChecks = 30

)
# It takes a while before job will turn to 'InProgress' status from 'Unknown'
$ensureJobWasCreatedWait = 120

$sw = [diagnostics.stopwatch]::StartNew()

Write-Host ("Creating scheduled list resources job...")
#$result = $null
do
{
    if ($sw.Elapsed.TotalSeconds -gt $timeout){
        Write-Host "        Timeout elapsed when creating job. " -ForegroundColor Red -BackgroundColor Black
        Write-host "This is probably caused by calling this script with same nodeId." -ForegroundColor Red -BackgroundColor Black
        Write-Host "Please wait a few minutes or extend timeout." -ForegroundColor Red -BackgroundColor Black
        break
    }
    if($null -eq $result){
        $result = Invoke-SwisVerb $swis "orion.nodes" "ScheduleListResources" @($nodeId)
        $jobId = $result.'#text'
        Write-Host ("Created job with guid:  " + $jobId)
    }
    Start-Sleep -Seconds $ensureJobWasCreatedWait
    $status = Invoke-SwisVerb $swis "orion.nodes" "GetScheduledListResourcesStatus" @($jobId, $nodeId)
    Write-host ("Job status is: " + $status.'#text')
} while ($status.'#text' -eq "Unknown")

Write-Host ("Waiting until job status will be 'ReadyForImport'...")
while ($status.'#text' -ne "ReadyForImport") {
    if ($sw.Elapsed.TotalSeconds -gt $timeout)
    {
        Write-Host "Timeout elapsed when waiting for status 'ReadyForImport'" -ForegroundColor Red -BackgroundColor Black
        break
    }
    Start-Sleep -Seconds $timeBetweenChecks
    $status = Invoke-SwisVerb $swis "orion.nodes" "GetScheduledListResourcesStatus" @($jobId, $nodeId)
    Write-Host ("Job status is: " + $status.'#text')
}

Write-Host ("Importing list resources...")
$importResult = Invoke-SwisVerb $swis "orion.nodes" "ImportListResourcesResult" @($jobId, $nodeId)

    if (![System.Convert]::ToBoolean($importResult.'#text')) {
        Write-Host "Import of ListResources result for NodeId:" + $nodeId + " finished with errors." -ForegroundColor Red -BackgroundColor Black
    } else {
        Write-Host -ForegroundColor Green ("Successfully added Server Resources to SolarWinds.")
    }
}


# Create function to disable service if it is not already disabled and/or has no dependent services
function Disable-Service($service_name){
    $Service_Confirm = (Get-Service -Name $service_name -ErrorAction SilentlyContinue)
    if($Service_Confirm){
        if($Service_Confirm.StartType -ne "Disabled"){
            if($Service_Confirm.DependentServices.Count -ne 0){
                # If service has dependent services
                return ((Get-Date -format "hh:mm:ss")+" |  SKIPPED  |  " + $service_name + " ("+$Service_Confirm.DisplayName+")" + "  |  Service found to have dependents. Skipped...")
            } else {
                # If service doesn't have dependent services, disable it.
                $service_state = (Set-Service -Name $service_name -StartupType Disabled)
                return ((Get-Date -format "hh:mm:ss")+" |  DISABLED  |  " +  $service_name + " ("+$Service_Confirm.DisplayName+")" )
            }
        } else {
            # IF sevice is already disabled.
            return ((Get-Date -format "hh:mm:ss")+" |  SKIPPED  |  " + $service_name  + " ("+$Service_Confirm.DisplayName+")" + "  |  Service already disabled. No actions taken.")
        }
    }
}


function Get-VMFolderByPath {
    <#
    .SYNOPSIS Retrieve VM folders by giving a path

    .DESCRIPTION The function will retrieve a folder by it's path.

    The path can contain any type of leaf (folder or datacenter).

    .NOTES

    Author: Luc Dekens 
    
    .PARAMETER
    Path		The path to the folder. This is a required parameter.
	
    .PARAMETER
    Separator	The character that is used to separate the leaves in the path. The default is '/'
	
    .EXAMPLE
    PS> Get-VMFolderByPath -Path "Folder1/Datacenter/Folder2"
	
    .EXAMPLE
    PS> Get-VMFolderByPath -Path "Folder1>Folder2" -Separator '>'
    #>

    param(
        [CmdletBinding()]
        [parameter(Mandatory = $true)]
        [System.String[]]${Path},
        [char]${Separator} = '/'
    )
    process {
        if ((Get-PowerCLIConfiguration).DefaultVIServerMode -eq "Multiple") {
            $vcs = $global:defaultVIServers
        }
        else {
            $vcs = $global:defaultVIServers[0]
        }
        foreach ($vc in $vcs) {
            $si = Get-View ServiceInstance -Server $vc
            $rootName = (Get-View -Id $si.Content.RootFolder -Property Name).Name
            foreach ($strPath in $Path) {
                $root = Get-Folder -Name $rootName -Server $vc -ErrorAction SilentlyContinue
                $strPath.Split($Separator) | ForEach-Object {
                    $root = Get-Inventory -Name $_ -Location $root -Server $vc -ErrorAction SilentlyContinue
                    if ((Get-Inventory -Location $root -NoRecursion | Select-Object -ExpandProperty Name) -contains "vm") {
                        $root = Get-Inventory -Name "vm" -Location $root -Server $vc -NoRecursion
                    }
                }
                $root | Where-Object { $_ -is [VMware.VimAutomation.ViCore.Impl.V1.Inventory.FolderImpl] } | ForEach-Object {
                    Get-Folder -Name $_.Name -Location $root.Parent -NoRecursion -Server $vc
                }
            }
        }
    }
}


Function ConnectPSsession {
    Param ($server, $cred)
    $b = New-PSSession -Credential $cred -ComputerName $server -ErrorAction Continue
    while ($null -eq $b) {
        $loopcount = 1
        While ( $error.exception.message -and $loopcount -lt 6 ){
            $loopcount = $loopcount + 1
            $error.clear()
            Start-Sleep -Seconds 60
            Write-host "Connecting..." -ForegroundColor Yellow -BackgroundColor Black
            $b = New-PSSession -Credential $cred -ComputerName $server -ErrorAction Continue
        }

        if ($loopcount -ge 6){
            $error.Clear()
            Restart-Computer -Credential $cred -ComputerName $server -Force -Wait -For WinRM -Timeout 300
            if ( $error.exception.message ){
                $error.clear()
                Restart-Computer -Credential $cred -Computername $server -Force -Wait -For Wmi -Timeout 300
                if ( $error.exception.message ) {
                    Write-Host "Windows patching reboot failure. Please investigate."
                    $restartfailure = $true
                    Break
                }
            }
        }
    }

    if ($restartfailure -eq $true){
        Write-Error "Script failure!" 
        Start-Sleep -Seconds 120
        break
    }
    Return $b
}
##example:    $b = ConnectPSsession $server $cred



## ScriptBlocks

## Set Windows Power Plan to High Performance
$SetPower = {
    Write-Host "[WARNING] Setting Windows Power Plan..." -ForegroundColor Yellow -BackgroundColor Black
        $p = Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan -Filter "ElementName = 'High Performance'"      
        powercfg /setactive ([string]$p.InstanceID).Replace("Microsoft:PowerPlan\{","").Replace("}","")
}


## Set Windows Visual Effects for best performance
$SetVFX = {
    $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    $fxset = (Get-ItemProperty -ErrorAction SilentlyContinue -Name visualfxsetting -Path $key).visualfxsetting 
    if ($fxset -ne 2) {
        Set-ItemProperty -Path $key -Name 'VisualFXSetting' -Value 2  
    }
        ## "VisualFXSetting"=dword:00000002"
}


## Set Windows Driver Downloads to Disabled
$SetDownloadDrivers = {
    $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Device Metadata"
    $fxset = (Get-ItemProperty -ErrorAction SilentlyContinue -Name PreventDeviceMetadataFromNetwork -Path $key).PreventDeviceMetadataFromNetwork 
    if ($fxset -ne 1) {
        Set-ItemProperty -Path $key -Name 'PreventDeviceMetadataFromNetwork' -Value 1  
    }
        ## "PreventDeviceMetadataFromNetwork"=dword:00000001"
}


## Scriptblock to copy the PowerShell Modules and the Firewall Rules to the new VM
$copyfiles = {
    param ($cred)
    #Remove-PSDrive -name modpath
    $error.clear()
    New-PSDrive -Name modpath -PSProvider FileSystem -Root "\\techhaus\software\PowerShell\Scripts\Modules" -Credential $cred
    if (!(Test-Path 'C:\Program Files\WindowsPowerShell\Modules\PSWindowsUpdate' -PathType Container )) {
        [Net.ServicePointManager]::SecurityProtocol = ([Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12) 

        Install-Packageprovider -name nuget -MinimumVersion 2.8.5.208 -Force  -confirm:$False
        Install-Module -name pswindowsupdate -AllowClobber -Force
    }
    If($error.exception.message) {
        Copy-Item modpath:\PSWindowsUpdate -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -Force
        [Net.ServicePointManager]::SecurityProtocol = ([Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12) 

        Install-Packageprovider -name nuget -MinimumVersion 2.8.5.208 -Force  -confirm:$False
        Install-Module -Name PSWindowsUpdate -AllowClobber -Force
    }
    $error.Clear()
    Copy-Item modpath:\SysAdminsFriends -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -Force
    Install-Module -Name SysAdminsFriends -AllowClobber -Force
    If($error.exception.message) {
        $error.Clear()
        Copy-Item modpath:\SysAdminsFriends -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -Force
        Start-Sleep -Seconds 3
    }
    Copy-Item modpath:\FirewallRules.csv -Destination 'C:\Program Files\WindowsPowershell\Modules\FirewallRules.csv' -Force
    If($error.exception.message) {
        $error.Clear()
        Copy-Item modpath:\FirewallRules.csv -Destination 'C:\Program Files\WindowsPowershell\Modules\FirewallRules.csv' -Force    
        start-sleep -Seconds 3
    }
    $error.Clear()
    Copy-Item modpath:\AdmPwd.PS -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -Force
    Install-Module -Name AdmPwd.PS -AllowClobber -Force
    Import-Module -Name AdmPwd.PS
    If($error.exception.message) {
        $error.Clear()
        Copy-Item modpath:\AdmPwd.PS -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -Force
        Start-Sleep -Seconds 3
    }
    $error.Clear()
<#
    Copy-Item modpath:\PoshWSUS -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -Force
    Install-Module -Name PoshWSUS -AllowClobber -Force
    Import-Module -Name PoshWSUS
    If($error.exception.message) {
        $error.Clear()
        Copy-Item modpath:\PoshWSUS -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -Force
        Start-Sleep -Seconds 3
    }
    $error.Clear()
#>

    $LAPSpath = Test-Path "C:\Program Files\WindowsPowershell\Modules\AdmPwd.PS" -PathType Container
    $PSWUpath = Test-Path "C:\Program Files\WindowsPowershell\Modules\PSWindowsUpdate" -PathType Container
    $SAFpath = Test-Path "C:\Program Files\WindowsPowershell\Modules\SysAdminsFriends" -PathType Container
    $FWRpath = Test-Path "C:\Program Files\WindowsPowershell\Modules\FirewallRules.csv" -PathType Leaf
    if ((!$LapsPath) -or (!$PSWUpath) -or (!$SAFpath) -or (!$FWRpath)){$status = "Error Occurred"}else{$status = "Copy Completed"}
    Remove-PSDrive -name modpath
    $status
    if ($status -eq "Error Occurred") {
        Write-Host "Copy Failed" -ForegroundColor Red -BackgroundColor Black
        Break
    }
} 
    

## Import Firewall Rules
$ImportRules = {
        param($server, $cred)
        Set-ExecutionPolicy remotesigned
        if(Test-Path -Path 'C:\Program Files\WindowsPowerShell\Modules\SysAdminsFriends' -PathType Container) {
            Write-Host "Directory Found. Importing Module"  -ForegroundColor Yellow -BackgroundColor Black
            #Import-Module -Name 'C:\Program Files\WindowsPowerShell\Modules\SysAdminsFriends'
            Install-Module -Name SysAdminsFriends
            Import-Module -name SysAdminsFriends
        }
        Start-Sleep -seconds 1
        if(Test-Path -Path "C:\Program Files\WindowsPowerShell\Modules\FirewallRules.csv" -PathType Leaf) {
            Write-Host "FirewallRules.csv found. Installing now."  -ForegroundColor Yellow -BackgroundColor Black
            Start-Sleep -Seconds 1
            Import-FirewallRules -CSVFile "C:\Program Files\WindowsPowerShell\Modules\FirewallRules.csv" | Out-Null
        }
        
        ## remove old user Profile firewall entries
        $b = New-PSSession -Credential $cred -ComputerName $server
        Invoke-Command -Session $b -ScriptBlock {
            Set-ItemProperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" -Name "DeleteUserAppContainersOnLogoff" -Value 1
        }

        ## Turn On VM Firewall
        Set-NetFirewallProfile -All -Enabled True
        Start-Sleep -Seconds 10
}


## Pin PowerShell ISE to taskbar - Currently only 2012 works
$PinPS = {
    param ($os)
    Write-Host "Pin PowerShell ISE to Taskbar in $os"  -ForegroundColor Yellow -BackgroundColor Black
    If($os -like "*2012*") {
        $shell = new-object -com "Shell.Application"  
        $folder = $shell.Namespace((Join-Path $env:SystemRoot System32\WindowsPowerShell\v1.0))
        $item = $folder.Parsename('powershell_ise.exe')
        $item.invokeverb('taskbarpin');
    } else {
        Write-Host "Cannot Pin to Taskbar - Not Implemented for $os"  -ForegroundColor Yellow -BackgroundColor Black
        #Start-Process "C:\Program Files\WindowsPowerShell\syspin.exe" "C:\Windows\system32\WindowsPowerShell\v1.0\powershell_ise.exe 'Pin to taskbar'"
    }
}


## Set TLS 
$SetSecurity = {
    Write-Host "Set PSGallery Trusted"  -ForegroundColor Yellow -BackgroundColor Black
    
    ## Enable TLS1.2 and TLS1.3
    #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::SecurityProtocol = ([Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12) 


    $ErrorActionPreference = 'SilentlyContinue'
    #Try {
        $error.clear()

        Write-Host "Trying to disable insecure protocols... " -ForegroundColor Yellow -BackgroundColor Black
        # Sets value if Multi-Protocol Unified Hello already exists.
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "DisabledByDefault" -Value 1
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "DisabledByDefault" -Value 1
         
        # Sets value if PCT 1.0 already exists
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "DisabledByDefault" -Value 1
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "DisabledByDefault" -Value 1
         
        # Sets value if TLS 1.0 already exists
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 1
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1
         
        # Sets value if TLS 1.1 already exists
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 1
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1
         
        # Sets value if SSL 2.0 already exists
        Set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1
         
        # Sets value if SSL 3.0 already exists
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0
        set-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 
    #} Catch {
    if($error.exception.message){    
        Write-Host "Create Registry Keys to Disable insecure protocols..." -ForegroundColor Yellow -BackgroundColor Black
        # Create keys in the registry if they don't already exist
        # Create keys for Multi-Protocol Unified Hello
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "Multi-Protocol Unified Hello"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello" -Name "Server"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello" -Name "Client"
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "DisabledByDefault" -Value 1
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "DisabledByDefault" -Value 1
        
        # Create keys for PCT 1.0
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "PCT 1.0"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0" -Name "Server"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0" -Name "Client"
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "DisabledByDefault" -Value 1
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "DisabledByDefault" -Value 1
 
        # Create keys for SSL 2.0
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "SSL 2.0"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" -Name "Server"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" -Name "Client"
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1
         
        # Create keys for SSL 3.0
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "SSL 3.0"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" -Name "Server"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" -Name "Client"
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1
         
        # Create keys for TLS 1.0
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "TLS 1.0"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" -Name "Server"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" -Name "Client"
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 1
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 1
         
        # Create Keys for TLS 1.1
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -Name "TLS 1.1"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" -Name "Server"
        new-item -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" -Name "Client"
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 1
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0
        new-itemproperty -Credential $cred -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 1
    }

    $ErrorActionPreference = 'Continue'

    ## Install NuGet and Allow PSGallery for PowerShell Modules
    #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::SecurityProtocol = ([Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12) 

    Install-Packageprovider -name nuget -MinimumVersion 2.8.5.208 -Force  -confirm:$False
    ## Register-PackageSource -Name NuGet -Location   https://onegetcdn.azureedge.net/providers/nuget-2.8.5.208.package.swidtag -ProviderName NuGet -trusted
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}


## Initialize and format additional drives
$DiskScript = {
    $disks = Get-Disk
    foreach ($disk in $disks) {
        if ($disk.partitionstyle -eq "RAW") {
            Initialize-Disk -Number $disk.number -confirm:$false
            New-Partition -DiskNumber $disk.number -AssignDriveLetter -UseMaximumSize | Format-Volume -Force -confirm:$false
             
        }
    }
}


## Get Network interface name
$getnetwork = {
    $ethernetlist = Get-NetAdapter 
    foreach( $ethname in $ethernetlist){
        if( $ethname.name -like "Ethernet*" -and $ethname.Status -like "Up" ){
            $EthernetName = $ethname.name
            #Write-host $EthernetName
        }
    }
$EthernetName
}


## Set Windows Updates to Manual
$SetWUmanual = {
    #Install-Module -name PSWindowsUpdate
    Import-module -Name PSwindowsupdate
    Set-WUSettings -NoAutoUpdate -Confirm:$False -verbose
    Start-Sleep -seconds 2
    $wusettings = (get-WUSettings).NoAutoUpdate
    if ($wusettings -ne 1){
        Set-WUSettings -NoAutoUpdate -Confirm:$False -verbose
    }
}




## Start Main Script

##       Logging Setup       ##

# $scriptName is used to name the folder and files created for log
$scriptName = "VM_deploy_30"

# Path to the logs folder which contains the .txt file of raw output of logAndWrite
# You can change this location to whatever you like
$logDir = "\\techhaus\software\PowerShell\Scripts\VMware\AutoIT\$($scriptName)_Logs\"

# For creating the exact log, date/time in the name.
#$logPath = "$logDir\$scriptName.$server.$date.txt" 
$logPath = "$logDir\$scriptName.$server.$date.txt" 

# Create log folder
$logEntries = createLogFolder $logDir
foreach ($logEntry in $logEntries) {
    logAndWrite $logPath $logEntry
}


## Install required Powershell Modules
##
##
$error.Clear()
logandwrite $logPath "[INFO] Setting PSGallery to trusted on local machine"
[Net.ServicePointManager]::SecurityProtocol = ([Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12) 
## not used in PS v7.2  # 
Import-PackageProvider -Name nuget
if (!$?){
    Install-Packageprovider -name nuget -MinimumVersion 2.8.5.201 -Force -confirm:$False
    import-packageprovider -name nuget
    start-sleep -Seconds 10
}
import-module -name PowerShellGet
if (!$?){
    install-module -name PowerShellGet -allowclobber -force
    import-module -name PowerShellGet
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted


logandwrite $logPath "[INFO] Import VMware PowerCLI modules" 
$installed = @(get-module -ListAvailable | Select-String -pattern "VMware")
if($null -eq $installed){
    Install-Module -Name vmware.powercli -SkipPublisherCheck -Credential $cred -AllowClobber -Force -Verbose -Confirm:$False
} 
$contains = "VMware.ImageBuilder"
$installed = $installed | Where-Object { $_ -notlike ($contains -Join "|") } 

Import-Module -Name VMware.PowerCli -Verbose
Start-Sleep -Seconds 2 
$loaded = @(Get-Module | Select-String -Pattern "VMware")
$loaded = $loaded | Where-Object { $_ -notlike ($contains -Join "|") } 

#if($loaded.Count -ne $installed.Count){
#    $error.Clear()
#    if ((Test-Path -Path 'C:\Program Files\WindowsPowerShell\Modules\VMware.PowerCLI' -PathType Container) -or (Test-Path -Path 'C:\Program Files (x86)\WindowsPowerShell\Modules\VMware.PowerCLI' -PathType Container)) {
#        Write-Host "Directory Found. Importing Module"  -ForegroundColor Green -BackgroundColor Black
#        Remove-Module -name "vmware.*" -Force -Confirm:$False
#        # Remove-Item -recurse -force "C:\Program Files\WindowsPowerShell\Modules\vm*" 
#        $error.Clear()
#        Start-Sleep 2
#        Install-Module -Name vmware.powercli -SkipPublisherCheck -Credential $cred -AllowClobber -Force -Confirm:$False
#        Import-Module -Name VMware.PowerCli 
#         
#        foreach($message in $error.exception.message){if($message -like "*The VMware.ImageBuilder module*"){$error.Clear()}}
#
#        if (($null -ne $error.exception.message)){
#            Write-Error "Import failed" -ErrorAction stop
#        } else {
#            Write-Host "ImageBuilder Module is not used. Import Succeeded" -ForegroundColor Green -BackgroundColor Black
#        }
#    } else {
#        $error.Clear()
#        Install-Module -Name vmware.powercli -SkipPublisherCheck -Credential $cred -AllowClobber -Force -Confirm:$False
#        Import-Module -name "VMware.PowerCLI"
#        import-module -name "VMware.VimAutomation.Sdk"
#        foreach($message in $error.exception.message){
#            if($message -like "*The VMware.ImageBuilder module*" -or $error.exception.message -like "*is currently in use.*")
#                {$error.Clear()
#            }
#        }
#        if ($null -ne $error.exception.message){
#            Write-Host "Copying VMware PowerShell Modules..."
#            Copy-Item "\\stqnas1\software\PowerShell\Scripts\VMware\Modules\VMware*" -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -ErrorAction SilentlyContinue
#            $loops = 0
#            while($error.exception.message -and $loops -le 10){
#                $error.Clear()
#                Copy-Item "\\stqnas1\software\PowerShell\Scripts\VMware\Modules\VMware*" -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse
#                $loops = $loops + 1
#            }
#            if ($loops -ge 10){
#                Write-Error "Exiting Script" -ErrorAction Stop
#            }
#            $error.clear()
#            Import-Module -Name "VMware.PowerCLI"
#            import-module -name "VMware.VimAutomation.Sdk"
#            foreach($message in $error.exception.message){if($message -like "*The VMware.ImageBuilder module*"){$error.Clear()}}
#        }
#        if ($loops -ge 10 -or $null -ne $error.exception.message){
#            Write-Host "Exiting Script"
#            Write-Error " Import-Module vmware.powercli failed " -ErrorAction stop
#            break
#        }
#    }
#}


Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false -verbose
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -verbose


## Check for Cohesity PowerShell Module
if(Get-Module -ListAvailable | Where-Object { $_.name -like "cohesity.powershell" }){
    Import-Module -Name cohesity.powershell
} else {
    Install-Module -name cohesity.powershell
    import-module -name cohesity.powershell
}
logandwrite $logPath "[Success] Cohesity PowerShell Module installed - Continuing" # -ForegroundColor Green -BackgroundColor Black



# Checking for Required AD Powershell Module. Importing if not available
logandwrite $logPath "[Success] Checking for Required AD Powershell Module" # -ForegroundColor Green
 
$name="ActiveDirectory"
if(-not(Get-Module -name $name)){
    if(Get-Module -ListAvailable | Where-Object { $_.name -eq $name }){
        Import-Module -Name $name
        write-host "Active Directory Module Installed - Continuing" -ForegroundColor Green -BackgroundColor Black
    } else {
        write-host "Active Directory powershell Module Not Installed - Installing" -ForegroundColor Yellow -BackgroundColor Black
        ## for server os
        Add-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature | Out-Null        
        ## for old client os
        Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell
        ## for new client os
        Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”
        ## for Windows 11 clients
        Get-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online | Add-WindowsCapability -Online

        Import-Module -Name ActiveDirectory
        Import-Module -name servermanager
    }
}

$item = $server
$CNname = "CN=" + $item + "_Admins"
$CreateOUpath = "OU=Shared Resources,DC=Valleymed,DC=net"

## Create the Server Admins Group
$SAG_Exists = [ADSI]::Exists("LDAP://$($CNname),$($CreateOUpath)")
If ($SAG_Exists -eq $true){
    logandwrite $logPath "[Success] $($CNname) already exists! Group creation skipped!" # -ForegroundColor Red
} Else {
    # Create the Server Admins Group
    New-ADGroup -Name $($Server + "_Admins") -GroupScope Domain -Path ($($CreateOUpath)) -Credential $cred
    logandwrite $logPath "[Success] Group $($CNname) created!" # -ForegroundColor Green
}


## Install PSexec.exe in your path (e.g. C:\Windows\System32\PSexec.exe)
$error.Clear()
logandwrite $logPath "[INFO]  Installing PSexec.exe in your path (i.e. C:\Windows\System32\PSexec.exe)"
if(!(Test-Path -Path 'C:\Windows\System32\PSexec.exe' -PathType leaf)) {
    Copy-Item \\techhaus\software\PSTools\PsExec.exe -Destination C:\Windows\System32\PSexec.exe -ErrorAction SilentlyContinue
    while ($error.exception.message) { 
        Start-Sleep -seconds 2
        $error.clear()
        Copy-Item \\techhaus\software\PSTools\PsExec.exe -Destination C:\Windows\System32\PSexec.exe -Force
    }
}


## Install SolarWinds Powershell Module
logandwrite $logPath "[INFO] Import SolarWinds module"
if(Test-Path -Path 'C:\Program Files\WindowsPowerShell\Modules\SwisPowerShell' -PathType Container) {
    Write-Host "Directory Found. Importing Module"  -ForegroundColor Yellow -BackgroundColor Black
    Import-Module -Name 'C:\Program Files\WindowsPowerShell\Modules\SwisPowerShell'
} else {
    $error.Clear()
    Copy-Item "\\stqnas1\software\PowerShell\Scripts\VMware\Modules\SwisPowerShell" -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse
    $loops = 0
    while($error.exception.message -and $loops -le 10){
        $error.Clear()
        Copy-Item "\\stqnas1\software\PowerShell\Scripts\VMware\Modules\SwisPowerShell" -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse
        $loops = $loops + 1
    }
    if ($loops -ge 10){
        Write-Error "Exiting Script" -ErrorAction Stop
    }
    Import-Module -Name 'C:\Program Files\WindowsPowerShell\Modules\SwisPowerShell'
}


## Location of Firewall rules file
#$firewallRules = "\\techhaus\software\PowerShell\Scripts\VMware\FirewallRules.csv"

$error.Clear()

## Set $VIserver 
$VIserver = $vCenter.tolower()


## Set Vcenter connection properties
$error.clear()
#Set-PowerCLIConfiguration -InvalidCertificateAction Ignore
logandwrite $logPath "[INFO] Connecting to vCenter"
Connect-VIServer -Server $VIserver -Credential $cred -ErrorAction Continue
if ( !$? ) {
    $error.Clear()
    $cred = get-credential
    Connect-VIServer -Server $VIserver -Credential $cred -ErrorAction Continue
    if($error.exception.message){
        Write-Error "Failed to Connect to the VCenter Server with the supplied Credentials" -ErrorAction Stop
    }
}

#Generate the Computer object in AD to be able to join new VM to domain
logAndWrite $logPath "[WARNING] Generating the AD Computer account for $server" 
#Write-host "Generating the AD Computer account for $server" -ForegroundColor Yellow
$ErrorActionPreference = 'SilentlyContinue'
#Try {
    $Parts = $null
    $orgunit = @()
    $orgunits = $null

    ## Check AD OU
    Write-Host "Checking AD for $server..." -ForegroundColor Yellow -BackgroundColor Black
    $adComputer = $null

    $adComputer = Get-ADComputer -Credential $cred -Identity $server -Server "kodak.valleymed.net" 
    if ($null -ne $adComputer){
        $OUinfo = Get-ADOrganizationalUnit -Identity $(($adComputer).DistinguishedName.SubString($adComputer.DistinguishedName.IndexOf("OU="))) 
        $oufound = $OUinfo.DistinguishedName
    }

    $OU = $OU.trim()

    if ($ou -like "*\*"){
        $parts = $OU -split "\\" 
    } elseif ($ou -like "*/*") {
        $parts = $OU -split '\/' 
    } else {
        $parts = $OU
    }

    foreach ($part in $parts){
        $orgunit += "OU=$part";
    }
    [system.array]::Reverse($orgunit)
    $orgunits = $orgunit -join ','

    if(($oufound -eq $OrgUnits + ",DC=Valleymed,DC=net") -or ($null -eq $oufound)){
        Write-Host "Server OU found: " $oufound -ForegroundColor Green -BackgroundColor Black
        Start-Sleep -Seconds 5
        #New-ADComputer -Server "kodak.valleymed.net" -Name $server -Path $orgunits",DC=Valleymed,DC=net" -Enabled $True -Credential $cred
    } else {
        Write-Host "Server Object in Wrong OU" -ForegroundColor Red -BackgroundColor Black
        Write-Host ""
        Import-Module -name ActiveDirectory
        Write-Host " "
        $removeADentry = $(Write-Host "(Verify you are not re-using an existing host name!!) Remove existing AD Host entry? (Y/n) " -ForegroundColor Red -BackgroundColor Black -NoNewline; Read-Host)
        if($removeADentry -like "y" -or $removeADentry -like "yes"){
            $removeServer = (get-adcomputer -Credential $cred -Filter {Name -eq $server})
            Remove-ADComputer -Credential $Cred $removeServer -Confirm:$false
            Start-Sleep -Seconds 10
        } else {
            Write-host "exiting now" -BackgroundColor Black -ForegroundColor Red
            Start-Sleep -Seconds 300
            exit
        }
    }

New-ADComputer -Server "kodak.valleymed.net" -Name $server -Path $orgunits",DC=Valleymed,DC=net" -Enabled $True -Credential $cred
#} Catch {
    if (!$?) {
        $tempOU = "Servers/test"
        $orgunit = @()
        Write-Host "Creating AD Computer Account" -ForegroundColor Green -BackgroundColor Black
        $parts = $tempOU -split '\/' 
        foreach ($part in $parts){
            $orgunit += "OU=$part"
        }
        [System.Array]::Reverse($orgunit)
        $orgunits = $orgunit -join ','
        New-ADComputer -Server "kodak.valleymed.net" -Name $server -Path $orgunits",DC=Valleymed,DC=net" -Enabled $True -Credential $cred
    } 

$erroractionpreference = 'Continue'



## Enter local admin password for the VM
Write-Host ""
$AdminLocal = $localPassword 
$LocalAdmin = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList '.\administrator',$AdminLocal

## Enter SolarWinds Creds
$error.clear()
$SWcreds = $SWcred

$error.clear()
#Clear-Variable swis
logandwrite $logPath "[INFO] Connecting to SolarWinds"
#Import-Module -Name SwisPowerShell
$swis = Connect-Swis -Hostname $swissvr -Credential $SWcreds
If ($error.exception.message) { 
    logAndWrite $logPath "[ERROR] Could not connect to Solarwinds. Check username and password." 
    Write-Error $error.exception.message -ErrorAction Stop
}


try {
    $Template = Get-Template -Name $Template -ErrorAction SilentlyContinue
} catch {
    $error.Clear()
    Connect-VIServer -Server vmcvc3.valleymed.net -Credential $cred
    Connect-VIServer -Server vmcvc4.valleymed.net -Credential $cred
    $Template = Get-Template -Name $Template
    if($error.exception.message){
        Write-Error " Template not Found! " -ErrorAction Suspend
    }
    Disconnect-VIServer -Server *
    Connect-VIServer -Server $VIServer
}



## Check if VM name is in use
$Exists = get-vm -name $server -ErrorAction SilentlyContinue  
While ($Exists) {
    Write-Host ""
    logAndWrite $logPath "[ERROR] VM already exists!" 
    Write-Host ""
    $Message = '!! VM ALREADY EXISTS !!'
    $Title = 'VM Deployment Warning'
    $TimeOut = 300
    $ButtonSet = 'RC'
    $IconType = 'Critical'

    $retval = Show-PopUp -Message $Message -Title $Title -TimeOut $TimeOut -ButtonSet $ButtonSet -IconType $IconType 
    if ( $retval -eq 2 ) {
        Write-Error "VM exists, exiting" -ErrorAction Stop
    } else {
        $Exists = get-vm -name $server -ErrorAction SilentlyContinue  
    }
}



If ($stopscript -eq $true) {
    Write-Host "Stopping Script..."
    Start-sleep -Seconds 10
    Break
}

## Check if IP Address is in use!
$error.Clear()
$activeIP = $null
$activeIP = ping $IP 
if($activeIP -notcontains "Request timed out.") {
    Write-Host "IP Address $IP is in use!!" -ForegroundColor Red -BackgroundColor Black
    Write-Host "Change the IP in the VM spreadsheet."
    Start-Sleep -Seconds 10
    Break
} else {
    Write-Host "IP Address $IP is available." -ForegroundColor Yellow -BackgroundColor Black
}
Write-Host ""


$error.Clear()
$datastore = $datastore.trim()
$Datastore = Get-Datastore -Name $Datastore
if ($error.exception.message){
    Write-Host " Could NOT find a DataStore with the name:  $datastore"
    Break
}

$CreatedOn = Get-Date -Format dd-MMM-yyyy


## List VM to be built
Write-Host "This is the virtual machine that will be built: " -ForegroundColor Yellow -BackgroundColor Black
Write-Host $Server -ForegroundColor Green -BackgroundColor Black
Write-Host ""


## Check for existence of $resourcePool on $cluster
# $loop = 0
#get resourcepool names in the cluster
Write-Host "Checking for Resource Pool $resourcepool on $cluster..."
$respools = (get-resourcepool -Location $cluster).name

:myLabel foreach($pool in $respools){
    if([string]$pool -ne $resourcepool){
        Write-Host [string]$pool $resourcepool "don't match"
    }
    if([string]$pool -eq $resourcepool){
        Write-Host [string]$pool " matches $resourcepool, Continuing..."
        break myLabel
    }
}

write-host "Continuing..."
if([string]$pool -ne $resourcepool) {
#if($pool -ne $resourcepool) {

write-host [string]$pool $resourcepool
    Write-Host "[Error] Resource Pool not found"
    $error.clear()
    if ($resourcepool -notlike "*.valleymed.net" ){
        $resourcePool = $resourcepool + ".valleymed.net"
    }
    $TargetVMHost = Get-VMHost -Name $resourcePool -ErrorAction SilentlyContinue
    If ($error.exception.message) {
        Write-Host "No Cluster Host Found..."
        break
    } else {
        $Error.Clear()
        Write-Host "Found $resourcepool, Continuing..."
    }
} else {
    Write-Host "Found $resourcepool, Continuing..."
    [object]$TargetVMHost = Get-Cluster $Cluster | Get-ResourcePool -Name $ResourcePool
}


## check DataStore Capacity
$error.clear()
$DatastoreInfo = `
    Get-Datastore | `
    Where-Object {$_.name -like $Datastore} |`
    Select-Object name,  `
    @{name="CapacityGB";Expression={[math]::Round($_.capacitygb,2)}}, `
    @{name="FreeSpaceGB";Expression={[math]::Round($_.freespacegb,2)}}, `
    @{name="PercentFree";Expression={[math]::Round(($_.freespacegb / $_.capacitygb * 100),2)}}
$FreePercent = [int]$DatastoreInfo.PercentFree
Write-Host "Initial Free %: " $FreePercent
if ($FreePercent -lt 25) {
    Write-Host "First Check for Capacity Failed"
    logAndWrite $logPath "[ERROR] Not Enough Free Space in DataStore"
    Write-Error "Not enough free space in Datastore $datastore" -ErrorAction Stop 
} Else {
    Write-Host "Hardrive Capacities Requested"
    Write-Host "$harddrive, $harddrive2, $harddrive3, $harddrive4, $harddrive5, $harddrive6"
    Start-Sleep -Seconds 10
    if($harddrive3 -like "None" -or $harddrive3 -like "0") {
        $totalNewHD = ([int]$harddrive + [int]$harddrive2 + [int]$Memory)
    } else {
        if ($harddrive4 -notlike "None" -and $harddrive5 -notlike "None" -and $harddrive6 -notlike "None"){
            $totalNewHD = ([int]$harddrive + [int]$harddrive2 + [int]$harddrive3 + [int]$harddrive4 + [int]$harddrive5 + [int]$harddrive6 + [int]$Memory)
        }
    }
    Write-Host "New HD capacity Needed: " $totalNewHD
    $datastoreCapacity = Get-Datastore | `
                        Where-Object {$_.Name -like $datastore} | `
                        Select-Object name, `
                        @{name="CapacityGB";Expression={[math]::Round($_.capacitygb,2)}}, `
                        @{name="FreeSpaceGB";Expression={[math]::Round($_.freespacegb,2)}}

    $datastoreFreeGB = ([int]$datastoreCapacity.FreeSpaceGB - $totalNewHD)
    Write-Host "$datastore - Free GB in Datastore: " $datastoreFreeGB
    $PercentFree = ( [math]::round($datastoreFreeGB / [int]$datastoreCapacity.capacitygb * 100))
    Write-Host "Percentage of free space in Datastore: " $PercentFree

    if(([int]$PercentFree) -lt 25) {
        Write-Host "Second Check for Capacity Failed"
        logAndWrite $logPath "[ERROR] Not Enough Free Space in DataStore"
        Write-Error "Not enough free space in Datastore $datastore" -ErrorAction Stop 

    } else {
        logAndWrite $logPath "[SUCCESS] DataStore Capacity Check Passed."
        #Write-Host "Datastore Capacity check passed."
    }
}

Write-Host ""

Start-Sleep -Seconds 5



# Check that DNS IP address matches requested IP, Create the Host (A) record and PTR record in DNS
Invoke-Command -Credential $Cred -computername "kodak.valleymed.net" -scriptblock { 
    param ($server) Get-DnsServerResourceRecord -Name $server -ZoneName 'valleymed.net' -ComputerName "kodak.valleymed.net"
} -ArgumentList $server -OutVariable dnsrecord -ErrorAction SilentlyContinue
if ($dnsrecord.hostname -eq $server) {
    logAndWrite $logPath "[WARNING] DNS Record already Exists."
    Write-host "Requested IP: "$IP
    Write-Host "Current IP: "$dnsrecord.recorddata.IPv4Address
    Write-Host " "
    if ($dnsrecord.recorddata.IPv4Address -ne $IP) {
        Write-Error "IP Address / Hostname mismatch"
        Write-Host "Remove incorrect DNS entries and try again"
        break
    }
} else {
    $error.Clear()
    Invoke-Command -Credential $Cred -computername "kodak.valleymed.net" -scriptblock { 
        param ($server, $IP) 
        Add-DnsServerResourceRecordA -Name $server -ZoneName 'valleymed.net' -ComputerName "kodak.valleymed.net" -IPv4Address $IP -CreatePtr 
    } -ArgumentList $server, $IP -OutVariable dnsrecord
    $dnsrecord
    if ($error.Count -eq 0) { 
        logAndWrite $logPath "[WARNING] DNS and Ptr Records Created."    
    }
}
$ErrorActionPreference = 'Continue'


## Generate a new OSCustomizationSpec to add the server to the domain and configure the NIC
$failure = $True
While($failure -eq $true){
    $Error.Clear()
    $OSCustomizationSpecExists = Get-OSCustomizationSpec -name $custom -ErrorAction SilentlyContinue
    While ($OSCustomizationSpecExists) {
        Write-Host "Removing Old OSCustomizationSpec:  "$custom
        Remove-OSCustomizationSpec -OSCustomizationSpec $custom -ErrorAction SilentlyContinue -Confirm:$false
        Start-Sleep -Seconds 15
        $OSCustomizationSpecExists = Get-OSCustomizationSpec -name $custom -ErrorAction SilentlyContinue
    }
    $error.clear()
    Start-Sleep -Seconds 10
    logAndWrite $logPath "[WARNING] Creating OSCustomizationSpec File"
    #Write-Host "Generating OSCustomizationSpec file" -ForegroundColor Yellow
    New-OSCustomizationSpec `
        -OrgName "Information Technology" `
        -OSType Windows `
        -ChangeSid `
        -Server $VIserver `
        -Name "$custom" `
        -FullName "Valley Medical Center" `
        -Type Persistent `
        -AdminPassword $AdminLocal `
        -TimeZone 'Pacific' `
        -AutoLogonCount 1 `
        -Domain "valleymed.net" `
        -DomainCredentials $cred `
        -NamingScheme Vm `
        -Description "Luke PowerCli Use only" `
        -LicenseMode PerServer `
        -LicenseMaxConnections 5 `
        -Confirm:$false
    Start-Sleep -Seconds 2
    logAndWrite $logPath "[WARNING] Creating OSCustomizationNICmapping File"
    #Write-Host "Generating OSCustomizationNicMapping file" -ForegroundColor Yellow
    Get-OSCustomizationNicMapping `
        -OSCustomizationSpec $custom | `
    Set-OSCustomizationNicMapping `
        -Position 1 `
        -IpMode UseStaticIP `
        -IpAddress $IP `
        -SubnetMask $SubnetMask `
        -DefaultGateway $Gateway `
        -Dns $DNS1, $DNS2 `
        -Confirm:$false `
        -ErrorAction Continue

    if($error.exception.message) {
        $failure = $True
        $error.Clear()
    }else{
        $failure = $False
    }
}

$error.Clear()


## Generating new VM per spec sheet
logAndWrite $logPath "[WARNING] Creating New VM per spec sheet"
Write-Host "Please Wait..." -ForegroundColor Yellow
if (($Template.name).Count -gt 1) { 
    Write-host "using $template..."  
    $Template = $Template[0] 
 }


Start-Sleep -Seconds 10
$error.Clear()
Write-Host "New-VM -Name $server -DiskStorageFormat Thin -Datastore $Datastore -Template $Template -OSCustomizationSpec $Custom -Notes $Description -ResourcePool $TargetVMHost -confirm:$False" #-ResourcePool (Get-ResourcePool -Name $resourcePool -Location (get-cluster $Cluster))
New-VM -Name $server `
    -DiskStorageFormat Thin `
    -Datastore $Datastore `
    -Template $Template `
    -OSCustomizationSpec $Custom `
    -Notes $Description `
    -ResourcePool $targetVMhost `
    -confirm:$False `
    -ErrorAction Continue
     #-ResourcePool (Get-ResourcePool -Name "$resourcePool" -Location (get-cluster $Cluster))
 
If ($error.exception.message -like "*The underlying connection was closed:*") {
    Write-Host "Please Wait..." -ForegroundColor Yellow -BackgroundColor Black
    Start-Sleep -Seconds 180
    $NewVM = Get-VM -Name $server #-erroraction silentlycontinue
    While (!($NewVM)) {
        Write-Host "Please Wait..." -ForegroundColor Yellow -BackgroundColor Black
        Start-Sleep -Seconds 180
        $NewVM = Get-VM -Name $server
    }
    $error.Clear()
}


If ($error.exception.message) { 
    logAndWrite $logPath "[ERROR] PowerCLI Error has occured.  Retrying..." 
    logAndWrite $logPath "[WARNING] Retrying PowerCLI Command..."
    Start-Sleep -Seconds 2
    $error.clear()
    Stop-VM -VM $server -confirm:$false
    Remove-VM -VM $server -DeletePermanently
    Start-Sleep -Seconds 3
    New-VM -Name $server -DiskStorageFormat Thin -Datastore $Datastore -Template $Template -OSCustomizationSpec $Custom -Notes $Description -ResourcePool $TargetVMHost -confirm:$False -ErrorAction Stop #-ResourcePool (Get-ResourcePool -Name "$resourcePool" -Location (get-cluster $Cluster)

#    $vmclusterhost = (get-cluster -Name $Cluster | get-vmhost).Name
#    New-VM -VMHost $vmclusterhost[0] -Name $server -DiskStorageFormat Thin -Datastore $Datastore -Template $Template -OSCustomizationSpec $Custom -Notes $Description -confirm:$False
    If ($error.exception.message) { 
        Write-Error $error.exception.message -ErrorAction Stop
    }
}
Start-Sleep -Seconds 3

#Sets the new VM as a variable to make configuration changes faster
$NewVM = Get-VM -Name $server #-erroraction silentlycontinue
While (!($NewVM)) {
    Start-Sleep -Seconds 15
    $NewVM = Get-VM -Name $server
}


## Set Memory amount and CPU count
logAndWrite $logPath  "[WARNING] Setting Memory and vCPU on $server" 
$NewVM | Set-VM -MemoryGB $Memory -NumCpu $vCPU -Confirm:$false
Start-Sleep -Seconds 2

If ($Reservations -eq "Yes") {
    logAndWrite $logPath "[WARNING] Setting Memory Reservations for $server"
    $newVM | Get-VMResourceConfiguration | Set-VMResourceConfiguration -MemReservationGB $Memory
    Start-Sleep -Seconds 1

    if ($error.exception.message) {
        Write-Host $error.exception.message 
        Start-Sleep -Seconds 300
        exit
    }
}


## Assign network VLAN for new VM
logAndWrite $logPath "[WARNING] Setting Network VLAN on $server" 
# $NewVM = Get-VM -Name $server -erroraction silentlycontinue
$NewVM | Get-NetworkAdapter | Set-NetworkAdapter -Type Vmxnet3 -Confirm:$False
Start-Sleep -Seconds 20

$network = $network.trim()
$NewVM | Get-NetworkAdapter | Set-NetworkAdapter -networkname $Network -Confirm:$false -ErrorAction Continue
if (!$?) {
    $NewVM | Get-NetworkAdapter | Set-NetworkAdapter -portgroup $Network -Confirm:$false 
    if (!$?) {
        logAndWrite $logPath "[ERROR] Build Failed.  $network is not available."
        Write-Host " $network is not available " 
        Start-Sleep -Seconds 300
        Exit
    }
}
Start-Sleep -Seconds 30
        

#Primary Harddrive
$NewVMHddSize = ($NewVM | Get-HardDisk | Where-Object {$_.Name -eq "Hard disk 1"}).CapacityGB
logAndWrite $logPath  "[WARNING] Script is working on primary harddrive sub routine.  VM template hdd size is $NewVMHddSize and the CSV is asking for $HardDrive" 
Start-Sleep -Seconds 1

IF (([int]$HardDrive) -gt $NewVMHddSize){$NewVM | Get-HardDisk | Where-Object {$_.Name -eq "Hard disk 1"} | Set-HardDisk -CapacityGB $HardDrive -Confirm:$false}
Start-Sleep -Seconds 1
        
#Secondary Harddrive
$NewVMHdd2Size = ($NewVM | Get-HardDisk | Where-Object {$_.Name -eq "Hard disk 2"}).CapacityGB
IF($HardDrive2){
    logAndWrite $logPath "[WARNING] Script is working on secondary harddrive sub routine.  VM template hdd size is $NewVMHdd2Size and the CSV is asking for $HardDrive2" 
    IF($Null -eq $NewVMHdd2Size){
        #Write-Host "This is the line that worked $NewVMHdd2Size -eq $Null" -ForegroundColor Yellow
        $NewVM | New-HardDisk -CapacityGB $HardDrive2 -StorageFormat Thin
    } ElseIf(([int]$HardDrive2) -gt $NewVMHdd2Size) {
        #Write-Host "This is the line that worked $HardDrive2 -gt $NewVMHdd2Size" -ForegroundColor Green
        $NewVM | Get-HardDisk | Where-Object {$_.Name -eq "Hard disk 2"} | Set-HardDisk -CapacityGB $HardDrive2 -Confirm:$false
    }
        
}
Start-Sleep -Seconds 2

IF(($HardDrive3 -like "None") -or ($harddrive3 -eq 0 )){
    Write-Host "No additional drives requested"
} Else {
    logAndWrite $logPath "[WARNING] Script is working on harddrive sub routine.  HardDrive3 is being set to $HardDrive3 GB" 
    $NewVM | New-HardDisk -CapacityGB $HardDrive3 -StorageFormat Thin
    Start-Sleep -Seconds 1
    $disk = Get-HardDisk -VM $Server | Select-Object -Index 2
    Write-Host "disk is: " $disk
    ## set the disk to use a new SCSI adapter
    $disk | New-ScsiController -BusSharingMode NoSharing -Type ParaVirtual
}

IF($HardDrive4 -like "none" -or $harddrive4 -eq 0){
    Write-Host ""
} else {
    logAndWrite $logPath "[WARNING] Script is working on harddrive sub routine.  HardDrive4 is being set to $HardDrive4 GB" 
    $NewVM | New-HardDisk -CapacityGB $HardDrive4 -StorageFormat Thin
    Start-Sleep -Seconds 1
    $disk = Get-HardDisk -VM $Server | Select-Object -Index 3
    Write-Host "disk is: " $disk
    ## set the disk to use a new SCSI adapter
    $disk | New-ScsiController -BusSharingMode NoSharing -Type ParaVirtual
}

IF($HardDrive5 -like "none" -or $harddrive5 -eq 0){
    Write-Host ""
} else {
    logAndWrite $logPath "[WARNING] Script is working on harddrive sub routine.  HardDrive5 is being set to $HardDrive5 GB" 
    $NewVM | New-HardDisk -CapacityGB $HardDrive5 -StorageFormat Thin
    Start-Sleep -Seconds 1
    $disk = Get-HardDisk -VM $Server | Select-Object -Index 4
    Write-Host "disk is: " $disk
    ## set the disk to use a new SCSI adapter
    $disk | New-ScsiController -BusSharingMode NoSharing -Type ParaVirtual
}

IF($HardDrive6 -like "none" -or $harddrive6 -eq 0){
    Write-Host ""
} else {
    logAndWrite $logPath "[WARNING] Script is working on harddrive sub routine.  HardDrive6 is being set to $HardDrive6 GB" 
    $NewVM | New-HardDisk -CapacityGB $HardDrive6 -StorageFormat Thin -Controller "SCSI controller 1"
    Start-Sleep -Seconds 1
    $disk = Get-HardDisk -VM $Server | Select-Object -Index 5
    Write-Host "disk is: " $disk
     
}

         
## Set VMware Tag 
if ( $resourcepool -like "Test Resource Pool" ) {
    $mytag = "TestVM"
} else {
    $mytag = "ProductionVM"
}
Get-VM $Server | New-TagAssignment -Tag $mytag


## If ResourcePool assignment failed then set it now.
if ( (get-vm -Name $server).ResourcePool.Name -eq $resourcePool ) {
    Write-Host "ResourcePool is $resourcepool"
} elseif (Get-VMHost -Name $resourcePool) {
    Write-Host "ESX Host is $resourcePool"
} else {
    logAndWrite "[Error] Resource Pool assignment FAILED"
    Write-Host "Stopping Script...."
    break
}


#Notes and Custom Annotations             
logAndWrite $logPath "[WARNING] Setting the notes on $server" 
$Description = @("$Description")
Set-VM -vm $server -description "$Description" -Confirm:$false | Out-Null

If(!(Get-CustomAttribute -Name Application -TargetType VirtualMachine)) {
    New-CustomAttribute -Name "Application" -TargetType VirtualMachine 
}
IF(($Application) -and (Get-CustomAttribute -Name Application -TargetType VirtualMachine)) { 
    Set-Annotation -entity $server -customAttribute "Application" -Value $Application -Confirm:$false
}
$oldnote = (Get-vm -name $server).notes
$newnote = "VM Created - $CreatedOn"
Set-VM -VM $server -Notes "$oldnote `r`n$newnote" -Confirm:$false
Write-Host "Notes written: `r`n$oldnote `r`n$newnote" -ForegroundColor Green -BackgroundColor Black

Start-Sleep -Seconds 5


## enable Copy/paste via VMware Remote Console
$NewVM = get-vm -Name $server
New-AdvancedSetting -Entity $NewVM.name -Name isolation.tools.copy.enable -Value True -Confirm:$false -Force:$true
New-AdvancedSetting -Entity $NewVM.name -Name isolation.tools.paste.enable -Value True -Confirm:$false -Force:$true
New-AdvancedSetting -Entity $NewVM.name -Name isolation.tools.copy.disable -Value False -Confirm:$false -Force:$true
New-AdvancedSetting -Entity $NewVM.name -Name isolation.tools.paste.disable -Value False -Confirm:$false -Force:$true
New-AdvancedSetting -Entity $NewVM.name -Name isolation.tools.setGUIOptions.enable -Value True -Confirm:$false -Force:$true
Start-Sleep -Seconds 15


#Power on the server
logAndWrite $logPath "[WARNING] Powering on $server" 
Start-VM -VM $server -Confirm:$False
start-sleep -Seconds 20


## make sure to Enable VM NIC so we can ping :-)
Get-VM $server | Get-NetworkAdapter | Set-NetworkAdapter -Connected:$True -Confirm:$False -ErrorAction Continue
Start-Sleep -Seconds 20
    
    
## Add Server to Trusted Host list
logandwrite $logPath "[WARNING] Add Server to Trusted Hosts list"
$error.Clear()
$curList = (Get-Item WSMan:\localhost\Client\TrustedHosts).value
if ( $curlist -notlike "*$server,*" ) {
    if ( $curlist ) {
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Credential $cred -value "$curlist, $server" -Force
        if($error.exception.message){
            Clear-Item -Path WSMan:\localhost\Client\TrustedHosts -Force
            Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Credential $cred -value "$server" -Force
        }
    } else {
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Credential $cred -value "$server" -Force
        if($error.exception.message){
            Clear-Item -Path WSMan:\localhost\Client\TrustedHosts -Force
            Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Credential $cred -value "$server" -Force
        }
    }
}
Write-Host " "
$error.Clear()

Clear-DnsClientCache


## Wait for OS customization reboots before continuing.
Write-Host "OS Customization in Progress. Please Wait..." -ForegroundColor Green -BackgroundColor Black
$loopcount = 1
$rebooted = $False

While ( (Test-Connection -ComputerName $server -Count 2 -Quiet ) -eq $False -or $loopcount -lt 10) { 

    Start-Sleep -Seconds 20
    #$Message = 'You MUST Wait for VM customization reboots to complete _BEFORE_ continuing. (You will see the VM auto-login when it is safe to continue)'
    $Title = "$server - VM Deployment Warning"
    if ($loopcount -gt 1){
        $TimeOut = 90
    }else{
        $TimeOut = 1200
    }

    if ($loopcount -gt 5) {
        exit
    }
    
    if($rebooted -ne $true){ 
        $sVar = "You MUST Wait for VM customization reboots BEFORE clicking OK. (You will see the VM  auto-logon when it is safe to continue)"
        $message = $sVar[0..42] -join ""
        $message2 = $sVar[43..84] -join ""
        $message3 = $sVar[85..126] -join ""
        Start-TimeoutDialog -Title $Title -Message $Message -Message2 $message2  -Message3 $message3 -Seconds $TimeOut
    }

    
    #Invoke-Command -Credential $localAdmin -ComputerName $server -ScriptBlock {winrm quickconfig}

    ## Disable Firewall until rules are applied so PING will work
    $Error.Clear()
    #Invoke-Command -credential $cred -ComputerName $server -ScriptBlock {Set-NetFirewallProfile -Profile Public,Private,Domain -Enabled False} -OutVariable firewall -ErrorAction Continue
    if (($error.exception.message) -and $loopcount -lt 5) {
        Write-Host "Trying again in 90 seconds" -ForegroundColor Yellow -BackgroundColor Black
        $error.Clear()
        if ($loopcount -ge 3 -and $retry -ne 1) {
            stop-vm -VM $server -Confirm:$False
            start-sleep -Seconds 10
            $spec = Get-OSCustomizationSpec -Name $custom
            Set-VM -VM $server -OSCustomizationSpec $spec -Confirm:$false
            start-sleep -Seconds 5
            Start-VM -VM $server
            $retry = 1
            $rebooted = $true
        }
    } elseif (!$error.exception.message) {
        Write-Host " Firewall Disabled Successfully. "
        break
    } elseif ($loopcount -ge 10) {
        Write-Host " VM wait time exceeded."
        $Wait = 300
        $Message = "$server - Wait time exceeded.  Retry Y/N"
        $Title = 'Wait for boot'
        $TimeOut = [int]$wait
        $ButtonSet = 'YN'
        $IconType = 'Exclamation'
        $retry = Show-PopUp -Message $Message -Title $Title -TimeOut $TimeOut -ButtonSet $ButtonSet -IconType $IconType 
        If ($retry -ne 6) {
            Write-error "Exiting script" -ErrorAction continue
            $endscript = $true
            Break
        }    
    } elseif ($loopcount -ge 5) {
        stop-vm -VM $server -Confirm:$False
        start-sleep -Seconds 10
        $spec = Get-OSCustomizationSpec -Name $custom
        Set-VM -VM $server -OSCustomizationSpec $spec -Confirm:$false
        start-sleep -Seconds 5
        Start-VM -VM $server
        $rebooted = $true
    }
    
    $loopcount = $loopcount + 1
}

    
If ($endscript -eq $true) {
    Write-Host "Timed out waiting for VM..."
    break
}
    

## Set Inventory Folder
if ( $vmFolder ) {
    logAndWrite $logPath "[WARNING] Moving VM into target folder: $vmFolder"
    $vm = Get-VM -Name $Server
    #$folder = Get-Folder -Name $VMFolder -Type VM
    if ($VMFolder -like "*\*"){
        $VMFolder -replace "\\",'/'
    }
    $folder = Get-VMFolderbypath -path $VMFolder -separator '/'
    Move-VM -VM $vm -Destination $vm.VMHost -InventoryLocation $folder
}


## Add server to the trusted hosts list
#Write-Host "$systemname"
$trustedhosts = (Get-Item -Path WSMan:\localhost\Client\TrustedHosts).value
if ( $trustedhosts -eq '*') {
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -value "" -Force
}
if ( ( $trustedhosts -notlike "*$Server,*" ) ) {
    $curList = (Get-Item WSMan:\localhost\Client\TrustedHosts).value
    if ( $curlist ) {
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Credential $cred -value "$curlist, $Server" -Force
    } else {
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Credential $cred -value "$Server" -Force
    }
}


Clear-DnsClientCache


## Set network adapter state to connected at boot
logAndWrite $logPath "[WARNING] Set Nework adapter connection state"
Get-VM $server | Get-NetworkAdapter | Set-NetworkAdapter -StartConnected:$true -Confirm:$false


## Disable Firewall until rules are applied so PING will work
Invoke-Command -credential $cred -ComputerName $server -ScriptBlock {Set-NetFirewallProfile -Profile Public,Private,Domain -Enabled False} -ErrorAction continue


## Install PSEXEC.exe
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock {
    param($cred)
    New-PSDrive -Name pspath -PSProvider FileSystem -Root "\\techhaus\software\PSTools" -Credential $cred
    Copy-Item pspath:\psexec.exe -Destination 'C:\Windows\system32\psexec.exe' -Force
    Unblock-File -Path 'C:\Windows\system32\psexec.exe'
} -ArgumentList $cred 


## Install SSU update manually on 2019 servers
<#
$b = New-PSSession -credential $cred -computername $server
Invoke-Command -Session $b -ScriptBlock {
    param($cred, $username, $auth, $server)
    $computer = $server
    Write-Host "Executing on:  $computer" -ForegroundColor Green -BackgroundColor Black
    $OSname = Get-CimInstance -ComputerName $computer -class Win32_operatingsystem
    if ($osname.caption -like "*2019*"){
        New-PSDrive -Name modpath -PSProvider FileSystem -Root "\\techhaus\software\PowerShell\Scripts\Modules" -Credential $cred
        Copy-Item modpath:\windows10.0-kb5005112-x64_81d09dc6978520e1a6d44b3b15567667f83eba2c.msu -Destination 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5005112-x64_81d09dc6978520e1a6d44b3b15567667f83eba2c.msu' -Force
        Unblock-File -Path 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5005112-x64_81d09dc6978520e1a6d44b3b15567667f83eba2c.msu'
        PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$computer wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Modules\windows10.0-kb5005112-x64_81d09dc6978520e1a6d44b3b15567667f83eba2c.msu' /wait /forcerestart
        Start-Sleep -Seconds 120
    }
} -ArgumentList $cred, $username, $auth, $server 
#>

Start-Sleep -seconds 10
## Update VMware Tools
logAndWrite $logPath "[WARNING] Update VMware Tools if needed..." 
$error.clear()
Write-Host "Installing VMware Tools update"
Start-Sleep -Seconds 10
$ToolsVersion = get-vm -Name $server | get-vmguest | select VMName, ToolsVersion
if($ToolsVersion.ToolsVersion -ge "12.3.0"){
    Write-Host "VMware Tools are up to date."
} else {
    $error.clear()
    $result = Get-VM -Name $server | Where-Object { 
        $_.ExtensionData.Guest.ToolsVersionStatus -eq 'guestToolsNeedUpgrade' -and $_.PowerState -like 'PoweredOn' } | `
        Get-VMGuest | Where-Object { $_.GuestFamily -like 'WindowsGuest'} | Update-Tools -NoReboot
    
    if ($error.exception.message -like "*Operation is not valid due to the current state of the object*"){
        $error.Clear()
        Start-Sleep -Seconds 60
        Write-Host "Retrying..."
        $result = Get-VM -Name $server | Where-Object { 
            $_.ExtensionData.Guest.ToolsVersionStatus -eq 'guestToolsNeedUpgrade' -and $_.PowerState -like 'PoweredOn' } | `
            Get-VMGuest | Where-Object { $_.GuestFamily -like 'WindowsGuest'} | Update-Tools -NoReboot
    }
    
    if ($error.exception.message) {
        Write-Host "VMware tools check failed.  Trying again..."
        Start-Sleep -Seconds 20
        
        $b = ConnectPSsession $server $cred
        Invoke-Command -session $b -scriptblock {
            param($cred)
            $downloadpath = "C:\Windows\Temp"
            $filename = 'VMware-tools-12.3.0-22234872-x86_64.exe'
            $file = "$downloadpath\$filename"
            New-PSDrive -Name toolspath -PSProvider FileSystem -Root '\\stqnas1\software\VMWare\VMware Tools\Tools_12_3_0' -Credential $cred
            Copy-Item toolspath:$filename -Destination $file
            Unblock-File -Path $file -Confirm:$false
            Start-Process $file -ArgumentList '/s','/v','/qn','REBOOT=R' -Wait # -Credential $cred # 
        } -ArgumentList $cred
    
        $result = Get-VM -Name $server | Where-Object { 
            $_.ExtensionData.Guest.ToolsVersionStatus -eq 'guestToolsNeedUpgrade' -and $_.PowerState -like 'PoweredOn' } | `
            Get-VMGuest | Where-Object { $_.GuestFamily -like 'WindowsGuest'} 
        
        if($result -notlike $null){
        
            $vm = Get-VM $server
            Get-VMGuest $server | Mount-Tools
            $b = ConnectPSsession $server $cred
        
            Invoke-Command -session $b -scriptblock {
                if ((Test-Path -Path C:\Windows\system32\PSEXEC.exe) -eq $false){
                    Copy-Item -Source "\\techhaus\software\PSTools\PsExec.exe" -Destination "C:\Windows\System32\PSexec.exe"
                }
            }
            Invoke-Command -Session $b -ScriptBlock {
                $CDRom = Get-WmiObject -class Win32_CDROMDrive | Select-Object Drive | ForEach {$_.Drive}
                $Subpath = '\setup64.exe'
                $ExecuteEXE = Join-Path -Path $CDRom -ChildPath $Subpath
                $installresult = start-process $executeEXE -ArgumentList '-s -v -qn ADDLOCAL=ALL REBOOT=R' -PassThru -Wait
                $installresult.ExitCode
            } -OutVariable ExitCode
            Write-Host $ExitCode
            if ($exitcode -like "3010" -or $ExitCode -like "0"){
                Write-Host "VMware Tools updated successfully" -ForegroundColor Green -BackgroundColor Black
                $result = $null
            } else {
                Write-Host "VMware Tools Need Manual Update" -ForegroundColor Red -BackgroundColor Black
                $result = "Failure"
            }
        }
    } else {
        Write-Host "VMware Tools Updated Successfully" -ForegroundColor Green -BackgroundColor Black
    }
    
    $ToolsVersion = get-vm -Name $server | get-vmguest | select VMName, ToolsVersion
    $ToolsVersion
}

Write-Host ""
Start-Sleep -seconds 10


## Remove USB Controllers 
Get-view -ViewType VirtualMachine -Property Name,'Config.Hardware.Device' -PipelineVariable vm | where-object {$_.name -eq $server} |
ForEach-Object -Process {
    $spec = New-Object -TypeName VMware.Vim.VirtualMachineConfigSpec

    $vm.Config.Hardware.Device.Where({$_.DeviceInfo.Label -match "usb"}) |
    ForEach-Object -Process {
        $devSpec = New-Object -TypeName VMware.Vim.VirtualDeviceConfigSpec
        $devSpec.Device = $_
        $devSpec.Operation = [VMware.Vim.VirtualDeviceConfigSpecOperation]::remove
        $spec.DeviceChange += $devSpec
    }
    if($spec.DeviceChange -ne $null){
        $vm.ReconfigVM($spec)
    }
}

## Disable Firewall untilGet-ChildItem $uninstallkey -Recurse -ErrorAction Stop | ForEach-Object {
                $CurrentKey = (Get-ItemProperty -Path $_.PsPath)
                if ($CurrentKey -match "Duo Authentication for Windows Logon") {
                    $DV = write-output "$($CurrentKey.DisplayName) $($CurrentKey.DisplayVersion)"
                }
            } rules are applied so PING will work
$Error.Clear()
Invoke-Command -credential $cred -ComputerName $server -ScriptBlock {Set-NetFirewallProfile -Profile Public,Private,Domain -Enabled False} -OutVariable firewall -ErrorAction Continue
if (($error.exception.message) -and $loopcount -lt 5) {
    Write-Host "Trying again in 90 seconds" -ForegroundColor Yellow -BackgroundColor Black
    $error.Clear()
    if ($loopcount -ge 3 -and $retry -ne 1) {
        stop-vm -VM $server -Confirm:$False
        start-sleep -Seconds 10
        $spec = Get-OSCustomizationSpec -Name $custom
        Set-VM -VM $server -OSCustomizationSpec $spec -Confirm:$false
        start-sleep -Seconds 5
        Start-VM -VM $server
        $retry = 1
        $rebooted = $true
    }
} elseif (!$error.exception.message) {
    Write-Host " Firewall Disabled Successfully. "
}


## enable Windows Remote Management - WINRM
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock {winrm quickconfig}


## Disable UAC AAM
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock {
    Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
    Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 0
}


$b = ConnectPSsession $server $cred

## Disable Server Manager on Startup
Invoke-Command -Session $b -ScriptBlock {
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose
}


$b = ConnectPSsession $server $cred

## Install Microsoft .NET
if ($NetInstall -like "True"){
    Invoke-command -Session $b -Scriptblock {
        New-ItemProperty “HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\” -Name “UseWUServer” -Value 0
        Set-ItemProperty “HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\” -Name “UseWUServer” -Value 0
    }
    Restart-Computer -credential $cred -ComputerName $server -Protocol WSMAN -Force -Wait -For WinRM -Timeout 240
    $b = ConnectPSsession $server $cred
    Invoke-command -Session $b -Scriptblock {
        #Install-WindowsFeature -Name NET-Framework-Features -IncludeAllSubFeature -IncludeManagementTools ## installs all versions of .NET
        Install-WindowsFeature NET-Framework-Core -Confirm:$False 
    }
    Restart-Computer -credential $cred -ComputerName $server -Protocol WSMAN -Force -Wait -For WinRM -Timeout 240
    $b = ConnectPSsession $server $cred
}


## Install Microsoft Edge for business
if ($EdgeInstall -like "True"){
    Invoke-command -Session $b -Scriptblock {
        param($cred, $server)
        $location = "\\stqnas1\software\Microsoft\EdgeEnterprise"
        New-PSDrive -Name Edgepath -PSProvider FileSystem -Root $location -Credential $cred
        md -Path C:\temp\edgeinstall -erroraction SilentlyContinue | Out-Null
        Copy-Item -Path Edgepath:\MicrosoftEdgeEnterpriseX64.msi -Destination C:\temp\edgeinstall\ -Force

        Start-Job -Name GetServerData_$server -Scriptblock {
            Start-Process C:\temp\edgeinstall\MicrosoftEdgeEnterpriseX64.msi -ArgumentList "/quiet"
            start-sleep -seconds 60
            ## uninstall Internet explorer
            dism /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 
        }

        $timer = $null
        $jobnames = get-job -State Running | Where-Object {$_.Name.Contains("GetServerData_")}
        while ($null -ne $jobnames.name) { 
            write-host "Waiting for:  " $jobnames.name
            start-sleep -seconds 30
            $jobnames = get-job -State Running | Where-Object {$_.Name.Contains("GetServerData_")}
            if (($jobnames).count -eq 1 -and $null -eq $timer){
                $timer = [Diagnostics.Stopwatch]::StartNew()
            }
            if ($timer.elapsed.totalseconds -gt 300){
                Write-Host $jobnames.name " did not complete within the alotted time."
                Break
            }    
        }
        if ($null -ne $timer){
            $timer.stop()
        }

    } -ArgumentList $cred, $server
    Restart-Computer -credential $cred -ComputerName $server -Protocol WSMAN -Force -Wait -For WinRM -Timeout 240
}

$b = ConnectPSsession $server $cred

## Wait for windows to reboot
Start-sleep -seconds 120

while (!(Test-Connection -computername $server )){
    start-sleep -seconds 20
}

## Disable NIC IPV6
logAndWrite $logPath "[WARNING] Disabling NIC IPV6"
$b = ConnectPSsession $server $cred
Invoke-Command -session $b -scriptblock {
    Get-NetAdapter | foreach { Disable-NetAdapterBinding -InterfaceAlias $_.Name -ComponentID ms_tcpip6 }
    #If the reply is IPv6 address, run following registry setting to just prefer ipv4 and reboot
    New-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0xff -PropertyType “DWord”
    #If DisabledComponents exists, use the set cmdlet
    Set-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0xff
    #You need to reboot the computer in order for the changes to take effect
    #
    # 0    to re-enable all IPv6 components (Windows default setting).
    # 0xff to disable all IPv6 components except the IPv6 loopback interface. This value also configures Windows to prefer using IPv4 over IPv6 
    #      by changing entries in the prefix policy table. For more information, see Source and destination address selection.
    # 0x20 to prefer IPv4 over IPv6 by changing entries in the prefix policy table.
    # 0x10 to disable IPv6 on all nontunnel interfaces (both LAN and Point-to-Point Protocol [PPP] interfaces).
    # 0x01 to disable IPv6 on all tunnel interfaces. These include Intra-Site Automatic Tunnel Addressing Protocol (ISATAP), 6to4, and Teredo.
    # 0x11 to disable all IPv6 interfaces except for the IPv6 loopback interface.
    #
}
Clear-DnsClientCache


## TabletInputService Registry settings
$admin = Get-Content $namefile
Invoke-Command -session $b -scriptblock {
    param($username)
    ## Create ID
    $idRef = [System.Security.Principal.NTAccount]($username)
    ## Set the Key Ownership
    (Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService').SetOwner($idRef)
    ## Disable the service 
    Set-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService” -Name “Start” -Value 4 -Force
    ## Create RegistryRights Object
    $regRights = [System.Security.AccessControl.RegistryRights]::FullControl
    ## Set Inheritance 
    $inhFlags = [System.Security.AccessControl.InheritanceFlags]::None
    ## Set Propagation
    $prFlags = [System.Security.AccessControl.PropagationFlags]::None
    ## Set Access
    $acType = [System.Security.AccessControl.AccessControlType]::Allow
    $acRead = [System.Security.AccessControl.AccessControlActions]::View
    ## Set Current Owner
    (Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService').SetOwner($idRef)
    ## Get Current ACL
    $oldACL = Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService'
    ## Create the Access Control Rule
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)
    $oldacl.SetAccessRule($rule)
    $oldACL | Set-Acl -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService'
    
    
    $oldACL = Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService'
    
    foreach ($account in $oldACL.access){
        $accountname = [string]($account.IdentityReference).Value
        if($accountname -notlike "$username"){
            $idRef = [System.Security.Principal.NTAccount]("$accountname") 
            $inhFlags = [System.Security.AccessControl.InheritanceFlags]::None
            $prFlags = [System.Security.AccessControl.PropagationFlags]::None
            $acType = [System.Security.AccessControl.AccessControlType]::Allow
            $acRead = [System.Security.AccessControl.AccessControlActions]::View
            $regRights = [System.Security.AccessControl.RegistryRights]::ReadKey
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($idRef, $regRights, $inhFlags, $prFlags, $acType)
            ## overwrite the existing ACL Rules
            $oldacl.SetAccessRule($rule)
            ## Apply the Rule to the Registry Key
            $oldACL | Set-Acl -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService'
            $rule = $null
            #Read-Host "continue? "
        }
    }
    ## Set Current Owner
    (Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService').SetOwner($idRef)
    Set-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService” -Name “Start” -Value 4 -Force

    #Remove Inheritance - Inheritance is removed from both keys so that if one is done the other will have to be also.
    $DisableInheritance = $true
    $PreserveInheritanceIfDisabled = $False
    $acl = Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService'
    $acl.SetAccessRuleProtection($DisableInheritance,  $preserveInheritanceIfDisabled)
    Set-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService' $acl
    $acl1 = Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService'
    $acl1.SetAccessRuleProtection($DisableInheritance, $preserveInheritanceIfDisabled)
    Set-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService' $acl1

} -ArgumentList $admin

start-sleep -seconds 90
# Create an array with names of services to disable.    
[System.Collections.ArrayList]$service_disabled = @()

##  Services to disable
#   Bluetooth audio gateway
    $service_disabled.Add("BTAGService")

#   Connected Devices Platform Service
    $service_disabled.Add("CDPSvc")

#   Network Connection Broker
    $service_disabled.Add("NcbService")

#   Bluetooth Support Service
    $service_disabled.Add("bthserv")

#   Xbox Live Auth Manager
    $service_disabled.Add("XblAuthManager")

#   Xbox Live Game Save
    $service_disabled.Add("XblGameSave")

#   WAP Push Message Routing Service
    $service_disabled.Add("dmwappushservice")

#   Downloaded Maps Manager
    $service_disabled.Add("MapsBroker")

#   GeoLocationService
    $service_disabled.Add("lfsvc")

#   Internet Connection Sharing (ICS)
    $service_disabled.Add("SharedAccess")

#   Link-Layer Topology Discovery Mapper
    $service_disabled.Add("lltdsvc")

#   Microsoft Account Sign-in Assistant
    $service_disabled.Add("wlidsvc")

#   Phone Service
    $service_disabled.Add("PhoneSvc")

#   Program Compatibility Assistant Service
    $service_disabled.Add("PcaSvc")

#   Quality Windows Audio Video Experience
    $service_disabled.Add("QWAVE")

#   Radio Management Service
    $service_disabled.Add("RmSvc")

#   Data Service
    $service_disabled.Add("SensorDataService")

#   Sensor Monitoring Service
    $service_disabled.Add("SensrSvc")

#   Sensor Service
    $service_disabled.Add("SensorService")

#   Smart Card Device Enumeration Service
    $service_disabled.Add("ScDeviceEnum")

#   SSDP Discovery
    $service_disabled.Add("SSDPSRV")

#   Still Image Acquisition Events
    $service_disabled.Add("WiaRpc")

#   Touch Keyboard and Handwriting Panel Service
    $service_disabled.Add("TabletInputService")

#   UPnP Device Host
    $service_disabled.Add("upnphost")

#   Wallet Service
    $service_disabled.Add("WalletService")

#   Windows Camera Frame Server
    $service_disabled.Add("FrameServer")

#   Windows Image Acquisition (WIA)
    $service_disabled.Add("stisvc")

#   Windows Insider Service
    $service_disabled.Add("wisvc")

#   Windows Mobile Hotspot Service
    $service_disabled.Add("icssvc")
 
## Disable reqested services
Invoke-Command -Session $b -ScriptBlock {
    param($service_disabled)
    function Disable-Service($service_name){
        $Service_Confirm = (Get-Service $service_name -ErrorAction SilentlyContinue)
        if (($Service_Confirm) -and ($Service_Confirm.StartType -ne "Disabled")){
            # Disable Service and dependent services
            $service =  Get-Service $service_name
            $service | Stop-Service  -Force
            Start-Sleep -Seconds 10
            $service | Set-Service -StartupType Disabled
            $Service_Confirm = (Get-Service $service_name -ErrorAction SilentlyContinue)
            # If service isn't disabled
            if (($Service_Confirm.DependentServices.Count -ne 0) -and ($Service_Confirm.DependentServices.StartType -notlike "Disabled")){
                # If service has dependent services
                return ((Get-Date -format "hh:mm:ss") + `
                    " |  SKIPPED  |  " + `
                    $service_name + `
                    " ("+$Service_Confirm.DependentServices.StartType+")" + `
                    " ("+$Service_Confirm.DependentServices.DisplayName+")" + `
                    "  |  Service found to have dependents. Skipped...")
            } else {
                # If service doesn't have dependent services, disable it.
                Set-Service -Name $service_name -StartupType Disabled
                return ((Get-Date -format "hh:mm:ss") + `
                    " |  DISABLED  |  " +  `
                    $service_name + `
                    " ("+$Service_Confirm.DisplayName+")" )
            }
        } else {
            # IF sevice is already disabled.
            return ((Get-Date -format "hh:mm:ss") + `
                " |  SKIPPED  |  " + `
                $service_name  + `
                " ("+$Service_Confirm.DisplayName+")" + `
                "  |  Service already disabled. No actions taken.")
        }
    }
    Foreach($item in $service_disabled){
        Disable-Service -service_name $item
    }
} -ArgumentList $service_disabled


## Extend drives to defined size
logAndWrite $logPath "[WARNING] Extending Drive(s) to requested size..."
invoke-command -Credential $cred -ComputerName $server  -scriptblock { $drivesize = (Get-Disk -number 0).AllocatedSize 
    $tosize = (Get-PartitionSupportedSize -DriveLetter C ).sizeMax
    if ($drivesize -lt $tosize) { 
        Resize-Partition -DriveLetter C -Size $tosize
    }
}

if ($UsePdrive -like $True){
	invoke-command -Credential $cred -ComputerName $server  -scriptblock { 
		$offlinedisks = Get-Disk | Where-Object IsOffline –Eq $True
		if($null -ne $offlinedisks){
			$offlinedisks | set-disk -IsOffline $false
		}
		Get-Partition -DiskNumber 1 -PartitionNumber 1 | Set-Partition -NewDriveLetter P
		$drivesize = (Get-Disk -number 1).AllocatedSize 
	    $tosize = (Get-PartitionSupportedSize -DriveLetter P ).sizeMax
	    if ($drivesize -lt $tosize) { 
	        Resize-Partition -DriveLetter P -Size $tosize
	   	}
	}
} else {
	invoke-command -Credential $cred -ComputerName $server  -scriptblock { $drivesize = (Get-Disk -number 1).AllocatedSize 
		$offlinedisks = Get-Disk | Where-Object IsOffline –Eq $True
		if($null -ne $offlinedisks){
			$offlinedisks | set-disk -IsOffline $false
		}
    	$tosize = (Get-PartitionSupportedSize -DriveLetter D ).sizeMax
    	if ($drivesize -lt $tosize) { 
        	Resize-Partition -DriveLetter D -Size $tosize
    	}
	}
}

## Initialize and format additional disks
IF(($HardDrive3 -notlike "none") -or ($harddrive3 -notlike "0")){
    logAndWrite $logPath "[WARNING] Initializing new disks..." 
    Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock $DiskScript 
}


## Copy Powershell Modules to target server
logAndWrite $logPath "[WARNING] Copy PowerShell Modules to $server" 
$Error.Clear()
if ($b = ConnectPSsession $server $cred) {
    $error.Clear()
    $state = $null
    Invoke-Command -Session $b -ScriptBlock $copyfiles -ArgumentList $cred -OutVariable state
} else {
    $error.Clear()
    $b = ConnectPSsession $server $cred
    $state = $null
    Invoke-Command -Session $b -ScriptBlock $copyfiles -ArgumentList $cred -OutVariable state
}

if ($state -like "*Error Occurred*"){
    Write-Host "Copy Error Occurred. Please Check VM State."
    Break
}
#Remove-PSSession $b


## If 2012 server, copy powershell update to target and Install
$os = Get-WinOSname -computer $server
if($OS -like "*2012 R2*") {
    logAndWrite $logPath "[WARNING] Installing PowerShell Update" 

    $b = ConnectPSsession $server $cred
    $error.Clear()
    Copy-Item -ToSession $b "\\techhaus\software\PSTools\PsExec.exe" -Destination "C:\Windows\System32\PSexec.exe"
    Copy-Item -ToSession $b '\\techhaus\software\PowerShell\PowerShell v5.1\Win8.1AndW2K12R2-KB3191564-x64.msu' -Destination 'C:\Program Files\WindowsPowershell\Win8.1AndW2K12R2-KB3191564-x64.msu'
    while ($error.exception.message) { 
        Start-Sleep -seconds 2
        $error.clear()
        Copy-Item -ToSession $b '\\techhaus\software\PowerShell\PowerShell v5.1\Win8.1AndW2K12R2-KB3191564-x64.msu' -Destination 'C:\Program Files\WindowsPowershell\Win8.1AndW2K12R2-KB3191564-x64.msu'
    }
    $username = (get-content $namefile)
    $auth = (Get-Content $file | ConvertTo-SecureString)

    $error.Clear()
    PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$Server wusa.exe /quiet 'C:\Program Files\WindowsPowershell\Win8.1AndW2K12R2-KB3191564-x64.msu' /forcerestart
    While ($error.exception.message) {
        $error.clear()
        PsExec.exe -u administrator -p $AdminLocal -accepteula -s \\$Server wusa.exe 'C:\Program Files\WindowsPowershell\Win8.1AndW2K12R2-KB3191564-x64.msu' /quiet /forcerestart
    }        

    Remove-PSSession $b

    ## Wait for reboot
    WaitForReboot(300)
} elseif ($os -like "*2012*") {
    logAndWrite $logPath "[WARNING] Installing PowerShell Update" 

    $b = ConnectPSsession $server $cred
    $error.Clear()
    Copy-Item -ToSession $b '\\techhaus\software\PSTools\PsExec.exe' -Destination 'C:\Windows\System32\PSexec.exe'
    Copy-Item -ToSession $b '\\techhaus\software\PowerShell\PowerShell v5.1\W2K12-KB3191565-x64.msu' -Destination 'C:\Program Files\WindowsPowershell\'
    while ($error.exception.message) { 
        Start-Sleep -seconds 2
        $error.clear()
        Copy-Item -ToSession $b '\\techhaus\software\PowerShell\PowerShell v5.1\W2K12-KB3191565-x64.msu' -Destination 'C:\Program Files\WindowsPowershell\'
    }
    PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$Server wusa.exe 'C:\Program Files\WindowsPowershell\W2K12-KB3191565-x64.msu' /quiet /forcerestart

    Remove-PSSession $b

    ## Wait for reboot
    WaitForReboot(300)
} elseif ($os -like "*2019*") {
    $b = ConnectPSsession $server $cred
    $error.Clear()
    Copy-Item -ToSession $b '\\techhaus\software\powershell\scripts\Server Patches\windows10.0-kb4476976-x64_a9c241844c041cb8dbcf28b5635eecb1a57e028a.msu' -Destination 'C:\Program Files\WindowsPowershell\windows10.0-kb4476976-x64_a9c241844c041cb8dbcf28b5635eecb1a57e028a.msu'
}


## Remove Windows Defender Anti-Virus
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock {
    Remove-WindowsFeature Windows-Defender  #, Windows-Defender-GUI
}


### Update VMware Tools
#logAndWrite $logPath "[WARNING] Update VMware Tools if needed..." 
#Get-VM -Name $server | Where-Object { $_.ExtensionData.Guest.ToolsVersionStatus -eq 'guestToolsNeedUpgrade' -and $_.PowerState -like 'PoweredOn' } | Get-VMGuest | Where-Object { $_.GuestFamily -like 'WindowsGuest'} | Update-Tools -NoReboot
#if (!$?) {
#    Start-Sleep -Seconds 10
#    Write-Host "VMware tools check failed.  Trying again..."
#    Get-VM -Name $server | Where-Object { $_.ExtensionData.Guest.ToolsVersionStatus -eq 'guestToolsNeedUpgrade' -and $_.PowerState -like 'PoweredOn' } | Get-VMGuest | Where-Object { $_.GuestFamily -like 'WindowsGuest'} | Update-Tools -NoReboot
#}
#Write-Host ""
#Start-Sleep -seconds 10


$error.Clear()
If ($Reservations -like "Yes") {
    ## Setting CPU Reservations for $server
    logAndWrite $logPath "[WARNING] Setting CPU Reservations for $server"
    $vmhostinfo = get-vmhost -VM $server
    $vmhostMhz = $vmhostinfo.CpuTotalMhz
    $vmhostCPUcount = $vmhostinfo.NumCpu
    $newVM = get-vm -Name $server
    [int]$vmCPU = $newvm.NumCpu
    Write-Host "vm CPU count: $vmCPU"

    [int]$CPU_Mhz = $vmhostMhz/$vmhostCPUcount
    [int]$vmCPUreservation = $vmCPU * $CPU_Mhz

    Write-Host "vmCPUreservation: $vmCPUreservation"
    #Start-Sleep -Seconds 10


    get-vm -Name $server | Get-VMResourceConfiguration | Set-VMResourceConfiguration -CpuReservationMhz $vmCPUreservation
    Start-Sleep -Seconds 1
    Write-Host (Get-VM -Name $server | Get-VMResourceConfiguration | Select-Object VM, CpuReservationMhz, MemReservationGB)
    if ($error.exception.message) {
        Write-Error $error.exception.message -ErrorAction Stop
    }
}


Write-Host " "


## Import Firewall Rules
logAndWrite $logPath "[WARNING] Importing Firewall Rules Now..."
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock $ImportRules -ArgumentList $server, $cred
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock {netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4, dir=in action=allow}
Write-Host ""


## Disable Cortana rules
Write-host "Disabling all built-in Cortana firewall rules..."
Invoke-Command -Credential $cred -ComputerName $server -scriptblock { Get-NetFirewallRule | Where-Object {$_.DisplayGroup -like '*Cortana*'} | Disable-NetFirewallRule | Out-Null } 
Invoke-Command -Credential $cred -ComputerName $server -scriptblock { Get-NetFirewallRule | Where-Object {$_.DisplayGroup -like '*Microsoft*Windows*Cortana*'} | Disable-NetFirewallRule }
if (! $? ){
    write-host ""
    write-host "Cortana Firewall rules are still enabled!" -ForegroundColor Red -BackgroundColor Black
    Write-Host ""
}


## Delete Duplicate Firewall Rules
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock {
    $output = (netsh advfirewall firewall show rule name=all verbose | Out-String).Trim() -split '\r?\n\s*\r?\n'
    $propertyNames = [System.Collections.Generic.List[string]]::new()
    
    $objects = @( $(foreach($section in $output ) {
        $obj = @{}
    
        foreach( $line in ($section -split '\r?\n') ) {
            if( $line -match '^\-+$' ) { continue }
            $name, $value = $line -split ':\s*', 2
            $name = $name -replace " ", ""
            
            $obj.$name  = $value
            if($propertyNames -notcontains $name) {
                $propertyNames.Add( $name )
            }
        }
        $obj
    }) | ForEach-Object {
        foreach( $prop in $propertyNames ) {
            if( $_.Keys -notcontains $prop ) {
                $_.$prop = $null
            }
        }
        [PSCustomObject]$_
    })
    
    $rules = $objects | Group-Object -Property RuleName, Program, Action, Profiles, RemoteIP, RemotePort, LocalIP, LocalPort, Enabled, Protocol, Direction
    # If you want to take a look
    # $rules | ?{$_.Count -gt 1} | Select-Object -ExpandProperty group | Out-GridView
    
    $rules | Where-Object {$_.Count -gt 1} | ForEach-Object {
        $name = $_ | Select-Object -ExpandProperty group | Select-Object -ExpandProperty RuleName -First 1
        # Here we have to use this cmdlet, since 'netsh advfirewall firewall delete' can't differentiate rules with the same name and will delete _all_ copies
        Get-NetFirewallRule -DisplayName $name | Select-Object -Skip 1 | Remove-NetFirewallRule
    }
}


## copy PSexec.exe to new server
Write-Host "Copying PSexec to server..."
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock { 
    if((get-childitem 'C:\Windows\System32\PSexec.exe') -ne $true) { 
        $notexist = $False 
    }
    Return $notexist
} -outvariable notexist
if ($notexist -eq $false) {
    Copy-Item -ToSession $b '\\techhaus\software\PSTools\PsExec.exe' -Destination 'C:\Windows\System32\PSexec.exe' -Force
}
Remove-PSSession $b

Start-Sleep -Seconds 20

$getService = {param($server, $cred) 
    $b = ConnectPSsession $server $cred
    invoke-command -session $b -scriptblock { 
        (Get-Service -Name "Winmgmt").WaitForStatus("running")
    }
    Remove-PSSession $b
}

$servicejob = Start-job -scriptblock $getService -ArgumentList $server, $cred
$starttime = Get-Date
$TimeOut = 120
do {
    $services = $false
    if ($servicejob.State -eq "Completed") { $services = $true } 
    $servicejob | Receive-Job
    $servicejob.State
    Start-Sleep -Seconds 30
} while ((((Get-Date) - $starttime) -le $TimeOut) -and ($services -eq $false))


## Check for POSHWSUS PowerShell Module
Import-Module -Name PoshWSUS
if (!$?){
    New-PSDrive -Name modpath -PSProvider FileSystem -Root "\\techhaus\software\PowerShell\Scripts\Modules" -Credential $cred
    Copy-Item modpath:\PoshWSUS -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse -Force
    Install-Module -Name PoshWSUS -AllowClobber -Force
    Import-Module -Name PoshWSUS
    Remove-PSDrive -name modpath
} elseif (Get-Module -ListAvailable | Where-Object { $_.name -like "PoshWSUS" }) {
    write-host "WSUS PowerShell Module installed - Continuing" -ForegroundColor Green -BackgroundColor Black
} else {
    Write-Host "WSUS PowerShell Module NOT installed" -ForegroundColor Red -BackgroundColor Black
}

$error.Clear()

$PSWSUSserver = Connect-PSWSUSServer -Verbose -WsusServer $WSUSserver -port 8530 


## If Server is in any WSUS groups, remove it
$Client = Get-PSWSUSClient -Computername $server
$client | ForEach {
    $Data = $_.GetComputerTargetGroups()
    $data | Add-Member -MemberType NoteProperty -Name FullDomainName -Value $_.fulldomainname -PassThru 
}
Foreach ($serv in $Data){
    if ($serv.Name -like "All Computers" -or $serv.name -like "Unassigned*"){
        Write-Host "$server is in:  " $serv.Name
    }else{
        Remove-PSWSUSClientFromGroup -Group $serv.name -Computer $server
    }
}

$WinUpdate = "TRUE"
Start-Sleep -Seconds 30
## Check for Windows Updates
if ($winupdate -notlike "FALSE") {
    logAndWrite $logPath "[WARNING] Rebooting prior to checking for Windows Updates..." 
    Start-Sleep -Seconds 30
    Write-Host "Waiting for Windows ..." -ForegroundColor Green -BackgroundColor Black
    Restart-Computer -credential $cred -ComputerName $server -Protocol WSMAN -Force -Wait -For WinRM -Timeout 240

    $list = $null
    $error.clear()
    $b = ConnectPSsession $server $cred
    Write-Host "Waiting for Windows to start." -ForegroundColor Green -BackgroundColor Black
    Start-Sleep -Seconds 120

    DoWindowsUpdates $server $cred

    Remove-PSSession $b
}

Start-Sleep -Seconds 3


## Register Server in WSUS
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock { 
    param($RebootPolicy)
    $Tgg = $RebootPolicy
    $Wup = "http://10.180.23.49:8530"
    $Wur = "http://10.180.23.49:8530"
    
    #Stop before the magic can happen
    stop-service wuauserv -Force
    stop-service bits -Force
    stop-service usosvc -Force
    stop-service cryptsvc -Force
    
    #Force set WU client settings
    New-Item –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
    New-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name TargetGroup -Value $Tgg -PropertyType "String" -Force -ErrorAction SilentlyContinue
    New-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name WUServer -Value $Wup -PropertyType "String" -Force -ErrorAction SilentlyContinue
    New-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name WUStatusServer -Value $Wup -PropertyType "String" -Force -ErrorAction SilentlyContinue
    New-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name UpdateServiceUrlAlternate -Value $Wur -PropertyType "String" -Force -ErrorAction SilentlyContinue
     
    New-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name TargetGroupEnabled -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
    New-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name DoNotConnectToWindowsUpdateInternetLocations -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
     
    New-Item –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
    New-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" –Name UseWUServer -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
    New-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" –Name NoAutoUpdate -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
     
    #Start all necessary services
    start-service wuauserv 
    start-service bits
    start-service usosvc
    start-service cryptsvc
 
    wuauclt /reportnow
    wuauclt /detetctnow
} -argumentlist $RebootPolicy


Force-WSUSCheckin $server
$WSUSclient = Get-PSWSUSClient $server | Select-Object * -ErrorAction Continue

if ($null -ne $WSUSclient){
    $os = Get-WinOSname -computer $server
    if($OS -like "*2016*"){
        $OSPolicy = "PROD-Win2016-NR"
    }
    if($OS -like "*2019*"){
        $OSPolicy = "PROD-Win2019-NR"
    }
    if($OS -like "*2022*"){
        $OSPolicy = "PROD-Win2022-NR"
    }
    
    Add-PSWSUSClientToGroup -Group $RebootPolicy -Computername $server -ErrorAction Continue
    if(!$?){
        Write-Host "Re-Trying. . . "
        Add-PSWSUSClientToGroup -Group $RebootPolicy -Computername $server -ErrorAction Continue
    }
    Add-PSWSUSClientToGroup -Group $OSPolicy -Computername $server -ErrorAction Continue
        if(!$?){
        Write-Host "Re-Trying. . . "
        Add-PSWSUSClientToGroup -Group $OSPolicy -Computername $server -ErrorAction Continue
    }

} else {
    Write-Host "$server is not in WSUS!" -ForegroundColor Red -BackgroundColor Black
}


## Set windows updates to Manual
logAndWrite $logPath "[WARNING] Set Windows Update to Manual" 
$error.Clear()
$loopcount = 0
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock $SetWUmanual
While ($error.exception.message){
    $error.Clear()
    $loopcount = $loopcount + 1
    if ($loopcount -gt 5){break}
    Write-Host "Retrying..."
    Start-Sleep -Seconds 30
    Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock $SetWUmanual
}
Write-Host ""


## Disable NIC Power Managment
logAndWrite $logPath "[WARNING] Disabling NIC power management for Server 2016 and newer"
$os = Get-WinOSname -computer $server
if($OS -notlike "*2012*") {
    Start-Sleep -Seconds 5
    Write-Host "Getting Adapter Name..."
    Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock $getnetwork -OutVariable EthernetName
    #Write-Host $EthernetName
    Write-Host "Setting Adapter Properties"
    $error.clear()
    $b = ConnectPSsession $server $cred
    #try {
        while ($null -eq $EthernetName){
            Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock $getnetwork -OutVariable Ethernettochange
            $EthernetName = ($Ethernettochange[0]).tostring()
            Write-Host "Network Adapter Name:  $EthernetName"

        }
        $b = ConnectPSsession $server $cred
        #Invoke-Command -Session $b -ScriptBlock {param ($EthernetName) Set-NetAdapterPowerManagement -name $EthernetName -AllowComputerToTurnOffDevice Disabled} -ArgumentList $EthernetName -ErrorAction SilentlyContinue
        Invoke-Command -Session $b -scriptblock {
            $adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement
            foreach ($adapter in $adapters){
                $adapter.AllowComputerToTurnOffDevice = 'Disabled'
                $adapter | Set-NetAdapterPowerManagement
            }
        }

    Start-Sleep -Seconds 60
    Remove-PSSession $b
    # Write-Host ""
}


## Set Windows VFX to Best Performance
logAndWrite $logPath "[WARNING] Setting Windows Visual Effects to Best Performance..."
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock $SetVFX
Remove-PSSession $b
Write-Host " "
Start-sleep -seconds 10


## Set Windows Driver Downloads to Disabled
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock $SetDownloadDrivers
Remove-PSSession $b
Write-Host " "
Start-sleep -seconds 10


## Set Windows Power Plan to High Performance
logAndWrite $logPath "[WARNING] Setting Windows Power Plan to High Performance..."
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock $SetPower
Remove-PSSession $b
Write-Host " "
Start-sleep -seconds 10


## Disable Print Spooler
logAndWrite $logPath "[WARNING] Disabling Windows Print Spooler Service..."
Invoke-command -Credential $cred -Computername $server -scriptblock { 
    Stop-Service -Name Spooler -Force
    Set-Service -Name Spooler -StartupType Disabled
}
Write-Host " "
Start-sleep -seconds 10


## pin powershell ISE to taskbar
logAndWrite $logPath "[WARNING] Pin PowerShell ISE to taskbar"
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock $PinPS -ArgumentList $os
Write-Host ""


## Allow install of nuGet and other powershell modules
logAndWrite $logPath "[WARNING] Disable TLS1.0, TLS1.1, SSL3, Etc. Enable TLS1.2, Install nuGet, and allow PSGallery on $server"
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock $SetSecurity
Write-Host ""


## Enable Pagefile settings
#if ($os -like "*2019*"){
    PsExec.exe -u valleymed\$username -p $auth -h -s -accepteula \\$Server wusa.exe /quiet 'C:\Program Files\WindowsPowershell\windows10.0-kb4476976-x64_a9c241844c041cb8dbcf28b5635eecb1a57e028a.msu' /forcerestart
#}

logandwrite $logpath "[WARNING] Set Page File location and Size..."
# Set-CimInstance -ComputerName $server -Query "Select * from Win32_ComputerSystem" -Property @{AutomaticManagedPagefile="False"}

## Adjust Pagefile settings on C:
# Set-CimInstance -ComputerName $server -Query "Select * from Win32_PageFileSetting" -Property @{InitialSize=0;MaximumSize=0}
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock { 
    $drivestate = (get-disk -number 1).IsReadOnly
    if ($drivestate -ne $false){
        Set-Disk -Number 1 -IsOffline $false
        Set-Disk -Number 1 -IsReadOnly $false
    }
    $pagefile = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
	## Disable Pagefile on C:
    $pagefile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name like '%pagefile.sys'";
    $pagefile.AutomaticManagedPagefile = $false | Out-Null
    if ( !$? ) {
        Set-CimInstance -ComputerName $server -Query "Select * from Win32_PageFileSetting" -Property @{InitialSize=800;MaximumSize=800}
    }
    ## $pagefile.InitialSize = 600;
    ## $pagefile.MaximumSize = 600;
    $pagefile[0].Delete();
    Write-Host ""
    $pagefileset = Gwmi -Class win32_pagefilesetting | Where-Object {$_.caption -like 'C*'}
    if ($pagefileset){
        $pagefileset.Delete()
    }
	## Enable system managed Pagefile on P:
	#if ($UsePdrive -like $true){
		$PageFile = Get-CimInstance -ClassName Win32_PageFileSetting -Filter "Name like '%pagefile.sys'"
		$PageFile | Remove-CimInstance
		
		$PageFile = New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name= "P:\pagefile.sys" }
		$PageFile | Set-CimInstance -Property @{ InitialSize = 0; MaximumSize = 0 }

		$PageFile = New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name= "C:\pagefile.sys" }
		$PageFile | Set-CimInstance -Property @{ InitialSize = 800; MaximumSize = 800 }

	#} else {
	#	$PageFile = Get-CimInstance -ClassName Win32_PageFileSetting -Filter "Name like '%pagefile.sys'"
	#	$PageFile | Remove-CimInstance
	#	
	#	$PageFile = New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name= "C:\pagefile.sys" }
	#	$PageFile | Set-CimInstance -Property @{ InitialSize = 800; MaximumSize = 800 }
	#	
	#	$PageFile = New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name= "D:\pagefile.sys" }
	#	$PageFile | Set-CimInstance -Property @{ InitialSize = 0; MaximumSize = 0 }
	#}
}

#Invoke-Command -Session $b -scriptblock {
#    $drivestate = (get-disk -number 1).IsReadOnly
#    if ($drivestate -ne $false){
#        Set-Disk -Number 1 -IsOffline $false
#        Set-Disk -Number 1 -IsReadOnly $false
#    }
#}

Remove-PSSession $b




## Enable Remote Desktop
logAndWrite $logPath "[WARNING] Enable Remote Desktop connections to $server"
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock `
    {Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0 }
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock `
    {Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 }
Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock `
    {Enable-NetFirewallRule -DisplayGroup "Remote Desktop" }
Write-Host ""


## set local administrator password
#logandwrite $logPath "[INFO] Set the Local Administrator password"
#Invoke-Command -credential $cred -ComputerName $server -ScriptBlock `
#    {param($user_local_password) net user administrator $user_local_password} -ArgumentList $user_local_password


## Force Group Policy Update
logAndWrite $logPath "[WARNING] Updating Group Policy..." 
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock {
    param($server, $adminlocal, $cred)
    #Set-ItemProperty -Path HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name UseWUServer -Value 0
    #Restart-Service -Name wuauserv -Force
    #Get-WindowsCapability -Name 'Rsat.GroupPolicy.*' -Online | Where-Object { $_.State -ne 'Installed' } | Add-WindowsCapability -Online
    #Set-ItemProperty -Path HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name UseWUServer -Value 1
    #Start-Sleep -seconds 10
    #Restart-Service -Name wuauserv -Force
    #Invoke-GPUpdate -Computer $server -RandomDelayInMinutes 0 -credential $cred -Force -Boot
    #$ErrorActionPreference = 'SilentlyContinue'
    psexec -u administrator -p $adminlocal -accepteula \\$server -s -i gpupdate /force
} -ArgumentList $server, $adminlocal, $cred 
Write-Host ""


## Add SolarWinds Account to local Administrator Group
$existSWuser = (Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock { (Get-LocalGroupMember 'Administrators').name -contains 'VALLEYMED\samsvc'})
if ($existSWuser -eq $false) {
    $os = Get-WinOSname -computer $server
    if ($os -notlike "*2012*"){
        Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock {
            Add-LocalGroupMember -Group Administrators -Member "VALLEYMED\samsvc"
        }
    }else{
        logAndWrite $logPath "[WARNING] Adding SolarWinds Service Account"
        $DomainName = 'valleymed'
        $ComputerName = $server
        $UserName = 'samsvc'
        $AdminGroup = [ADSI]"WinNT://$ComputerName/Administrators,group"
        $User = [ADSI]"WinNT://$DomainName/$UserName,user"
        $AdminGroup.Add($User.Path)
    }
} else {
    logAndWrite $logPath "[WARNING] SolarWinds Service Account already exists"
}


## Add Service Administrator account Group
$SAG_User = $server + "_Admins"
$existSAGuser = (Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock { (Get-LocalGroupMember 'Administrators').name -contains "VALLEYMED\$SAG_User"})
if ($existSAGuser -eq $false) {
    Invoke-Command -Credential $cred -ComputerName $server -ScriptBlock {
        Param ($SAG_User) 
        Add-LocalGroupMember -Group 'Administrators' -Member "valleymed\$SAG_User" -Verbose
    } -ArgumentList $SAG_User
}


## Install CrowdStrike
$b = ConnectPSsession $server $cred
Write-Host "Checking that CSFalconService is installed..."
Invoke-Command -Session $b -ScriptBlock { 
    param ($server, $CSpath, $Cred)
    $loops = 1
    $CSFalcon = Get-Process -ComputerName $server -Name "CSFalconService*" -ErrorAction SilentlyContinue
    While (!($CSFalcon) -and $loops -lt 5) {
    	$loops = $loops + 1
    	
        Write-Host "Waiting for CrowdStrike installation to complete..." -ForegroundColor Yellow -BackgroundColor Black
        if($null -eq $cspath){
            $CSpath = (Get-ChildItem -Path '\\techhaus\software\CrowdStrike\Servers_N-1' -Include WindowsSensor.exe -Recurse -Force -ErrorAction Silentlycontinue).DirectoryName
        }
        New-PSDrive -Name CSFalcon -Credential $cred -PSProvider FileSystem -Root $CSpath 
        Copy-Item CSFalcon:\WindowsSensor.exe -Destination 'C:\Windows\' -Recurse -Force
        Remove-PSDrive CSFalcon

        Write-Host "Starting Installation now..."
        PsExec.exe \\$Server -accepteula -nobanner -s "C:\Windows\WindowsSensor.exe" /install /quiet /norestart "CID=8A8EEFB4430748BDB81C4ED0EE458A1E-29"
        
        Write-host "Waiting for Install to Complete..."
        Start-sleep -seconds 180
        Write-host "Verifying CrowdStrike Service is running..."
        $CSFalcon = Get-Process -ComputerName $server -Name "CSFalconService*" -ErrorAction SilentlyContinue
    }
} -ArgumentList $server, $CSpath, $Cred


#Write-Host "Installing CrowdStrike..." -ForegroundColor Yellow -BackgroundColor Black
#PsExec.exe -accepteula -s \\$Server $CSpath /install /quiet /norestart CID=8A8EEFB4430748BDB81C4ED0EE458A1E-29


## Clean Up the temporary VMware Customization Settings
logAndWrite $logPath "[WARNING] Deleting the OSCustomizationSpec File" 
Remove-OSCustomizationSpec -OSCustomizationSpec $custom -Confirm:$false


## Add Server to SolarWinds
logAndWrite $logPath "[WARNING] Add Server $server to SolarWinds" 
$nodeexist = $null

## Set Solarwinds Server name
$swissvr = "SWSAMSVR1.valleymed.net"
$swis = Connect-Swis -Hostname $swissvr -Credential $SWcreds

## Get node id number 
#
[int]$nodeid = Get-Swisdata $swis "Select nodeid from orion.nodes where nodename like '%$server'"

$nodeuri = Get-SwisData $swis "SELECT Uri FROM Orion.Nodes WHERE NodeName LIKE '%$server'"

## IF Server is already in Solarwinds, delete it.
if ($nodeuri) {
    foreach ($node in $nodeuri) {
        Write-Host "node exists, uri: $node"
        Remove-SwisObject $swis $node
        Write-Host "node $server has been removed" -ForegroundColor Green -BackgroundColor Black
    }
    start-sleep -Seconds 120
}

$nodeexist = Get-SwisData $swis "SELECT NodeID, Caption, NodeName FROM Orion.Nodes WHERE NodeName LIKE '%$server'"
#$nodeexist = Get-SwisData $swis "SELECT NodeID, Caption, NodeName FROM Orion.Nodes WHERE NodeName LIKE '%$server'"

While (!($nodeexist)) {
    logAndWrite $logPath "[WARNING] Adding VM to SolarWinds..." 
    Start-Sleep -Seconds 10

    # Credentials on SolarWinds to use WMI 
    $credentialName = "ServerMonitoring" # Enter the name under which the WMI credentials are stored. You can find it in the "Manage Windows Credentials" section of the Orion website (Settings)

    # Node properties
    $newNodeProps = @{
        IPAddress = $ip
        Caption = $server
        EngineID = 2
        ObjectSubType = "WMI"
        DNS = $server
        SysName = $server
    }

    #Creating the node
    $newNodeUri = New-SwisObject $swis -EntityType "Orion.Nodes" -Properties $newNodeProps
    $nodeProps = Get-SwisObject $swis -Uri $newNodeUri

    #Getting the Credential ID
    $credentialId = Get-SwisData $swis "SELECT ID FROM Orion.Credential where Name = '$credentialName'"
    if (!($credentialId)) {
        Throw "Can't find the Credential with the provided Credential name '$credentialName'."
    }

    #Adding NodeSettings
    $nodeSettings = @{
        NodeID = $nodeProps["NodeID"]
        SettingName = "WMICredential"
        SettingValue = ($credentialId.ToString())
    }

    #Creating node settings
    New-SwisObject $swis -EntityType "Orion.NodeSettings" -Properties $nodeSettings

    # register specific pollers for the node
    $poller = @{
        NetObject = "N:" + $nodeProps["NodeID"]
        NetObjectType = "N"
        NetObjectID = $nodeProps["NodeID"]
    }

    # Add Pollers for Status (Up/Down), Response Time, Details, Uptime, 
    # CPU, & Memory Status
    $poller["PollerType"]="N.Status.ICMP.Native";
    New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

    # Response time
    $poller["PollerType"]="N.ResponseTime.ICMP.Native";
    New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

    # Details
    $poller["PollerType"]="N.Details.WMI.Vista";
    New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

    # Uptime
    $poller["PollerType"]="N.Uptime.WMI.XP";
    New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

    # CPU
    $poller["PollerType"]="N.Cpu.WMI.Windows";
    New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

    # Memory
    $poller["PollerType"]="N.Memory.WMI.Windows";
    New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller 
    #endregion Add Pollers for Status (Up/Down), Response Time, Details, Uptime, CPU, & Memory

    # Volumes / Disks
    $drives = Get-WmiObject -Credential ($cred) -ComputerName $server -Class win32_Volume -Filter "DriveType=3 AND DriveLetter IS NOT NULL" ##DriveType=3

    logAndWrite $logPath "[WARNING] Adding Custom Properties to SolarWinds for $Server" 
    Start-Sleep -Seconds 30

    $lastnode = $nodeprops #Get-SwisData $swis 'SELECT NodeID, Caption FROM Orion.Nodes' | Select-Object -Last 1

    $nodeId = $lastnode.NodeID # NodeID of a node whose custom properties you want to change

    $discoverID = Invoke-SwisVerb $swis Orion.NPM.Interfaces DiscoverInterfacesOnNode $nodeid

    $ifaceId = $discoverID.ID

    foreach ($drive in $drives){
        $DriveCaption = "$($drive.Caption) Label:$($drive.Label)  $([Convert]::ToString($drive.SerialNumber, 16))";
        $DriveDescription = "$($drive.Caption) Label:$($drive.Label)  Serial Number $([Convert]::ToString($drive.SerialNumber, 16))";
        $AddDrive = @{  
                    NodeID=$nodeid;  
                    VolumeType="Fixed Disk";  
                    VolumeTypeID="4";  
                    Icon="FixedDisk.gif";  
                    VolumeIndex="1";  
                    Caption=$DriveCaption;  
                    VolumeDescription=$DRiveDescription;                    
                    PollInterval="120";  
                    StatCollection="15";  
                    RediscoveryInterval="30";
        }

        #Inserting drives to be monitored into the database          
        $driveURI = New-swisobject $swis -EntityType "Orion.volumes" -properties $AddDrive
        $volume = Get-SwisObject $swis -uri $driveURI
        Start-Sleep -Seconds 10

        if ($volume){  
            $volumeId = $volume["VolumeID"]    
            write-host $volume['volumeID']  
        
            #Write-Verbose $volumeId  
            $poller = $null;  
            $poller = @{};  
        
            #setting params for the database fields  
            $poller["PollerType"]="V.Details.WMI.Windows";  
            $poller["NetObject"]=  "V:"+$volumeID;
            $poller["NetobjectType"] = "V";  
            $poller["NetObjectID"] = $volumeID;  
        
            #Adding to the database  
            New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller  
            $poller["PollerType"]="V.Statistics.WMI.Windows";
            New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller  
            $poller["PollerType"]="V.Status.WMI.Windows";
            New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller  
        
        }
    }

    # prepare custom property values
    $customProps = @{
        Application_Analyst = $analyst;
        Applications        = $applications;
        City                = $City;
        Customer            = $customer;
        DATACENTERLOCATION  = $DataCenter;
        PRIMARYADMIN        = $PrimaryAdmin;
        PRODUCTION_STATE    = $ProductionState;
        RANKING             = $Rank;
        SECONDARYADMIN      = $SecondaryAdmin;
        SERVER_FUNCTION     = $ServerFunction;
        SERVERHARDWARETYPE  = $ServerHardwareType;
    }

    logAndWrite $logPath "[WARNING] $nodeId"
    logAndWrite $logPath "[WARNING] $customProps"
    Start-Sleep -Seconds 10
    
    # build the node URI
    $uri = "swis://$swissvr/Orion/Orion.Nodes/NodeID=$($nodeId)/CustomProperties";

    # set the custom property
    Set-SwisObject $swis -Uri $uri -Properties $customProps
    Start-Sleep -Seconds 15
    
    # build the interface URI
    $uri = "swis://$swissvr/Orion/Orion.Nodes/NodeID=$($nodeId)/Interfaces/InterfaceID=$($ifaceId)/CustomProperties";

    # set the custom property
    Set-SwisObject $swis -Uri $uri -Properties $customProps

    Start-sleep -Seconds 60

    ## List all Nodes in SolarWinds - Oldest to Newest
    #Get-SwisData $swis 'SELECT NodeID, Caption FROM Orion.Nodes'

    $nodeexist = Get-SwisData $swis "SELECT NodeID, Caption, NodeName FROM Orion.Nodes WHERE NodeName LIKE '%$server'"
}

## Get node id number 
#
if($nodeid -eq $null){$nodeid = 0}
while ($nodeid -eq 0 -and $looper -le 5){
    [int]$nodeid = Get-Swisdata $swis "Select nodeid from orion.nodes where nodename like '%$server'"
    Start-Sleep -Seconds 30
    $looper = $looper + 1
}

## Add Server Resources to SolarWinds monitoring
logandwrite $logPath "[INFO] Adding Server Resources to SolarWinds Monitoring"
SWISaddResources -nodeId $nodeid -swis $swis -timeBetweenChecks 30

## Add Physical Memory Monitor 
Add-SwisObject -Uri $swis -SwisCredential $swcred -Path "NPM.Interfaces.Interfaces" -Properties @{NodeID=$nodeid;Caption="Physical Memory";Name="physicalmemory";IfIndex=<ifIndex>}

## Add Network Interface to Solarwinds Monitoring
$ipaddress = (Resolve-DnsName $server).IPAddress
write-host $ipaddress

# Get the node you want to add the network adapter to
$node = Get-SwisData $swis "SELECT NodeID FROM Orion.Nodes WHERE Caption like '%$server'"

# Get Node ID 
$NodeID = Get-SwisData $swis "SELECT NodeID FROM Orion.Nodes WHERE IPAddress=@ipadd" @{ipadd=$ipaddress}
write-host "NodeID: "$NodeID

$GetNodeUri = Get-swisdata $swis "SELECT uri FROM Orion.Nodes WHERE IPAddress=@ipadd" @{ipadd=$ipaddress}

$nodeProps = Get-SwisObject $swis -Uri $GetNodeUri
write-host $nodeProps

$NodeID = $nodeProps["NodeID"]
write-host $NodeID

# To add an interface, please fill in the correct values you need
# These seem to be the minimum values needed to get the interface to add correctly
$newIfaceProps = @{
    NodeID = $NodeID;
    InterfaceIndex=3;
    InterfaceName='vmxnet3 Ethernet Adapter';
    IfName="ethernet_32772";
    # Interface Index may need to be passed in from vco or altered to match build details
    Caption="vmxnet3 Ethernet Adapter · Ethernet0";
    ObjectSubType="WMI";
    #Status=0;
    RediscoveryInterval=5;
    PollInterval=10;
    StatCollection=1;
    NextRediscovery=[DateTime]::UtcNow;
    InterfaceIcon="6.gif";
    Interfacetypename="ethernetCsmacd";
    nextpoll=[DateTime]::UtcNow;
    InterfacetypeDescription="Ethernet";
    Interfacesubtype=3;
    InterfaceType=6;
    InterfaceAlias="Ethernet0";
    Counter64="Y";

}


$newIfaceUri = New-SwisObject $swis –EntityType "Orion.NPM.Interfaces" –Properties $newIfaceProps
Write-Host "Debug: New interface uri : $newIfaceUri"

$ifaceProps = Get-SwisObject $swis -Uri $newIfaceUri
Write-Host "Debug: New interface properties $ifaceProps"

# register specific pollers for the node
# for WMI nodes you need to use WI instead of I

$poller = @{
    NetObject="IW:"+$ifaceProps["InterfaceID"];
    NetObjectType="IW";
    NetObjectID=$ifaceProps["InterfaceID"];
}
$IntID = $ifaceProps["InterfaceID"]
Write-host "Echo - Interface ID is $IntID"

# Below are the pollers needed for WMI - these were pulled from the poller table in the DB
# Status
$poller["PollerType"]="IW.Status.WMI.WinV62";
New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

# Interface Traffic
$poller["PollerType"]="IW.StatisticsTraffic.WMI.WinV62";
New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

# Interface Errors
$poller["PollerType"]="IW.StatisticsErrors.WMI.WinV62";
New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

# Rediscovery
$poller["PollerType"]="IW.Rediscovery.WMI.WinV62";
New-SwisObject $swis -EntityType "Orion.Pollers" -Properties $poller

Start-sleep	-seconds 10

# Trigger a PollNow on the node to cause other properties and stats to be filled in
Invoke-SwisVerb $swis Orion.Nodes PollNow @("N:" + $nodeProps["NodeID"])


##  Move Computer Object to final OU
    $orgunit = @()
    Write-Host "Moving AD Computer Object to target OU" -ForegroundColor Green -BackgroundColor Black
    $parts = $OU -split '\/' 
    foreach ($part in $parts){
        $orgunit += "OU=$part"
    }
    [array]::Reverse($orgunit)
    $orgunits = $orgunit -join ','
    Get-ADComputer $server | Move-ADObject -TargetPath $orgunits",DC=Valleymed,DC=net" -Verbose

## Last check for updates
if ($winupdate -notlike "FALSE") {
    Write-Host "Get list of available Updates..." -ForegroundColor Green -BackgroundColor Black
    $b = ConnectPSsession $server $cred
    Invoke-Command -session $b -ScriptBlock {
        param($server)
        Import-Module -name PSWindowsUpdate
        Write-Host " "
        Write-Host "Hide specific updates..."
        psexec.exe  -accepteula \\$server -s -i powershell.exe 'Get-WindowsUpdate -Hide -KBArticleID "KB2538243", "KB890830", "KB4589210", "KB4589208", "KB5034439" -Confirm:$false'
        Get-WUList -MicrosoftUpdate 
    } -ArgumentList $server -OutVariable WUverboseMSFT 
    
    if($WUverboseMSFT.kb.count -gt 0){
        $list = "Updates Needed..."
        $list
        Write-Host $WUverboseMSFT.kb
        DoWindowsUpdates $server $cred
        Invoke-Command -session $b -ScriptBlock {
            Import-Module -name PSWindowsUpdate
            Write-Host " "
            Write-Host "Hide specific updates..."
            psexec.exe  -accepteula \\$server -s -i powershell.exe 'Get-WindowsUpdate -Hide -KBArticleID "KB2538243", "KB890830", "KB4589210", "KB4589208", "KB5034439" -Confirm:$false'
        }    
    }
}

## Check LAPS for Admin Password
$loopcount = 0
do {
    Write-Host "Checking for LAPS installation"
    #do {
        Start-Sleep -Seconds 15
        install-module -name AdmPwd.PS -force -Confirm:$False
        Import-module -name AdmPwd.PS
        $LAPS = Get-AdmPwdPassword -ComputerName $server
    #} while ($LAPS -eq $null)

    if($loopcount -eq 1){
        $b = ConnectPSsession $server $cred
        Invoke-Command -session $b -ScriptBlock {
            Param($server)
            install-module -name AdmPwd.PS -force -confirm:$False
            Start-Sleep -Seconds 10
            Import-module -name AdmPwd.PS
            Start-Sleep -Seconds 10
            $LAPS = Get-AdmPwdPassword -ComputerName $server
            Get-WindowsCapability -Name 'Rsat.GroupPolicy.*' -Online | Where-Object { $_.State -ne 'Installed' } | Add-WindowsCapability -Online 
            Start-Sleep -Seconds 30
            Invoke-GPUpdate –Computer $server -Force –Verbose
            # update-help -force
            $LAPS
        } -Argumentlist $server -OutVariable LAPS
    }
    Start-Sleep -Seconds 30
    $loopcount = $loopcount + 1
} While ($null -eq ($LAPS).Password -and $loopcount -le 3)


## Check the version of duo installed by parsing the Registry Uninstall Keys
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock {
    $uninstallkey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
    
    Function Get-DuoVersion{
        Try{
            Get-ChildItem $uninstallkey -Recurse -ErrorAction Stop | ForEach-Object {
                $CurrentKey = (Get-ItemProperty -Path $_.PsPath)
                if ($CurrentKey -match "Duo Authentication for Windows Logon") {
                    $DV = write-output "$($CurrentKey.DisplayName) $($CurrentKey.DisplayVersion)"
                }
            }
        }catch{
            $DV = Write-Output "Cannot determine if Duo for Windows Logon (Microsoft RDP) is installed."
        }
        Return $DV
    } 

    $DUOStatus = Get-DuoVersion
    $DuoStatus
} -outvariable DUOStatus

if ($DUOStatus -like "Duo Authentication for Windows*") {
    Write-Host $DUOStatus -ForegroundColor Green -BackgroundColor Black
}else{
    Write-Host "Duo Authentication NOT INSTALLED" -BackgroundColor Black -ForegroundColor Red
}


## Create the Cohesity UserName "valleymed.net\DomainAdmin"
$domainuser = get-content $namefile 
$userparts = $domainuser -split "\\"
$domainname = $userparts[0] + ".net"
$cohesityUser = $domainname + '\' + $userparts[1]

# Connect-CohesityCluster -Server cohesityprod -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "valleymed.net\domainAdmin", (ConvertTo-SecureString -AsPlainText "Password1@" -Force))
# Connect-CohesityCluster -Server cohesityprod -Credential (new-object -TypeName System.Management.Automation.PSCredential -Argumentlist $cohesityUsername, (Get-Content $file | ConvertTo-SecureString))
Connect-CohesityCluster -Server cohesityprod.valleymed.net -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $cohesityUser, (Get-Content $file | ConvertTo-SecureString))

If($Viserver -notcontains ".valleymed.net"){
    $FQDNviServer = $viserver + ".valleymed.net"
}

## Add Server to Cohesity Job requested in spreadsheet
if ($cohesityjob -notlike "none" -or $cohesityjob -ne $null){
    $CohesitySource = Get-CohesityProtectionSource -Environments KVMware | Where-Object {$_.protectionSource.name -like $FQDNVIserver}
    Write-Host "Adding $server to Cohesity Protection Job $cohesityjob" -ForegroundColor Green -BackgroundColor Black

    Update-CohesityProtectionSource -ID $CohesitySource.protectionSource.id
    Start-Sleep -Seconds 45

    $jobID = (Get-CohesityProtectionJob -Names $cohesityJob).id
    if ($jobID){
        $protectionJob = Get-CohesityProtectionJob -Id $JobId
        if ($null -eq $protectionJob) {
            write-host "Protection Job was not found."
            break
        }
        
        $protectionSources = Get-CohesityVMwareVM -Names $Server
        if ($null -eq $protectionSources -or $protectionSources.Count -eq 0) {
            write-host "No matching virtual machines found."
            break
        }
        
        $protectionSourceIds = $protectionSources | ForEach-Object{ $_.Id }
        
        $protectionJob.SourceIds = $protectionJob.SourceIds + $protectionSourceIds    
        
        $protectionJob | Set-CohesityProtectionJob -Confirm:$False

        if( ! $? ){
            Write-Host "FAILED adding $server to Protection Job $cohesityjob" -ForegroundColor Red -BackgroundColor Black
        } else {
            Write-Host "Added $server to Protection Job $cohesityjob" -ForegroundColor Green -BackgroundColor Black
        }
    }
}


## Disable Offline File Sync service
$InvokeCimMethod = @{
                    ClassName    = 'Win32_OfflineFilesCache'
                    ComputerName = $cn
                    MethodName   = 'Enable'
                    Arguments    = @{Enable = $false}
                }
Invoke-CimMethod @InvokeCimMethod


## Remove WSUS Registry keys
$b = ConnectPSsession $server $cred
Invoke-Command -Session $b -ScriptBlock { 

    #Stop before the magic can happen
    stop-service wuauserv -Force
    stop-service bits -Force
    stop-service usosvc -Force
    stop-service cryptsvc -Force
    
    #Force set WU client settings
    Remove-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name TargetGroup
    Remove-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name WUServer
    Remove-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name WUStatusServer
    Remove-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name UpdateServiceUrlAlternate
     
    Remove-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name TargetGroupEnabled
    Remove-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" –Name DoNotConnectToWindowsUpdateInternetLocations
     
    Remove-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" –Name UseWUServer
    #Remove-ItemProperty –Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" –Name NoAutoUpdate 
     
    #Start all necessary services
    start-service wuauserv 
    start-service bits
    start-service usosvc
    start-service cryptsvc
}

$b = ConnectPSsession $server $cred
Invoke-Command -session $b -scriptblock {
    #If the reply is IPv6 address, run following registry setting to just prefer ipv4 and reboot
    New-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0xff -PropertyType “DWord”
    #If DisabledComponents exists, use the set cmdlet
    Set-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0xff
    #You need to reboot the computer in order for the changes to take effect
    #
    # 0    to re-enable all IPv6 components (Windows default setting).
    # 0xff to disable all IPv6 components except the IPv6 loopback interface. This value also configures Windows to prefer using IPv4 over IPv6 
    #      by changing entries in the prefix policy table. For more information, see Source and destination address selection.
    # 0x20 to prefer IPv4 over IPv6 by changing entries in the prefix policy table.
    # 0x10 to disable IPv6 on all nontunnel interfaces (both LAN and Point-to-Point Protocol [PPP] interfaces).
    # 0x01 to disable IPv6 on all tunnel interfaces. These include Intra-Site Automatic Tunnel Addressing Protocol (ISATAP), 6to4, and Teredo.
    # 0x11 to disable all IPv6 interfaces except for the IPv6 loopback interface.
    #
}

## last reboot
Write-Host "Rebooting new VM..."
Restart-Computer -credential $cred -ComputerName $server -Protocol WSMan -Force -Wait -For WinRM -Timeout 180
    
Remove-PSSession $b

logAndWrite $logPath "[SUCCESS] Build Complete" 

$Message = "$server - VM Build Complete"
$Title = 'Build Complete'
$TimeOut = 60
$ButtonSet = 'OK'
$IconType = 'Information'

Show-PopUp -Message $Message -Title $Title -TimeOut $TimeOut -ButtonSet $ButtonSet -IconType $IconType 

try{
$error.clear()
}
Finally {
    Stop-Transcript -ErrorAction SilentlyContinue
}
exit


# SIG # Begin signature block
# MIIPTAYJKoZIhvcNAQcCoIIPPTCCDzkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHAYY4mAjkn8WA6ay8z7Wfpr8
# Z+OgggyfMIIGHzCCBAegAwIBAgITMgAADLuC4Nd4KLuIAAAAAAAMuzANBgkqhkiG
# 9w0BAQsFADBfMRMwEQYKCZImiZPyLGQBGRYDbmV0MRkwFwYKCZImiZPyLGQBGRYJ
# VmFsbGV5bWVkMS0wKwYDVQQDEyRVVy1WYWxsZXkgTWVkaWNhbCBDZW50ZXIgSXNz
# dWluZyBDQTIwHhcNMjMwNDEwMjIwNzQzWhcNMjUwNDA5MjIwNzQzWjAZMRcwFQYD
# VQQDEw5MdWtlIFguIEZvd2xlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBALdwRCVHafuufNw/Wkz5yAm2wkb6LN1aA4XBWaSthf7Z4mPLJOtBSVZAzWcp
# vcK7jrE08KiQBs+EUSJaP+v9qI4gtNIOj3zZOJWElGOXwgVC0KAT+gfIyPg0+w/B
# vXg6x8PrMywlWnz1fwu3ontH6BRbsdRli8uOhHRU8RtXsT3nrizHczL7douc/Fbk
# S+/9UWRq05/otSP63QEQI+9E1f6QLHHG693aFkAOQy3lOB27hKWWvs11HhM94bQD
# 44heBL3AJSKgnJfIfOGf/P1Njs/M9EpXztNnbuAPZyNm9c11/TcGt8Ib9CH5fsNi
# P8UH7uZTeQ9eat/WiHhhTcoDseECAwEAAaOCAhgwggIUMD0GCSsGAQQBgjcVBwQw
# MC4GJisGAQQBgjcVCITqtxKD5KFdh/2dBoSBkFuEwf0bgV/24W2ExNV+AgFkAgEa
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMAsGA1UdDwQEAwIHgDAbBgkrBgEEAYI3FQoE
# DjAMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBTgW9UkKxgXTKfRZmc9C8JdpMhCMzAf
# BgNVHSMEGDAWgBT9SevFqi81iiBvmszRMU3z96o4dDBjBgNVHR8EXDBaMFigVqBU
# hlJodHRwOi8vY3JsLnZhbGxleW1lZC5uZXQvQ2VydERhdGEvVVctVmFsbGV5JTIw
# TWVkaWNhbCUyMENlbnRlciUyMElzc3VpbmclMjBDQTIuY3JsMG4GCCsGAQUFBwEB
# BGIwYDBeBggrBgEFBQcwAoZSaHR0cDovL2NybC52YWxsZXltZWQubmV0L0NlcnRE
# YXRhL1VXLVZhbGxleSUyME1lZGljYWwlMjBDZW50ZXIlMjBJc3N1aW5nJTIwQ0Ey
# LmNydDAvBgNVHREEKDAmoCQGCisGAQQBgjcUAgOgFgwUbHVrZWYyQFZhbGxleW1l
# ZC5uZXQwTgYJKwYBBAGCNxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIx
# LTgzOTUyMjExNS03NjQ3MzM3MDMtMTgwMTY3NDUzMS0zNjk2ODANBgkqhkiG9w0B
# AQsFAAOCAgEAbvizQTsqWNO3CbClTwXxDOAEiyI7H0IvTWiY0cMfqbqXj1LjRr2c
# KSm7xi5DqOa90tGtf0HD3cvcDhAVR6ny2aDLA/4Y3srcR2/QAKmceNORhMtwvcLl
# rH6mnADrXx5zhgM5bFSnTqspkObuOc8sSU+FPpIj44J7+r2wIPVxUd4DOPPjLuz3
# KCuoStdqf26Ws//HXzgoFjoKRskdpasjuk3mUprfUA16GjzZrKZKs1qnM/8H987j
# gbMa6lGAhY+CJkRdPXBdGlHWnXnGPy3BWCBQamu9+EHMhvHzeYietbfoke1Qa8gI
# NKjCBto+v7ueuLiGbByuXOBfw71MA3ec4eie2OlUJldohttqUVCsK15dxVMGaBup
# MQowYPI9dqvTAfVBc68ZpGg4iwZeetIkWtKeQv2I5YKC+hv0ZrrnPnHQvNTz3t6A
# RY4I7rRBSA7yQ39T2+jt0FszCC4kXOTuY/721Wx697KYOU8WOzATu8YBLRN7lX4/
# sYqzo2TfjOb2mnjNOzaYy4Sjrrq+tElk9heM8TsHslKsnc9Sukl0w0380YEce5sS
# ZmrrSnjHrHGcEDgc2iwzcjWcts46l75KAbAPckaM90vCQRnjTCbemPo7WHzbIPuy
# Whn5T+r5iAblO+tM/YL141V7scB2i4diGqNQn+7DR45cl1onCSjJH5gwggZ4MIIE
# YKADAgECAhM4AAAAA+k7VLXbr+VmAAAAAAADMA0GCSqGSIb3DQEBCwUAMCsxKTAn
# BgNVBAMTIFVXLVZhbGxleSBNZWRpY2FsIENlbnRlciBSb290IENBMB4XDTE4MTAw
# MjIwMjIwM1oXDTI4MTAwMjIwMzIwM1owXzETMBEGCgmSJomT8ixkARkWA25ldDEZ
# MBcGCgmSJomT8ixkARkWCVZhbGxleW1lZDEtMCsGA1UEAxMkVVctVmFsbGV5IE1l
# ZGljYWwgQ2VudGVyIElzc3VpbmcgQ0EyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAnfbq7t0NOqDTKX0P886y7TgHgWeCFEDFKydIBXKDVUd5sPAv0I4R
# q3ufiv8vewqvD7FixjoPGnz2OlP7pKVyMjC3gYqL0MlN/ywqAZFDO1I0HoTb2Dp3
# NUlyMMrLZU1ZKzExE6+QO/b8HaL9lQIookLUDan5g8DjEReTTla6gQYN8RI5RqIP
# l2Jus1YnzmjxnHv5DLr8n6bPW8K1g4I44O6QLA0/cTjUJqr3p9QQDJpuCPNPCuHc
# h3ofKeyw8aD09nkGmhO8rDJcT6gtVEsWQ5bfOyRHLrygjRaSSRYxudgUjgBDcAsQ
# QDYyA1qgerN/m4+u02xEPFNWGOsVqsJtz7jbzL+jQckl/gKZcpC/WL6wKu3O0Gxn
# 3JRnZhTJLpvsDZH3ESyIf6SQzMRYDS91hlceuTPr6xOuNBgGSRE6UHHX758Qo6n1
# A+ZRCQ6y9G+KLLJlbP7wMsEFxDWCWF2zOHEywCSLKX4s/YSFdyERA+q4U/rdFke/
# Pm72/Nlur1JypNd7YwwJtRLrtAcBKMlW+l52ZL1xtMsGjVUqO7i2nFZ2vzWiDLxy
# AEx9CF2nhs7Vb9T90uZA84mqXItc2aBgbT1y0pSqOUYJVOv15EnpgIoFBMqTdubl
# wZtTbD05QvVHtlsDKx+Prp0633jGA2rGjiaEV7lke6yi9UNgzL1lrSMCAwEAAaOC
# AV8wggFbMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBT9SevFqi81iiBvmszR
# MU3z96o4dDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# EgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBQ6y825U95LTeDvZz6EGCLP
# be6YTTBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsLnZhbGxleW1lZC5uZXQv
# Q2VydERhdGEvVVctVmFsbGV5JTIwTWVkaWNhbCUyMENlbnRlciUyMFJvb3QlMjBD
# QS5jcmwwagYIKwYBBQUHAQEEXjBcMFoGCCsGAQUFBzAChk5odHRwOi8vY3JsLnZh
# bGxleW1lZC5uZXQvQ2VydERhdGEvVVctVmFsbGV5JTIwTWVkaWNhbCUyMENlbnRl
# ciUyMFJvb3QlMjBDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAAYmZeyzFiYVWbc4
# 35BnIXfafu3yi3yggMM00pVLC8jhxMLxlUxNO+GUxlPVFqW5f92HFzUCCwnMYsSR
# 9Ge6px5klm1qQNdlOH9jGklzPr7UoeUdJe6BFlyf4pekWnPtHTtHTmyIR82wkY4n
# kvIwJ3lnqkdXMrGvDMgpryAJVlxI83z/LyOZQ4JQmQ4RoWlz7cxlAZlR7HsH+9dG
# 1UL4gp8KZugoxmMHxo+YvsHpsM8IP7Y7IcvrBU7nZs8ie0A5pwPd586JvNRcG/yv
# INQggo1o0UqG6QWva41b6TCeWEar0qTbi12kRr1b6HZ56Ku+QIvTdDzJW9vO01EB
# wjKRvwdYO2AKpnJS3a3tVXPst6I5XUbBu1e47tev6vT9uzlhMQYstbnthZnULnxt
# JfRA+QjORlIC7S67JlkT9txuMn0cdhXz1Tth2x6HLHzMOxjqlO+JFgGRnWjeEpD2
# R3cdrOK3/3xAwAspBGA+av7YXbCqPkuEZILMyI4/Sy4bdIaFFPd6aifR88kq+bh1
# a7yyUP3hMtTtLn4CL9aQoAE3SbadtqrPVtr1mVNrKBpQzoZv7lqatQ5IBgv58g7c
# rEjQWNHGWBlb6zb/tObleVGSgte66kfOCIsxBrczFWqgPRQs2o8uIppSEZ1DGMDU
# Wc2emNHOmYeudyaj7PZ8DYGdBDRlMYICFzCCAhMCAQEwdjBfMRMwEQYKCZImiZPy
# LGQBGRYDbmV0MRkwFwYKCZImiZPyLGQBGRYJVmFsbGV5bWVkMS0wKwYDVQQDEyRV
# Vy1WYWxsZXkgTWVkaWNhbCBDZW50ZXIgSXNzdWluZyBDQTICEzIAAAy7guDXeCi7
# iAAAAAAADLswCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBODfHEfRhwzFR7tbGlj+cFilsKyMA0G
# CSqGSIb3DQEBAQUABIIBADeTdf99cZrIftuAu6e2tzHPKnYh9BdOdjAcy1+PG4BP
# Ts+aS5Wtt3dEESmodrIB2bnvNqvxls6NBJ7zBaKERmNdKQcYVpzboXHSyu/Haoaa
# 6oKo7B8g+muqJpzUHnAJAyRvtTEkujTSwr3WasIb5jwCG1X1IapAyGFi77udmzWd
# Q5D2uGhaHAhjW8vfsiuByt/05HYLMjQSJ0u1DbG0Jin26o6Y3tQscTQZ6zW/Jo3e
# MQMIuEqSAIyGb8k5OwXrqCL592uhUjVVvf6hjtGqdQ2HjjYDPyBdI//RNM8lney7
# rwq+VjvDSkY4zgZkX09mhB70Gq8/xHs8PZQ8FFqiYuE=
# SIG # End signature block
