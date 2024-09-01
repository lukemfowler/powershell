## Uncomment to install required PowerShell module
#
#Install-Module -Name PSWindowsUpdate -Force -AllowClobber
#Import-Module -Name PSWindowsUpdate
#


$date = (Get-Date).ToString("yyyyMMdd-hhmm")

Start-Transcript -Path "\\techhaus\software\PowerShell\Scripts\Server Patches\patching_$date.log"


## read in the list of servers to patch
if(Test-Path -Path .\Servers_to_Patch.csv -PathType Leaf) {
    $Servers = Import-CSV .\Servers_to_Patch.csv
} else {
    Write-Host "Server Patching file not found!" -ForegroundColor Red -BackgroundColor Black
    Write-Error "Exiting script." -ErrorAction stop
}


# $date is used for logging and file naming. Suggest to not use within scripts unless exact string 
# format is suitable (not suitable for calculations!)
$date = (Get-Date).ToString("yyyyMMdd-hhmm")


## Get Domain Credentials
Write-Host "Enter Domain Admin Credentials domain\username" -ForegroundColor Yellow -BackgroundColor Black
$credOSC = Get-Credential

## Scriptblock to check for Windows updates
    $GetUpdates = {$finalList  = @() 
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
        $UpdateSearcher = $UpdateSession.CreateupdateSearcher() 
        if($updateSearcher -ne $null){
            $Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0 and Type='Software'").Updates)
    
            foreach($update in $updates){
                $titlecontains = ($Update.Title) # | select-string -Pattern 'Security','Servicing' -SimpleMatch )
                if(($titlecontains -ne $null) `
                    -and ($titlecontains -notlike "*Preview*") `
                    -and ($titlecontains -notlike "*Best Practices*") `
                    -and ($titlecontains -notlike "*Malicious Software Removal Tool*")){
                        
                        $templist = New-Object PSObject
                        $title = $Update.Title
                        $Severity = $Update.MsrcSeverity

                        $templist | Add-Member -Name "Name" -value $title -MemberType NoteProperty
                        $templist | Add-Member -Name "Severity" -Value $Severity -MemberType NoteProperty
                        $finalList += $templist
                }
            }
        }
        $finallist 
    }

## Wait for Windows Updates to finish
$WaitforWU = {
    $ServiceName = 'wuauserv'
    $arrService = Get-Service -Name $ServiceName
    while($arrService.Status -eq 'Running') {
        $arrService.Refresh()
        start-sleep -seconds 10
    }
}


Foreach($item in $Servers) {
    $server = $item.ServerName


    ## Copy Powershell Modules to target server
    $b = New-PSSession -credential $credOSC $server
    Invoke-Command -Credential $credOSC -ComputerName $server -ScriptBlock {New-Item -ItemType Directory -Force "C:\Program Files\WindowsPowershell\Modules\"}
    Copy-Item -ToSession $b "\\valleymed\groups\IT\System\Luke\PSModules\PSWindowsUpdate" -Destination 'C:\Program Files\WindowsPowershell\Modules\' -Recurse


    Invoke-Command -Credential $credOSC -ComputerName $server -ErrorAction SilentlyContinue -ScriptBlock $GetUpdates -Outvariable List

    ## If updates are needed, install them
    $installpass = 1
    While ($list) {
        Write-Host "Install Windows Updates - Pass number $installpass" -ForegroundColor Yellow -BackgroundColor Black

        $installpass = ( $installpass + 1 )
        ## install windows updates remotely 
        Start-Transcript -Path  "\\techhaus\software\PowerShell\Scripts\Server Patches\patching.log" -Append

        Invoke-WUJob -Credential $credOSC -computername $server -Script { import-module PSWindowsUpdate; Get-WindowsUpdate -AcceptAll -Install -AutoReboot } -Confirm:$false -Verbose -RunNow
        # -IgnoreRebootRequired is the counterpart to -AutoReboot

        Clear-Variable list

        ## Wait for Windows updates to finish
        Start-Transcript -Path  "\\techhaus\software\PowerShell\Scripts\Server Patches\patching.log" -Append
        Write-host "Waiting for Windows Updates to install..." -foregroundColor Yellow -BackgroundColor Black
        Invoke-Command -Credential $credOSC -ComputerName $server -ScriptBlock $WaitforWU

        ## Wait for reboot
        WaitForReboot(420)

        Start-Transcript -Path  "\\techhaus\software\PowerShell\Scripts\Server Patches\patching.log" -Append
        Write-Host "Checking for updates..." -ForegroundColor Yellow -BackgroundColor Black
        Invoke-Command -Credential $credOSC -ComputerName $server -ErrorAction SilentlyContinue -ScriptBlock $GetUpdates -Outvariable List
        Write-Host ""

    }
}
Stop-Transcript
