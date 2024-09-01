
$cred = if ($cred){$cred}else{Get-Credential}  

$server = Read-Host -Prompt "Enter Server Name: "

$ServicePID = Invoke-Command -Credential $cred -computername $server -scriptblock { (get-wmiobject win32_service | Where-Object { $_.name -like "*wuauserv*"}).processID } -OutVariable processID
if ($ServicePID -ne "0") {
    Invoke-Command -Credential $cred -Computername $server -scriptblock { param ($ServicePID) taskkill /f /pid $ServicePID} -ArgumentList $ServicePID
}

$b = New-PSSession -credential $cred -computername $server -ErrorAction Stop
invoke-command -session $b -scriptblock {param($cred)
    New-PSDrive -Name nugetfolder -PSProvider FileSystem -Root "\\techhaus\software\PowerShell\scripts\Modules" -Credential $cred
    copy-item nugetfolder:\nuget -Container -Destination 'C:\Program Files\PackageManagement\ProviderAssemblies\' -Recurse -Force
    Remove-PSDrive Nugetfolder
} -ArgumentList $cred

    Invoke-Command -Session $b -ScriptBlock {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}
    Invoke-Command -Session $b -ScriptBlock {Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -confirm:$False}
    Invoke-Command -Session $b -ScriptBlock {Get-PackageProvider -ListAvailable}
    Invoke-Command -Session $b -ScriptBlock {Import-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 }
    Invoke-Command -Session $b -ScriptBlock {Set-PSRepository -Name PSGallery -InstallationPolicy Trusted }
    Invoke-Command -session $b -ScriptBlock {Install-Module -Name PSWindowsUpdate -Force -allowclobber }
    Start-Sleep -Seconds 10
    Invoke-Command -Session $b -ScriptBlock {Reset-WUComponents -verbose -erroraction Continue}
    Invoke-Command -session $b -ScriptBlock {Get-WUList -WindowsUpdate -Verbose} -OutVariable WUverbose | Format-Table

$update = $null
$update = Read-Host -Prompt "install updates (Y/n): "

#install updates from Microsoft
if ($update -like "Y" -or $update -like "yes") {
    Invoke-Command -session $b -ScriptBlock {
        invoke-wujob -computername localhost -script {
            Install-WindowsUpdate -WindowsUpdate -AcceptAll -ForceInstall -AutoReboot -confirm:$false 
        } -Confirm:$false -runnow -verbose
    }

    $runningloops = 0
    Invoke-Command -Session $b -ScriptBlock {
        $status = (Get-WUJob).statename
        while($status -eq "Running" -and $runningloops -le 45){
            Write-Host "Waiting for Updates to install..."
            Start-Sleep -Seconds 60
            $runningloops = $runningloops + 1
        }
    }
}

Remove-PSSession $b
