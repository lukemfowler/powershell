## Script to build credential files for VM_deploy_xx.ps1 script
##
## This script asks you to create credential files for 
## Domain Admin account, Domain User Account, and
## Local Server Administrator Account.
##
## These files are stored in your C:\temp folder
## and will only work for the user that created them
## on the same machine.
##


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


function Test-Cred {
           
    [CmdletBinding()]
    [OutputType([String])] 
       
    Param ( 
        [Parameter( 
            Mandatory = $false, 
            ValueFromPipeLine = $true, 
            ValueFromPipelineByPropertyName = $true
        )] 
        [Alias( 
            'PSCredential'
        )] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()] 
        $Credentials
    )
    $Domain = $null
    $Root = $null
    $Username = $null
    $Password = $null
      
    If($Credentials -eq $null){
        Try {
            $Credentials = Get-Credential "valleymed\$env:username" -ErrorAction Stop
        } Catch {
            $ErrorMsg = $_.Exception.Message
            Write-Warning "Failed to validate credentials: $ErrorMsg "
            Pause
            Break
        }
    }
      
    # Checking module
    Try {
        # Split username and password
        $Username = $credentials.username
        $Password = $credentials.GetNetworkCredential().password
  
        # Get Domain
        $Root = "LDAP://" + ([ADSI]'').distinguishedName
        $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
    } Catch {
        $_.Exception.Message
        Continue
    }
  
    If(!$domain) {
        Write-Warning "Something went wrong"
    } Else {
        If ($domain.name -ne $null) {
            return "Authenticated"
        } Else {
            return "Not authenticated"
        }
    }
}


$retry = ""

$namefolder = (Get-ChildItem Env:\USERNAME).value
if (Test-Path "C:\temp\$namefolder\name.txt"){

    Write-Host "Create new Credentials"
    $Message = "Create new Credential files?  These are used for authentication during the build process and MUST EXIST."
    $Title = 'Create New Credential Files'
    $TimeOut = [int]45
    $ButtonSet = 'YN'
    $IconType = 'Exclamation'
    $retry = Show-PopUp -Message $Message -Title $Title -TimeOut $TimeOut -ButtonSet $ButtonSet -IconType $IconType 
    If ( $retry -ne 6 -and $retry -ne -1 ) {
        Write-Host "exiting script"
        $endscript = $true
        Break
    }

}


if ( $retry -eq 6 -or $retry -eq -1 -or (Test-Path "C:\temp\$namefolder\name.txt") -eq $false ) {
    $Message = "Please Enter your Domain Admin Credentials"
    $Title = 'Credential Prompt'
    $TimeOut = [int]30
    $ButtonSet = 'OK'
    $IconType = 'Exclamation'

    Show-PopUp -Message $Message -Title $Title -TimeOut $TimeOut -ButtonSet $ButtonSet -IconType $IconType 

    $path = "C:\temp\$namefolder"
    If(!(test-path -PathType container $path)){
        New-Item -ItemType Directory -Path $path
    }


    $build_Creds = $true
    $buildCredential = Get-Credential -Message "Please Enter your Domain Admin Credentials" 
    $cred_test = (Test-Cred $buildCredential)

    $loopcount = 1
    While ( $cred_test -eq "not authenticated") {
        $buildcredential = Get-Credential -Message "Please Enter your Domain Admin Credentials"
        $cred_test = $buildCredential
        if ($loopcount -eq 3){
            $build_Creds = $false
            Write-Host "No Valid Credentials Entered"
            break
        }
        
        $loopcount = $loopcount + 1
    }

    if ( $build_Creds -eq $false ) {
        $endscript = $true
        Break
    }

    if ((test-path c:\temp) -eq $false){
        new-Item c:\temp\ -itemtype  Directory -Force
    }
    $buildCredential.Password | ConvertFrom-SecureString | Out-File "C:\temp\$namefolder\password.txt" -Force
    $buildCredential.UserName | Out-File "C:\temp\$namefolder\name.txt" -force


    $Message = "Please Enter your Domain User Credentials"
    $Title = 'Credential Prompt'
    $TimeOut = [int]30
    $ButtonSet = 'OK'
    $IconType = 'Exclamation'

    Show-PopUp -Message $Message -Title $Title -TimeOut $TimeOut -ButtonSet $ButtonSet -IconType $IconType 

    $buildusercred = Get-Credential -Message "Please Enter your Domain User / SOLARWINDS Credentials"
    $cred_test = (Test-Cred $builduserCred)
    $loopcount = 1
    While ( $cred_test -eq "not authenticated") {
        $buildusercred = Get-Credential -Message "Please Enter your Domain User / SOLARWINDS Credentials"
        $cred_test = $buildusercred
        if ($loopcount -eq 3){
            $build_Creds = $false
            Write-Host "No Valid Credentials Entered"
            break
        }
        
        $loopcount = $loopcount + 1
    }

    if ( $build_Creds -eq $false ) {
        $endscript = $true
        Break
    }

    $buildusercred.Password | ConvertFrom-SecureString | Out-File "C:\temp\$namefolder\user_password.txt" -force
    $buildusercred.UserName | Out-File "C:\temp\$namefolder\user_name.txt" -Force


    $Message = "Please Enter the Server Local Administrator Password"
    $Title = 'Credential Prompt'
    $TimeOut = [int]30
    $ButtonSet = 'OK'
    $IconType = 'Exclamation'

    Show-PopUp -Message $Message -Title $Title -TimeOut $TimeOut -ButtonSet $ButtonSet -IconType $IconType 

    Read-Host -Prompt "Enter Password for Local Administrator Account" -AsSecureString |  ConvertFrom-SecureString | Out-File "C:\Temp\$namefolder\Local_Password.txt" -Force

    if ($endscript -eq $true) {
        Write-Host "Exiting Script Now."
        $endscript
    }
}



# SIG # Begin signature block
# MIIPTAYJKoZIhvcNAQcCoIIPPTCCDzkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUBrCvmllWsI5uzyVadbDA1S06
# 7gKgggyfMIIGHzCCBAegAwIBAgITMgAADLuC4Nd4KLuIAAAAAAAMuzANBgkqhkiG
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
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBp8i2RUZmfmdeEEs7Mh3zMyyNB/MA0G
# CSqGSIb3DQEBAQUABIIBABjfshN75LbR9CHi0UVWQsE3UDjdAvQQVhOy7eXFMR77
# dyOCZFSONMC1S6cB1yPRqdoueP3erEjuwFogwLUAAmwVXZF1+9JjpGhDlbTLioMY
# EJxk/jaPDnfz+3KgQxP6O8M87DOz0ahl0tic98NzWZdYer5nYystSIDTm/H7Eead
# KHA4Lw8HBjrYclck00J+GdBXjlrybBS9/oEuaB7x0d6ZQ9G69ATNV9l/XVky7vVo
# Ck7wzCEVi6EE85ZAmzsnta7+fwmwaQoa0i7pPQ/xTkCHYg20jhbkZCuNPSd5X1yy
# iGJhNRwWoCaZg18mijZze8I1k1VTbjrw3iua/NP/sjc=
# SIG # End signature block
