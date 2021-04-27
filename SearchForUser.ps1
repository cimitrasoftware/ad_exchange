# Search for a User in Active Directory
# Co-Author: Tay Kratzer tay@cimitra.com
# Date: 2/23/21

Param(
    [string] $FirstNameIn,
    [string] $LastNameIn,
    [switch] $ShowErrors
 )


 $verboseOutputSet = $false


# Show Help
function ShowHelp{
$scriptName = Split-Path -leaf $PSCommandpath
Write-Host ""
Write-Host "Search for a User in Active Directory In Every OU"
Write-Host ""
Write-Host "[ HELP ]"
Write-Host ""
Write-Host ".\$scriptName -h or -help"
Write-Host ""
Write-Host "[ SCRIPT USAGE ]"
Write-Host ""
Write-Host ".\$scriptName -FirstNameIn -LastNameIn"
Write-Host ""
Write-Host "[ EXAMPLE ]"
Write-Host ""
Write-Host "Example: .\$scriptName -FirstNameIn Jane -LastNameIn Doe"
Write-Host ""
Write-Host "[ ERROR HANDLING ]"
Write-Host ""
Write-Host "-ShowErrors = Show Error Messages"
Write-Host ""
Write-Host "Example: .\$scriptName -ShowErrors -FirstNameIn Jane -LastNameIn Doe"
Write-Host ""
exit 0
}

if (Write-Output $args | Select-String "\-h\b|\-help\b" )
{
ShowHelp
}


# Get the First Name variable passed in
# Get change to title case if the culture dictates
$firstNameIn = (Get-Culture).TextInfo.ToTitleCase($FirstNameIn) 

# Get the Last Name variable passed in
# Get change to title case if the culture dictates
$lastNameIn = (Get-Culture).TextInfo.ToTitleCase($LastNameIn) 

# See if the -showErrors variable was passed in
if ($ShowErrors){
$verboseOutputSet = $true
}

# See if the -showErrors variable was passed in
if ($ForcePasswordReset){
$global:forcePasswordResetSet = $true
}


if($firstNameIn.Length -gt 2){
$firstNameInSet = $true
}

if($lastNameIn.Length -gt 2){
$lastNameInSet = $true
}


# This script expects 2 arguments
if (!( $firstNameInSet -and $lastNameInSet)){ 
ShowHelp
 }
# -------------------------------------------------


if ($ShowErrors){
$verboseOutputSet = $true
}



function  Get-DistinguishedName {
    param (
        [Parameter(Mandatory,
        ParameterSetName = 'Input')]
        [string[]]
        $CanonicalName,

        [Parameter(Mandatory,
            ValueFromPipeline,
            ParameterSetName = 'Pipeline')]
        [string]
        $InputObject
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Pipeline') {
            $arr = $_ -split '/'
            [array]::reverse($arr)
            $output = @()
            $output += $arr[0] -replace '^.*$', '$0'
            $output += ($arr | select -Skip 1 | select -SkipLast 1) -replace '^.*$', 'OU=$0'
            $output += ($arr | ? { $_ -like '*.*' }) -split '\.' -replace '^.*$', 'DC=$0'
            $output -join ','
        }
        else {
            foreach ($cn in $CanonicalName) {
                $arr = $cn -split '/'
                [array]::reverse($arr)
                $output = @()
                $output += $arr[0] -replace '^.*$', '$0'
                $output += ($arr | select -Skip 1 | select -SkipLast 1) -replace '^.*$', 'OU=$0'
                $output += ($arr | ? { $_ -like '*.*' }) -split '\.' -replace '^.*$', 'DC=$0'
                $output -join ','
            }
        }
    }
}


Write-Output ""
Write-Output "Users With The Name [ $firstNameIn $lastNameIn ]"
Write-Output "-----------------------------------------------------------"
try{
@($theUser = Get-ADUser -Filter "Name -like '$firstNameIn $lastNameIn' " ) | Get-DistinguishedName
Write-Output $theUser
$global:actionResult = $true
}catch{
$err = "$_"
$global:err = $err
$global:actionResult = $false
}


if($actionResult){
Write-Output "-----------------------------------------------------------"
}else{
Write-Output "Error: Unable to List Users in Active Directory"
Write-Output ""
Write-Output "-----------------------------------------------------------"
    if ($verboseOutputSet){
    Write-Output "[ERROR MESSAGE BELOW]"
    Write-Output "-----------------------------"
    Write-Output ""
    Write-Output $err
    Write-Output ""
    Write-Output "-----------------------------"
    }

}


