# IGNORE THIS ERROR! IGNORE THIS ERROR! JUST A POWERSHELL THING THAT HAPPENS ON THE FIRST LINE OF A POWERSHELL SCRIPT 

# Cimitra Active Directory Integration Module Install Script
# Author: Tay Kratzer tay@cimitra.com

$CIMITRA_DOWNLOAD = "https://github.com/cimitrasoftware/ad_exchange/archive/refs/heads/main.zip"
$global:INSTALLATION_DIRECTORY = "C:\cimitra\scripts\ad"
$CIMITRA_DOWNLOAD_OUT_FILE = "cimitra_ad.zip"

$global:runSetup = $true


function CHECK_ADMIN_LEVEL{

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator")) {
Write-Output ""
Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
Write-Output ""
exit 1
}

}

CHECK_ADMIN_LEVEL


write-output ""
write-output "START: INSTALLING - Cimitra Active Directory & Exchange Practice"
write-output "----------------------------------------------------------------"
Write-Output ""

if ($args[0]) { 
$INSTALLATION_DIRECTORY = $args[0]
}

if (Write-Output $args | Select-String "\-skipSetup" )
{
$global:runSetup = $false
}

$EXTRACTED_DIRECTORY = "$INSTALLATION_DIRECTORY\ad_exchange-main"

try{
New-Item -ItemType Directory -Force -Path $INSTALLATION_DIRECTORY
}catch{}

$theResult = $?

if (!$theResult){
Write-Output "Error: Could Not Create Installation Directory: $INSTALLATION_DIRECTORY"
exit 1
}

Write-Output ""
Write-Output "The PowerShell Scripts Will Be Installed To: $INSTALLATION_DIRECTORY"
Write-Output ""

Write-Output ""
write-output ""
write-output "START: Installing Cimitra Active Directory & Exchange Practice"
write-output "--------------------------------------------------------------"
Write-Output ""
Write-Output "Downloading File: $CIMITRA_DOWNLOAD"
Write-Output ""

Invoke-WebRequest $CIMITRA_DOWNLOAD -OutFile $CIMITRA_DOWNLOAD_OUT_FILE -UseBasicParsing 

$theResult = $?

if (!$theResult){
Write-Output "Error: Could Not Download The File: $CIMITRA_DOWNLOAD"
exit 1
}

Write-Output ""
Write-Output "Extracting File: $CIMITRA_DOWNLOAD"
Write-Output ""

Expand-Archive .\$CIMITRA_DOWNLOAD_OUT_FILE -Destination $INSTALLATION_DIRECTORY -Force

$theResult = $?

if (!$theResult){
Write-Output "Error: Could Not Extract File: $CIMITRA_DOWNLOAD_OUT_FILE"
exit 1
}

try{
Remove-Item -Path .\$CIMITRA_DOWNLOAD_OUT_FILE -Force -Recurse 2>&1 | out-null
}catch{}

try{
Move-Item -Path  $EXTRACTED_DIRECTORY\*.ps1  -Destination $INSTALLATION_DIRECTORY -Force 2>&1 | out-null
}catch{}

try{
Remove-Item -Path $EXTRACTED_DIRECTORY -Force -Recurse 2>&1 | out-null
}catch{}

try{
Set-Location -Path $INSTALLATION_DIRECTORY
}catch{
Write-Output ""
Write-Output "Error: Cannot access directory: $INSTALLATION_DIRECTORY"
Write-Output ""
exit 1
}

Write-Output ""
Write-Host "Configuring Windows to Allow PowerShell Scripts to Run" -ForegroundColor blue -BackgroundColor white
Write-Output ""
Write-Output ""
Write-Host "NOTE: Use 'A' For 'Yes to All'" -ForegroundColor blue -BackgroundColor white
Write-Output ""
Unblock-File * 

try{
powershell.exe -NonInteractive -Command Set-ExecutionPolicy Unrestricted 2>&1 | out-null
}catch{
Set-ExecutionPolicy Unrestricted 
}

try{
powershell.exe -NonInteractive -Command Set-ExecutionPolicy Bypass 2>&1 | out-null
}catch{
Set-ExecutionPolicy Bypass
}

try{
powershell.exe -NonInteractive -Command Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process 2>&1 | out-null
}catch{
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
}

try{
powershell.exe -NonInteractive -Command Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser 2>&1 | out-null
}catch{
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser}

try{
powershell.exe -NonInteractive -Command Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine 2>&1 | out-null
}catch{
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine
}



if (!(Test-Path -Path $INSTALLATION_DIRECTORY\settings.cfg -PathType leaf)){


if((Test-Path $INSTALLATION_DIRECTORY\config_reader.ps1)){

$CONFIG_IO="$INSTALLATION_DIRECTORY\config_reader.ps1"

try{
. $CONFIG_IO
}catch{}

confirmConfigSetting "$INSTALLATION_DIRECTORY\settings.cfg" "AD_USER_CONTEXT" "OU=USERS,OU=DEMO,OU=CIMITRA,DC=cimitrademo,DC=com"
confirmConfigSetting "$INSTALLATION_DIRECTORY\settings.cfg" "AD_SCRIPT_SLEEP_TIME" "5"
confirmConfigSetting "$INSTALLATION_DIRECTORY\settings.cfg" "AD_EXCLUDE_GROUP" ""
}

}

if(!(get-module -list activedirectory))
{
write-output ""
write-output "START: INSTALLING - Microsoft Remote Server Administration Tools (RSAT)"
write-output "-----------------------------------------------------------------------"
Write-Output ""

Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”

write-output ""
write-output "FINISH: INSTALLING - Microsoft Remote Server Administration Tools (RSAT)"
write-output "------------------------------------------------------------------------"
Write-Output ""

}

write-output ""
write-output "[PLEASE CONFIGURE THE EXCLUDE GROUP]"
write-output "------------------------------------"
write-output ""
write-output "NOTE: Important Security Feature: | Exclude Group |"
write-output ""
write-output "Users defined in a group designated as the | Exclude Group |"
write-output "cannot be modified by this script. The | Exclude Group | can" 
write-output "be specified in a configuration file called:"
Write-Output ""
Write-Output "$INSTALLATION_DIRECTORY\settings.cfg."
Write-Output ""
write-output "The Exclude Group setting in the settings.cfg file looks like this:"
Write-Output ""
Write-Output "AD_EXCLUDE_GROUP=CN=CIMITRA_EXCLUDE,OU=USER GROUPS,OU=GROUPS,OU=KCC,OU=DEMOSYSTEM,DC=cimitrademo,DC=com"
Write-Output ""
write-output "------------------------------------"
write-output ""
write-output "FINISH: Installing Cimitra Active Directory & Exchange Practice"
write-output "---------------------------------------------------------------"
Write-Output ""