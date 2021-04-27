# Read and write to a config file
# Author: Tay Kratzer tay@cimitra.com

$CONFIG_FILE_DEFAULT="${PSScriptRoot}\settings.cfg"
$CONFIG_FILE_IN=$args[0]

# If no config file is specified, use a default settings file
if (!$args[0]) { 
$CONFIG_FILE_IN = $CONFIG_FILE_DEFAULT
# $CONFIG_FILE_IN="c:\linwin\settings.cfg"
# Write-Output "Using Settings File: $CONFIG_FILE_IN"
 }


function ConfirmFromConfigFile{
# USAGE: ConfirmFromConfigFile <config file> <variable name> <variable value> 
# EXAMPLE: ConfirmFromConfigFile 'c:\cimitra\scripts\settings.cfg' 'SERVER_ADDRESS'

# Read in 2 parameters
$CONFIG_FILE_IN=$args[0]
$VARIABLE_NAME=$args[1]


# Create the file if it doesn't exist
if (!(Test-Path $CONFIG_FILE_IN))
{
return $false
}
# ----------------------------------------------------------------------- #
# If the value exists, take everything out of the file . . 
# ...except the matching string and copy it to the temporary file
# If the value doesn't exist, copy the entire config file to the temp file
# ----------------------------------------------------------------------- #
if ((Get-Content "$CONFIG_FILE_IN") -match "$VARIABLE_NAME"){
return $true
}else{
return $false
}

}


function ReadFromConfigFile{
# USAGE: $<YOUR NAME FOR THE CONFIG FILE>=(ReadFromConfigFile '<config file to read>')
# EXAMPLE: $CONFIG=(ReadFromConfigFile 'c:\temp\test.txt')
$CONFIG_FILE_IN=$args[0]

Get-Content $CONFIG_FILE_IN | Where-Object {$_.length -gt 0} | Where-Object {!$_.StartsWith("#")} | ForEach-Object {

    $var = $_.Split('=',2).Trim()
    New-Variable -Scope Script -Name $var[0] -Value $var[1]
    }

}

function WriteToConfigFile{
# USAGE: WriteToConfigFile <config file> <variable name> <variable value> 
# EXAMPLE: WriteToConfigFile 'c:\cimitra\scripts\settings_ad.cfg' 'SERVER_ADDRESS' '192.168.1.1'

# Read in 3 parameters
$CONFIG_FILE_IN=$args[0]
$VARIABLE_NAME=$args[1]
$VARIABLE_VALUE=$args[2]
$TEMP_FILE_ONE=New-TemporaryFile

# Create the file if it doesn't exist
if (!(Test-Path $CONFIG_FILE_IN))
{
New-Item $CONFIG_FILE_IN
}
# ----------------------------------------------------------------------- #
# If the value exists, take everything out of the file . . 
# ...except the matching string and copy it to the temporary file
# If the value doesn't exist, copy the entire config file to the temp file
# ----------------------------------------------------------------------- #
if ((Get-Content "$CONFIG_FILE_IN") -match "$VARIABLE_NAME"){
(Get-Content "$CONFIG_FILE_IN") -notmatch "$VARIABLE_NAME" | Out-File "$TEMP_FILE_ONE"
}else{
Copy-Item "$CONFIG_FILE_IN" -Destination "$TEMP_FILE_ONE"
}

# Add the Variable and Value to the temp file
Add-Content $TEMP_FILE_ONE -Value "$VARIABLE_NAME=$VARIABLE_VALUE"

# Copy the temp file over the top of the config file
Copy-Item "$TEMP_FILE_ONE" -Destination "$CONFIG_FILE_IN"

# Remove the temporary file
if ((Test-Path $TEMP_FILE_ONE))
{
Remove-Item -Path $TEMP_FILE_ONE -Force
}
# cat $CONFIG_FILE_IN
}

function confirmConfigSetting{

$CONFIG_FILE_IN=$args[0]
$VARIABLE_NAME=$args[1]
$VARIABLE_VALUE=$args[2]

if (!(ConfirmFromConfigFile "$CONFIG_FILE_IN" "$VARIABLE_NAME")){

WriteToConfigFile "$CONFIG_FILE_IN" "$VARIABLE_NAME" "$VARIABLE_VALUE"

}


}



# ----------------------------------------------------------#
# For testing purposes, use the 3 lines below
# WriteToConfigFile 'c:\temp\test.txt' 'SERVER_PORT' '443'
# $CONFIG=(ReadFromConfigFile 'c:\temp\test.txt')
# Write-Output "Server PORT: $CONFIG$SERVER_PORT"

# -OR 

# For testing purposes, use the 4 lines below
# $context = "OU=USERS,OU=DEMO,OU=CIMITRA,DC=cimitrademo,DC=com"
# WriteToConfigFile 'c:\temp\test.txt' 'AD_CONTEXT' $context
# $CONFIG=(ReadFromConfigFile 'c:\temp\test.txt')
# Write-Output "ACTIVE DIRECTORY CONTEXT: $CONFIG$AD_CONTEXT"
# ----------------------------------------------------------#