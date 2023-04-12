#==========================================================================================
#
# SCRIPT NAME        :     Check-AD-Service-Account-Password-Expiration.ps1
#
# AUTHOR             :     Louis GAMBART
# CREATION DATE      :     2023.04.10
# RELEASE            :     v1.1.1
# USAGE SYNTAX       :     .\Check-AD-Service-Account-Password-Expiration.ps1
#
# SCRIPT DESCRIPTION :     This script checks the expiration date of the password of the service in Active Directory in order to monitor them via NRPE.
#
#==========================================================================================

#                 - RELEASE NOTES -
# v1.0.0  2023.04.10 - Louis GAMBART - Initial version
# v1.0.1  2023.04.12 - Louis GAMBART - Add SearchBase parameter to search in specific OU
# v1.1.0  2023.04.12 - Louis GAMBART - Add exception list
# v1.1.1  2023.04.12 - Louis GAMBART - Add a search pattern with the name of the account
#
#==========================================================================================


###################
#                 #
#  I - VARIABLES  #
#                 #
###################

# clear error variable
$error.clear()

# get the name of the host
[String] $hostname = $env:COMPUTERNAME

# set warning and error expiration days
[int] $daysWarningExpiration = 60
[int] $daysErrorExpiration = 30

# active directory users
[System.Collections.ArrayList] $errorServiceUsers = @()
[System.Collections.ArrayList] $warningServiceUsers = @()

# set the service user search pattern and OU
[String] $serviceUsersSearchPattern = "SVC-*"
[String] $serviceUsersOU = ""

# execption list
[System.Collections.ArrayList] $exceptionList = @("EXCEPTION1", "EXCEPTION2")


####################
#                  #
#  II - FUNCTIONS  #
#                  #
####################

function Get-Datetime {
    <#
    .SYNOPSIS
    Get the current date and time
    .DESCRIPTION
    Get the current date and time
    .INPUTS
    None
    .OUTPUTS
    System.DateTime: The current date and time
    .EXAMPLE
    Get-Datetime | Out-String
    2022-10-24 10:00:00
    #>
    [CmdletBinding()]
    [OutputType([System.DateTime])]
    param()
    begin {}
    process { return [DateTime]::Now }
    end {}
}


function Write-Log {
    <#
    .SYNOPSIS
    Write log message in the console
    .DESCRIPTION
    Write log message in the console
    .INPUTS
    System.String: The message to write
    System.String: The log level
    .OUTPUTS
    None
    .EXAMPLE
    Write-Log "Hello world" "Verbose"
    VERBOSE: Hello world
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('Error', 'Warning', 'Information', 'Verbose', 'Debug')]
        [string]$LogLevel = 'Information'
    )
    begin {}
    process {
        switch ($LogLevel) {
            'Error' { Write-Error $Message -ErrorAction Stop }
            'Warning' { Write-Warning $Message -WarningAction Continue }
            'Information' { Write-Information $Message -InformationAction Continue }
            'Verbose' { Write-Verbose $Message -Verbose }
            'Debug' { Write-Debug $Message -Debug Continue }
            default { throw "Invalid log level: $_" }
        }
    }
    end {}
}


function Find-Module {
    <#
    .SYNOPSIS
    Check if a module is installed
    .DESCRIPTION
    Check if a module is installed
    .INPUTS
    System.String: The name of the module
    .OUTPUTS
    System.Boolean: True if the module is installed, false otherwise
    .EXAMPLE
    Check-Module -ModuleName 'ActiveDirectory'
    True
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName
    )
    begin {}
    process {
        $module = Get-Module -Name $ModuleName -ListAvailable
        if ($module) {
            return $true
        } else {
            return $false
        }
    }
    end {}
}


function Get-Password-Expiration-Domain-Policy {
    <#
    .SYNOPSIS
    Get the password expiration domain policy
    .DESCRIPTION
    Get the password expiration domain policy
    .INPUTS
    None
    .OUTPUTS
    System.Int32: The password expiration domain policy
    .EXAMPLE
    Get-Password-Expiration-Domain-Policy
    90
    #>
    [CmdletBinding()]
    [OutputType([System.Int32])]
    param()
    begin {}
    process {
        return (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
    }
}


######################
#                    #
#  III - PARAMETERS  #
#                    #
######################

# date&time parameters
[System.Int32] $maxPasswordAge = Get-Password-Expiration-Domain-Policy
[System.DateTime] $expiredDate = (Get-Datetime).addDays(-$maxPasswordAge)
[System.DateTime] $warningDate = (Get-Datetime).addDays(-($maxPasswordAge - $daysWarningExpiration -1))
[System.DateTime] $errorDate = (Get-Datetime).addDays(-($maxPasswordAge - $daysErrorExpiration -1))


########################
#                      #
#  IV - ERROR HANDLER  #
#                      #
########################

# trap errors
trap {
    Write-Log "An error has occured: $_" 'Error'
    exit 1
}


##########################
#                        #
#  V - SCRIPT EXECUTION  #
#                        #
##########################

Write-Log "Starting script on $hostname at $(Get-Datetime)" 'Verbose'
if (Find-Module -ModuleName 'ActiveDirectory') {
    try { Import-Module -Name 'ActiveDirectory' }
    catch { Write-Log "Unable to import the ActiveDirectory module: $_" 'Error' }

    $warningServiceUsers = Get-ADUser -Filter {(PasswordLastSet -lt $warningDate) -and (PasswordLastSet -gt $errorDate) -and (PasswordNeverExpires -eq $false) -and (Enabled -eq $true) -and (Name -like $serviceUsersSearchPattern)} -Properties PasswordNeverExpires, PasswordLastSet -SearchBase $serviceUsersOU | Select-Object SamAccountName, PasswordLastSet, @{name = "DaysUntilExpired"; Expression = {$_.PasswordLastSet - $ExpiredDate | Select-Object -ExpandProperty Days}} | Sort-Object PasswordLastSet
    $errorServiceUsers = Get-ADUser -Filter {(PasswordLastSet -lt $ErrorDate) -and (PasswordLastSet -gt $expiredDate) -and (PasswordNeverExpires -eq $false) -and (Enabled -eq $true) -and (Name -like $serviceUsersSearchPattern)} -Properties PasswordNeverExpires, PasswordLastSet -SearchBase $serviceUsersOU | Select-Object SamAccountName, PasswordLastSet, @{name = "DaysUntilExpired"; Expression = {$_.PasswordLastSet - $ExpiredDate | Select-Object -ExpandProperty Days}} | Sort-Object PasswordLastSet

    $warningServiceUsers = $warningServiceUsers | Where-Object { $_.SamAccountName -notin $exceptionList }
    $errorServiceUsers = $errorServiceUsers | Where-Object { $_.SamAccountName -notin $exceptionList }

    if ($errorServiceUsers.Count -gt 0) {
        Write-Host "ERROR: $errorServiceUsers.Count", "users has the password expired in the last", $daysErrorExpiration, "days "
        Write-Host "<b>"
        foreach ($errorUser in $errorServiceUsers)
        {
            Write-Host "\n $( $errorUser.SamAccountName ) ($( $errorUser.DaysUntilExpired ) days) "
        }
        Write-Host "\n\n WARNINGS </B>(from $daysErrorExpiration to $daysWarningExpiration days)<b>:</b>"
        foreach ($warningUser in $warningServiceUsers)
        {
            Write-Host "\n $( $warningUser.SamAccountName ) ($( $warningUser.DaysUntilExpired ) days) "
        }
        exit 2
    } 
    elseif ($warningServiceUsers.Count -gt 0) {
        Write-Host "WARNING: $warningServiceUsers.Count", "users has the password expiring in the next", $daysWarningExpiration, "days "
        foreach ($warningUser in $warningServiceUsers)
        {
            Write-Host "\n $( $warningUser.SamAccountName ) ($( $warningUser.DaysUntilExpired ) days) "
        }
        exit 1
    }
    else {
        Write-Host "OK: No user has the password expiring in the next", $daysWarningExpiration, "days "
        exit 0
    }

} else {
    Write-Log "The ActiveDirectory module is not installed" 'Error'
}