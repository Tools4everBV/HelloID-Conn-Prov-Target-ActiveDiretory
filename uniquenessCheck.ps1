#################################################
# HelloID-Conn-Prov-Target-Microsoft-AD-UniquenessCheck
# Check if fields are unique
# PowerShell V2
#################################################

# Initialize default properties
$a = $account | ConvertFrom-Json;
$aRef = $accountReference | ConvertFrom-Json

# The entitlementContext contains the configuration
# - configuration: The configuration that is set in the Custom PowerShell configuration
$eRef = $entitlementContext | ConvertFrom-Json

# Operation is a script parameter which contains the action HelloID wants to perform for this entitlement
# It has one of the following values: "create", "enable", "update", "disable", "delete"
$o = $operation | ConvertFrom-Json

# Set Success to false at start, at the end, only when no error occurs it is set to true
$success = $false

# Initiate empty list for Non Unique Fields
$nonUniqueFields = [System.Collections.Generic.List[PSCustomObject]]::new()

#region Fields to check
$fieldsToCheck = [PSCustomObject]@{
    "userPrincipalName" = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'userPrincipalName' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $a.userPrincipalName
        keepInSyncWith  = @("mail", "proxyAddresses") # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = @("mail", "proxyAddresses") # Properties to cross-check for uniqueness.
    }
    "mail"              = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'mail' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $a.mail
        keepInSyncWith  = @("userPrincipalName", "proxyAddresses") # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = @("userPrincipalName", "proxyAddresses") # Properties to cross-check for uniqueness.
    }
    "proxyAddresses"    = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'proxyAddresses' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $a.proxyAddresses
        keepInSyncWith  = @("userPrincipalName", "mail") # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = $null # Properties to cross-check for uniqueness.
    }
    "sAMAccountName"    = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'sAMAccountName' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $a.sAMAccountName
        keepInSyncWith  = @("commonName") # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = $null # Properties to cross-check for uniqueness.
    }
    "commonName"        = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'cn' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $a.commonName
        keepInSyncWith  = @("sAMAccountName") # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = $null # Properties to cross-check for uniqueness.
    }
}
#endregion Fields to check

try {
    if ($o.ToLower() -ne "create") {
        #region Verify account reference
        $actionMessage = "verifying account reference"
    
        if ([string]::IsNullOrEmpty($($aRef))) {
            throw "The account reference could not be found"
        }
        #endregion Verify account reference
    }
    
    foreach ($fieldToCheck in $fieldsToCheck.PsObject.Properties | Where-Object { -not[String]::IsNullOrEmpty($_.Value.accountValue) }) {       
        #region Get AD account
        # Docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2025-ps
        $actionMessage = "calculating filter account for property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)]"

        # Custom check for proxyAddresses to deal with an array of values
        $filter = $null
        if ($fieldToCheck.Value.systemFieldName -eq 'proxyAddresses') {
            foreach ($fieldToCheckAccountValue in $fieldToCheck.Value.accountValue) {
                if ($filter -eq $null) {
                    $filter = "$($fieldToCheck.Value.systemFieldName) -eq '$($fieldToCheckAccountValue)'"
                }
                else {
                    $filter = $filter + " -or $($fieldToCheck.Value.systemFieldName) -eq '$($fieldToCheckAccountValue)'"
                }
            }
        }
        else {
            $filter = "$($fieldToCheck.Value.systemFieldName) -eq '$($fieldToCheck.Value.accountValue)'" 
        }

        if (@($fieldToCheck.Value.crossCheckOn).Count -ge 1) {
            foreach ($fieldToCrossCheckOn in $fieldToCheck.Value.crossCheckOn) {
                # Custom check for proxyAddresses to prefix value with 'smtp:'
                if ($fieldToCrossCheckOn -eq 'proxyAddresses') {
                    $filter = $filter + " -or $($fieldToCrossCheckOn) -eq 'smtp:$($fieldToCheck.Value.accountValue)'"
                }
                else {
                    $filter = $filter + " -or $($fieldToCrossCheckOn) -eq '$($fieldToCheck.Value.accountValue)'"
                }
            }
        }

        $actionMessage = "querying AD account where [filter] = [$filter]"

        $getADAccountSplatParams = @{
            Filter      = $filter
            Verbose     = $false
            ErrorAction = "Stop"
        }

        Write-Information "getADAccountSplatParams: $($getADAccountSplatParams | ConvertTo-Json)"
    
        $getADAccountResponse = $null
        $getADAccountResponse = Get-ADUser @getADAccountSplatParams
        $correlatedAccount = $getADAccountResponse
            
        Write-Information "Queried AD account where [filter] = [$filter]. Result count: $(@($correlatedAccount).Count)"
        #endregion Get AD account

        #region Check property uniqueness
        $actionMessage = "checking if property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique"
        if (@($correlatedAccount).count -gt 0) {
            if ($o.ToLower() -ne "create" -and $correlatedAccount.id -eq $aRef) {
                Write-Information "Person is using property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] themselves."
            }
            else {
                Write-Information "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is not unique. In use by account with ID: $($correlatedAccount.id)"
                [void]$nonUniqueFields.Add($fieldToCheck.Name)
                if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                    foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $a.PsObject.Properties.Name }) {
                        [void]$nonUniqueFields.Add($fieldToKeepInSyncWith)
                    }
                }
            }
        }
        elseif (@($correlatedAccount).count -eq 0) {
            Write-Information "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique."
        }
        #endregion Check property uniqueness
    }

    # Set Success to true
    $success = $true
}
catch {
    $ex = $PSItem
    
    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

    # Set Success to false
    $success = $false

    Write-Warning $warningMessage

    # Required to write an error as uniqueness check doesn't show auditlog
    Write-Error $auditMessage
}
finally {
    $nonUniqueFields = @($nonUniqueFields | Sort-Object -Unique)

    # Send results
    $result = [PSCustomObject]@{
        Success         = $success
        NonUniqueFields = $nonUniqueFields
    }
    
    Write-Output ($result | ConvertTo-Json -Depth 10)
}