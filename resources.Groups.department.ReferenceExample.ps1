#####################################################
# HelloID-Conn-Prov-Target-ActiveDirectory-Resources-Groups-Department
#
# Version: 1.1.0
#####################################################
$rRef = $resourceContext | ConvertFrom-Json
$success = $false # Set to false at start, at the end, only when no error occurs it is set to true

$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

# Troubleshooting
# $dryRun = $false
$debug = $false # Warning! Only set to true when troubleshooting, this will severly impact the performance.

# Variables to define what groups to query (to check if group already exists)
$adGroupsSearchOUs = @() # Warning! When no searchOUs are specified. Groups from all ous will be retrieved.
$adGroupsSearchFilter = "" # Example: "Name -like `"combination group`"" # Warning! When no searchFilter is specified. All groups will be retrieved.
if ([String]::IsNullOrEmpty($adGroupsSearchFilter)) {
    $adGroupsSearchFilter = "*"
}

# Additionally set resource properties as required
$requiredFields = @()
# Example: Department
# $requiredFields = @('DisplayName')
# Example: Title
# $requiredFields = @('Name')
# Example: Custom object (custom object consists of all custom properties)
# $requiredFields = @('CustomField1','CustomField2')

#region Supporting Functions
function Get-ADSanitizedGroupName {
    # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
    # This list of special characters includes: a leading space a trailing space and any of the following characters: # , + " \ < > 
    # A group account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
    # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
    # https://www.ietf.org/rfc/rfc2253.txt    
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim();
    # $newName = $newName -replace ' - ','_'
    $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",;,:,\,|,},{,.]', ''
    $newName = $newName -replace '\[', '';
    $newName = $newName -replace ']', '';
    $newName = $newName -replace ' ', '';
    $newName = $newName -replace '\.\.\.\.\.', '.';
    $newName = $newName -replace '\.\.\.\.', '.';
    $newName = $newName -replace '\.\.\.', '.';
    $newName = $newName -replace '\.\.', '.';
    return $newName;
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }

        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}
#endregion Supporting Functions

#region Execute

# Get Primary Domain Controller
try {
    $pdc = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
}
catch {
    Write-Warning ("PDC Lookup Error: {0}" -f $_.Exception.InnerException.Message)
    Write-Warning "Retrying PDC Lookup"
    $pdc = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
}

# Query AD groups
try {
    Write-Verbose "Querying AD groups that match the filter [$adGroupsSearchFilter]"

    $properties = @(
        , "samAccountName"
        , "distinguishedName"
    )

    $adQuerySplatParams = @{
        Filter     = $adGroupsSearchFilter
        Properties = $properties
        Server     = $pdc
    }

    if (($adGroupsSearchOUs | Measure-Object).Count -eq 0) {
        Write-Information "Querying AD groups that match filter [$($adGroupsSearchFilter)]"
        $adGroups = Get-ADGroup @adQuerySplatParams | Select-Object $properties
    }
    else {
        $adGroups = foreach ($adGroupsSearchOU in $adGroupsSearchOUs) {
            Write-Information "Querying AD groups that match filter [$($adGroupsSearchFilter)] in OU [$($adGroupsSearchOU)]"
            Get-ADGroup @adQuerySplatParams -SearchBase $adGroupsSearchOU | Select-Object $properties
        }
    }

    # Group on samAccountName (to check if group exists (as samAccountName has to be unique for a group))
    $adGroupsGrouped = $adGroups | Group-Object samAccountName -AsHashTable

    Write-Information "Succesfully queried AD groups. Result count: $(($adGroups | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
        
    throw "Failed to query AD groups. Error Message: $($errorMessage.AuditErrorMessage)"
}

# In preview only the first 10 items of the SourceData are used
try {
    foreach ($resource in $rRef.SourceData) {
        Write-Verbose "Checking $($resource)"

        # Check if required fields are available in resource object
        $incompleteResource = $false
        $missingFields = [System.Collections.ArrayList]@()
        foreach ($requiredField in $requiredFields) {
            if ($requiredField -notin $resource.PsObject.Properties.Name) {
                $incompleteResource = $true
                [void]$missingFields.Add($requiredField)
                if ($debug -eq $true) { Write-Warning "Resource object is missing required field [$requiredField]" }
            }

            if ([String]::IsNullOrEmpty($resource.$requiredField)) {
                $incompleteResource = $true
                [void]$missingFields.Add($requiredField)
                if ($debug -eq $true) { Write-Warning "Resource object has a null or empty value for required field [$requiredField]" }
            }
        }

        if (-Not($incompleteResource -eq $True)) {
            try {
                #region mapping
                # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
                # This list of special characters includes: a leading space a trailing space and any of the following characters: # , + " \ < > 
                # A group account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
                # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
                # https://www.ietf.org/rfc/rfc2253.txt

                $path = "OU=Groups,OU=Resources,DC=enyoi,DC=org"   

                # Example: Department (department differs from other objects as the property for the name is "DisplayName", not "Name")
                $groupName = ("department_" + "$($resource.ExternalId)") # Best practice to use the id of the resource to avoid max char limitations and issues in case of name change
                $groupDescription = ("Security Group for department " + "$($resource.DisplayName)" + ", created by HelloID")

                # Example: Title
                # $groupName = ("title_" + "$($resource.ExternalId)") # Best practice to use the id of the resource to avoid max char limitations and issues in case of name change
                # $groupDescription = ("Security Group for title " + "$($resource.Name)" + ", created by HelloID")

                # Example: Custom object (custom object consists of all custom properties)
                # $groupName = ("customfield_" + "$($resource.CustomField1)") # Best practice to use the id of the resource to avoid max char limitations and issues in case of name change
                # $groupDescription = ("Security Group for custom field " + "$($resource.CustomField1)" + ", created by HelloID")

                $groupName = Get-ADSanitizedGroupName -Name $groupName

                $ADGroupParams = @{
                    Name           = $groupName
                    SamAccountName = $groupName
                    GroupCategory  = "Security"
                    GroupScope     = "Global"
                    DisplayName    = $groupName
                    Path           = $path
                    Description    = $groupDescription
                }
                #endregion mapping

                $distinguishedName = "CN=$($ADGroupParams.SamAccountName),$($ADGroupParams.Path)"
                $groupExists = $false
                $adGroup = $null
                if($null -ne $adGroupsGrouped){
                    $adGroup = $adGroupsGrouped["$($ADGroupParams.SamAccountName)"]
                }
                if ($null -ne $adGroup) {
                    $groupExists = $true
                }
                else {
                    $groupExists = $false
                }
                # If resource does not exist
                if ($groupExists -eq $False) {
                    <# Resource creation preview uses a timeout of 30 seconds
                    while actual run has timeout of 10 minutes #>
                    if (-Not($dryRun -eq $True)) {
                        if ($debug -eq $true) {
                            Write-Information "Debug: Creating group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)]"
                            Write-Information "Debug: Group parameters: $($ADGroupParams | ConvertTo-Json)"
                        }
    
                        $NewADGroup = New-ADGroup @ADGroupParams
    
                        $auditLogs.Add([PSCustomObject]@{
                                Message = "Created group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)]"
                                Action  = "CreateResource"
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Would create group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)]"
                        if ($debug -eq $true) { Write-Information "Debug: Group parameters: $($ADGroupParams | ConvertTo-Json)" }
                    }
    
                }
                else {
                    if (-Not($dryRun -eq $True)) {
                        if ($debug -eq $true) {
                            Write-Information "Debug: Group $($distinguishedName) already exists"
    
                            $auditLogs.Add([PSCustomObject]@{
                                    Message = "Skipped creating group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)]. (Already exists)"
                                    Action  = "CreateResource"
                                    IsError = $false
                                })
                        }
    
                    }
                    else {
                        Write-Warning "DryRun: Group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)] already exists"
                        if ($debug -eq $true) { Write-Information "Debug: Group parameters: $($ADGroupParams | ConvertTo-Json)" }
                    }
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                if ($errorMessage.AuditErrorMessage -like "*The specified group already exists*") {
                    if (-Not($dryRun -eq $True)) {
                        if ($debug -eq $true) {
                            Write-Information "Debug: Group $($distinguishedName) already exists"
    
                            $auditLogs.Add([PSCustomObject]@{
                                    Message = "Skipped creating group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)]. (Already exists)"
                                    Action  = "CreateResource"
                                    IsError = $false
                                })
                        }
    
                    }
                    else {
                        Write-Warning "DryRun: Group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)] already exists"
                        if ($debug -eq $true) { Write-Information "Debug: Group parameters: $($ADGroupParams | ConvertTo-Json)" }
                    }
                }
                else {
                    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
            
                    Write-Warning "Failed to create group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)]. Error Message: $($errorMessage.AuditErrorMessage)"
                    if ($debug -eq $true) {
                        Write-Information "Debug: Resource: $($resource | ConvertTo-Json)"
                        Write-Information "Debug: Group parameters: $($ADGroupParams | ConvertTo-Json)"
                    }
        
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Failed to create group [$($distinguishedName)] for resource [$($resource | ConvertTo-Json)]. Error Message: $($errorMessage.AuditErrorMessage)"
                            Action  = "CreateResource"
                            IsError = $true
                        })
                }
            }
        }
        else {
            if (-Not($dryRun -eq $True)) {
                if ($debug -eq $true) {
                    Write-Information "Debug: Resource object incomplete, cannot continue. Missing fields: $($missingFields -join ';')"
                    Write-Information "Debug: Resource object: $($resource | ConvertTo-Json)"
    
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Skipped creating group for resource [$($resource | ConvertTo-Json)]. (Resource missing required fields. Missing fields: $($missingFields -join ';'))"
                            Action  = "CreateResource"
                            IsError = $false
                        })
                }
            }
            else {
                Write-Warning "DryRun: Resource object incomplete, cannot continue. Missing fields: $($missingFields -join ';')"
                if ($debug -eq $true) { Write-Information "Debug: Resource object: $($resource | ConvertTo-Json)" }
            }
        }
    }
}
#endregion Execute
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-not($auditLogs.IsError -contains $true)) {
        $success = $true
    }
    
    #region Build up result
    $result = [PSCustomObject]@{
        Success   = $success
        AuditLogs = $auditLogs
    }
    Write-Output ($result | ConvertTo-Json)
    #endregion Build up result
}