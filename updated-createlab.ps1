# Requires only Microsoft.Graph.Authentication
# Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

$ErrorActionPreference = "Stop"

$Scopes = @(
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Policy.ReadWrite.ApplicationConfiguration",
    "Organization.ReadWrite.All"
)

Connect-MgGraph -Scopes $Scopes -NoWelcome

function Invoke-Graph {
    param(
        [Parameter(Mandatory)][ValidateSet("GET","POST","PATCH","PUT","DELETE")][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body
    )
    try {
        $p = @{ Method = $Method; Uri = $Uri; OutputType = "PSObject" }
        if ($PSBoundParameters.ContainsKey("Body")) {
            $p.Body = ($Body | ConvertTo-Json -Depth 20 -Compress)
            $p.ContentType = "application/json"
        }
        Invoke-MgGraphRequest @p
    }
    catch {
        Write-Warning "$Method $Uri failed: $($_.Exception.Message)"
        $null
    }
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = @()
    while ($Uri) {
        $r = Invoke-Graph -Method GET -Uri $Uri
        if (-not $r) { break }
        $items += @($r.value)
        $Uri = $r.'@odata.nextLink'
    }
    $items
}

function Add-GraphReference {
    param([string]$Uri,[string]$ObjectId)
    Invoke-Graph -Method POST -Uri $Uri -Body @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$ObjectId" } | Out-Null
}

function New-DemoApplication {
    param([string]$DisplayName,[string]$IdentifierUri,[int]$PasswordDays)
    $app = Invoke-Graph POST "https://graph.microsoft.com/v1.0/applications" @{
        displayName = $DisplayName
        identifierUris = @($IdentifierUri)
    }
    if (-not $app) { return }
    $sp = Invoke-Graph POST "https://graph.microsoft.com/v1.0/servicePrincipals" @{ appId = $app.appId }
    $secret = Invoke-Graph POST "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/addPassword" @{
        passwordCredential = @{
            displayName = "$DisplayName secret"
            startDateTime = [DateTime]::UtcNow.ToString("o")
            endDateTime = [DateTime]::UtcNow.AddDays($PasswordDays).ToString("o")
        }
    }
    if ($secret.secretText) {
        Write-Warning "Secret for $DisplayName is shown once: $($secret.secretText)"
    }
    [pscustomobject]@{ Application = $app; ServicePrincipal = $sp }
}

Write-Host "Getting default domain"
$domain = (Get-GraphCollection "https://graph.microsoft.com/v1.0/domains?`$select=id,isDefault" | Where-Object isDefault -eq $true | Select-Object -First 1).id
if (-not $domain) { throw "Default domain not found." }

$PasswordProfile = @{
    password = "b0gus p@s3w0rd yay!"
    forceChangePasswordNextSignIn = $false
}

if ((Read-Host "Do user objects need to be created? Enter Yes or No") -eq "yes") {
    Write-Host "Creating users"
    $users = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Users.txt").Content | ConvertFrom-Csv -Header MailNickName,GivenName,Surname,DisplayName,UserPrincipalName,Unused,StreetAddress,City,Unused2,PostalCode,Country
    foreach ($u in $users) {
        $upn = $u.UserPrincipalName -replace "contoso.com$",$domain
        Write-Host "Creating user $($u.DisplayName)"
        Invoke-Graph POST "https://graph.microsoft.com/v1.0/users" @{
            accountEnabled = $true; displayName = $u.DisplayName; passwordProfile = $PasswordProfile
            city = $u.City; companyName = "Contoso"; country = $u.Country
            mailNickname = $u.MailNickName; postalCode = $u.PostalCode
            streetAddress = $u.StreetAddress; surname = $u.Surname; givenName = $u.GivenName
            userPrincipalName = $upn
        } | Out-Null
    }
}

Write-Host "Getting all users"
$aadusers = @(Get-GraphCollection "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,mailNickname,department,accountEnabled,userType&`$top=999")
if ($aadusers.Count -lt 20) { Write-Host "Not very many user objects" }

$Departments = @("Logistics","Information Technology","IT Support","Strategic Information Systems","Data Entry","Research and Development","Strategic Sourcing","Purchasing","Operations","Public Relations","Corporate Communications","Advertising","Market Research","Strategic Marketing","Customer service","Telesales","Account Management","Marketing","Sales","Payroll","Recruitment","Training","Human Resource","Accounting","Financial")

Write-Host "Updating user departments and usage location"
foreach ($u in $aadusers) {
    Invoke-Graph PATCH "https://graph.microsoft.com/v1.0/users/$($u.id)" @{ department = ($Departments | Get-Random) } | Out-Null
}
foreach ($u in ($aadusers | Select-Object -First ([math]::Floor($aadusers.Count * .90)))) {
    Invoke-Graph PATCH "https://graph.microsoft.com/v1.0/users/$($u.id)" @{ usageLocation = "US" } | Out-Null
}

Write-Host "Creating dynamic department groups"
foreach ($dep in ($Departments | Select-Object -Unique)) {
    Invoke-Graph POST "https://graph.microsoft.com/v1.0/groups" @{
        displayName = $dep; description = "Dynamic group for $dep"; mailEnabled = $false
        mailNickname = ($dep -replace " ",""); securityEnabled = $true
        groupTypes = @("DynamicMembership")
        membershipRule = "(user.department -contains `"$dep`")"
        membershipRuleProcessingState = "On"
    } | Out-Null
}

Write-Host "Creating security groups"
1..50 | ForEach-Object {
    Invoke-Graph POST "https://graph.microsoft.com/v1.0/groups" @{
        displayName = "Security Group $_"; mailEnabled = $false
        mailNickname = "SecurityGroup$_"; securityEnabled = $true
    } | Out-Null
}

Write-Host "Creating admin accounts"
$aadadminusers = @()
1..15 | ForEach-Object {
    $source = $aadusers | Get-Random
    $admin = Invoke-Graph POST "https://graph.microsoft.com/v1.0/users" @{
        displayName = "Admin $($source.displayName)"; passwordProfile = $PasswordProfile
        userPrincipalName = "ADMIN.$($source.userPrincipalName)"; accountEnabled = $true
        mailNickname = "admin$($source.mailNickname)"
        passwordPolicies = "DisablePasswordExpiration"
    }
    if ($admin) { $aadadminusers += $admin }
}

Write-Host "Disabling five random accounts"
$aadusers | Get-Random -Count ([math]::Min(5,$aadusers.Count)) | ForEach-Object {
    Invoke-Graph PATCH "https://graph.microsoft.com/v1.0/users/$($_.id)" @{ accountEnabled = $false } | Out-Null
}

Write-Host "Assigning random directory roles"
$roleDefinitions = Get-GraphCollection "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn"
$targetRoles = @($roleDefinitions | Where-Object { $_.displayName -like "*Administrator*" -or $_.displayName -like "*Reader*" })
foreach ($role in $targetRoles) {
    1..(Get-Random -Minimum 3 -Maximum 15) | ForEach-Object {
        $admin = $aadadminusers | Get-Random
        Invoke-Graph POST "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" @{
            principalId = $admin.id; roleDefinitionId = $role.id; directoryScopeId = "/"
        } | Out-Null
    }
}

Write-Host "Creating guest invitations"
$guestLines = ((Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Guest.txt").Content -split "`r?`n") | Where-Object { $_.Trim() }
foreach ($email in $guestLines) {
    Invoke-Graph POST "https://graph.microsoft.com/v1.0/invitations" @{
        invitedUserEmailAddress = $email.Trim(); inviteRedirectUrl = "https://myapps.microsoft.com"
        sendInvitationMessage = [bool](@($true,$false) | Get-Random)
    } | Out-Null
}
$guests = @(Get-GraphCollection "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName&`$top=999")

$appAdminRole = $roleDefinitions | Where-Object displayName -eq "Application Administrator" | Select-Object -First 1
if ($guests -and $appAdminRole) {
    Invoke-Graph POST "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" @{
        principalId = ($guests | Get-Random).id; roleDefinitionId = $appAdminRole.id; directoryScopeId = "/"
    } | Out-Null
}

Write-Host "Collecting groups and randomizing memberships/owners"
$aadgroups = @(Get-GraphCollection "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,groupTypes&`$top=999")
foreach ($g in ($aadgroups | Where-Object { $_.groupTypes -notcontains "DynamicMembership" })) {
    1..(Get-Random -Minimum 10 -Maximum 400) | ForEach-Object {
        Add-GraphReference "https://graph.microsoft.com/v1.0/groups/$($g.id)/members/`$ref" (($aadusers | Get-Random).id)
    }
}
1..30 | ForEach-Object {
    $g = $aadgroups | Get-Random; $u = $aadusers | Get-Random
    Add-GraphReference "https://graph.microsoft.com/v1.0/groups/$($g.id)/owners/`$ref" $u.id
}
1..3 | ForEach-Object {
    $g = $aadgroups | Where-Object { $_.groupTypes -notcontains "DynamicMembership" } | Get-Random
    $members = Get-GraphCollection "https://graph.microsoft.com/v1.0/groups/$($g.id)/members?`$select=id&`$top=999"
    foreach ($m in $members) { Invoke-Graph DELETE "https://graph.microsoft.com/v1.0/groups/$($g.id)/members/$($m.id)/`$ref" | Out-Null }
}

Write-Host "Creating group lifecycle policy"
Invoke-Graph POST "https://graph.microsoft.com/v1.0/groupLifecyclePolicies" @{
    groupLifetimeInDays = 99; managedGroupTypes = "All"; alternateNotificationEmails = "bob@contoso.com"
} | Out-Null

Write-Host "Creating authorization and group settings"
$templates = Get-GraphCollection "https://graph.microsoft.com/v1.0/directorySettingTemplates"
$passwordRuleTemplate = $templates | Where-Object id -eq "5cf42378-d67d-4f36-ba46-e8b86229381d" | Select-Object -First 1
if ($passwordRuleTemplate) {
    $values = @($passwordRuleTemplate.values | ForEach-Object { @{ name=$_.name; value=$_.defaultValue } })
    ($values | Where-Object name -eq "LockoutThreshold").value = "15"
    ($values | Where-Object name -eq "LockoutDurationInSeconds").value = "30"
    Invoke-Graph POST "https://graph.microsoft.com/v1.0/settings" @{ displayName=$passwordRuleTemplate.displayName; templateId=$passwordRuleTemplate.id; values=$values } | Out-Null
}
$unifiedTemplate = $templates | Where-Object displayName -eq "Group.Unified" | Select-Object -First 1
if ($unifiedTemplate) {
    $existing = Get-GraphCollection "https://graph.microsoft.com/v1.0/settings"
    $unified = $existing | Where-Object displayName -eq "Group.Unified" | Select-Object -First 1
    if (-not $unified) {
        $unified = Invoke-Graph POST "https://graph.microsoft.com/v1.0/settings" @{
            displayName=$unifiedTemplate.displayName; templateId=$unifiedTemplate.id
            values=@($unifiedTemplate.values | ForEach-Object { @{name=$_.name;value=$_.defaultValue} })
        }
    }
    $vals = @($unified.values)
    ($vals | Where-Object name -eq "AllowToAddGuests").value = "False"
    ($vals | Where-Object name -eq "AllowGuestsToAccessGroups").value = "True"
    Invoke-Graph PATCH "https://graph.microsoft.com/v1.0/settings/$($unified.id)" @{ values=$vals } | Out-Null
}

Write-Host "Creating Home Realm Discovery and claims mapping policies"
Invoke-Graph POST "https://graph.microsoft.com/v1.0/policies/homeRealmDiscoveryPolicies" @{
    displayName="BasicAutoAccelerationPolicy"; definition=@('{"HomeRealmDiscoveryPolicy":{"AccelerateToFederatedDomain":true}}')
} | Out-Null
Invoke-Graph POST "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies" @{
    displayName="TransformClaimsExample"
    definition=@('{"ClaimsMappingPolicy":{"Version":1,"IncludeBasicClaimSet":"true","ClaimsSchema":[{"Source":"user","ID":"extensionattribute1"},{"Source":"transformation","ID":"DataJoin","TransformationId":"JoinTheData","JwtClaimType":"JoinedData"}],"ClaimsTransformations":[{"ID":"JoinTheData","TransformationMethod":"Join","InputClaims":[{"ClaimTypeReferenceId":"extensionattribute1","TransformationClaimType":"string1"}],"InputParameters":[{"ID":"string2","Value":"sandbox"},{"ID":"separator","Value":"."}],"OutputClaims":[{"ClaimTypeReferenceId":"DataJoin","TransformationClaimType":"outputClaim"}]}]}}')
} | Out-Null

Write-Host "Creating applications and service principals"
1..10 | ForEach-Object { New-DemoApplication "Demo App $_" "https://localhost:$_" 365 | Out-Null }
16..20 | ForEach-Object { New-DemoApplication "Demo App $_" "https://localhost:$_" 20 | Out-Null }

Write-Host "Creating Bill Gates demo user and manager hierarchy"
$ceo = Invoke-Graph POST "https://graph.microsoft.com/v1.0/users" @{
    accountEnabled=$true; displayName="Bill Gates"; passwordProfile=$PasswordProfile; city="Seattle"; state="WA"
    companyName="Contoso"; country="US"; mailNickname="BillGates"; postalCode="99999"
    streetAddress="One Contoso Way"; surname="Gates"; givenName="Bill"; userPrincipalName="bg@$domain"
}
$aadusers = @(Get-GraphCollection "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Member'&`$select=id,displayName,userPrincipalName,department,accountEnabled&`$top=999")
foreach ($dep in $Departments) {
    $depUsers = @($aadusers | Where-Object department -eq $dep)
    if (-not $depUsers) { continue }
    $manager = $depUsers[0]
    Invoke-Graph PUT "https://graph.microsoft.com/v1.0/users/$($manager.id)/manager/`$ref" @{ "@odata.id"="https://graph.microsoft.com/v1.0/users/$($ceo.id)" } | Out-Null
    foreach ($u in ($depUsers | Select-Object -Skip 1)) {
        Invoke-Graph PUT "https://graph.microsoft.com/v1.0/users/$($u.id)/manager/`$ref" @{ "@odata.id"="https://graph.microsoft.com/v1.0/users/$($manager.id)" } | Out-Null
    }
}

Write-Warning @"
The following MSOnline-era operations were intentionally not reproduced because there is no like-for-like supported Microsoft Graph operation:
- Creating legacy service principals with New-MsolServicePrincipal
- Enabling legacy per-user MFA with StrongAuthenticationRequirements
- Set-MsolCompanyContactInformation and Set-MsolCompanySecurityComplianceContactInformation
- Set-MsolCompanySettings legacy tenant flags
- Set-MsolPasswordPolicy validity/notification settings
Use Conditional Access/authentication-method policies for MFA and supported admin portals/APIs for tenant/domain settings.
"@

Disconnect-MgGraph
