# Seeds a demo/lab Entra tenant.
# Requires: Microsoft.Graph.Authentication
# Requires: Global Administrator (user writes 403 without it)
#
# NOTE: PowerShell variables are case-INsensitive. The Graph base URL is named
# $Base, not $G, because "foreach ($g in $static)" would silently overwrite $G.

[CmdletBinding()]
param(
    [switch]$CreateUsers,
    [switch]$EnableCAPolicies   # default is report-only - do not enforce Block policies in a lab
)

$ErrorActionPreference = "Stop"
$Base = "https://graph.microsoft.com/v1.0"
$BetaBase = "https://graph.microsoft.com/beta"

Connect-MgGraph -NoWelcome -Scopes @(
    "User.ReadWrite.All","User.Invite.All","Group.ReadWrite.All","Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration",
    "Policy.ReadWrite.ConditionalAccess","Policy.ReadWrite.AuthenticationMethod",
    "AdministrativeUnit.ReadWrite.All","CustomSecAttributeDefinition.ReadWrite.All",
    "CustomSecAttributeAssignment.ReadWrite.All","Organization.ReadWrite.All"
)

function Invoke-Graph {
    param([ValidateSet("GET","POST","PATCH","PUT","DELETE")]$Method, $Uri, $Body)

    if ($Uri -notmatch '^https://graph\.microsoft\.com/') {
        Write-Warning "Bad URI (variable clobbered?): $Uri"; return $null
    }

    for ($i = 1; $i -le 5; $i++) {
        try {
            $p = @{ Method = $Method; Uri = $Uri; OutputType = "PSObject"; ErrorAction = "Stop" }
            if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 99 -Compress); $p.ContentType = "application/json" }
            return Invoke-MgGraphRequest @p
        }
        catch {
            $code = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
            if ($code -in 429,503,504) { Start-Sleep -Seconds ([math]::Pow(2,$i)); continue }
            Write-Warning "$Method $Uri [$code] $($_.ErrorDetails.Message)"
            return $null
        }
    }
}

function Get-GraphAll {
    param($Uri)
    $all = @()
    while ($Uri) {
        $resp = Invoke-Graph GET $Uri
        if (-not $resp) { break }
        $all += @($resp.value)
        $Uri = $resp.'@odata.nextLink'
    }
    return $all
}

# $ref is a literal path segment; the id goes in the body as @odata.id
function Add-Ref { param($Uri,$Id) Invoke-Graph POST $Uri @{ "@odata.id" = "$Base/directoryObjects/$Id" } | Out-Null }
function Set-Ref { param($Uri,$Id) Invoke-Graph PUT  $Uri @{ "@odata.id" = "$Base/users/$Id" } | Out-Null }

$domain = (Get-GraphAll "$Base/domains?`$select=id,isDefault" | Where-Object isDefault).id
$me = Invoke-Graph GET "$Base/me?`$select=id,userPrincipalName"
Write-Host "Domain: $domain / Signed in: $($me.userPrincipalName)"

$pwProfile = @{ password = "b0gus p@s3w0rd yay!"; forceChangePasswordNextSignIn = $false }

$Departments = @("Logistics","Information Technology","IT Support","Strategic Information Systems","Data Entry",
    "Research and Development","Strategic Sourcing","Purchasing","Operations","Public Relations",
    "Corporate Communications","Advertising","Market Research","Strategic Marketing","Customer service",
    "Telesales","Account Management","Marketing","Sales","Payroll","Recruitment","Training",
    "Human Resource","Accounting","Financial")

# --- Users -------------------------------------------------------------------
if ($CreateUsers) {
    Write-Host "Creating users"
    $csv = (Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Users.txt").Content |
        ConvertFrom-Csv -Header MailNickName,GivenName,Surname,DisplayName,UserPrincipalName,x1,StreetAddress,City,x2,PostalCode,Country
    foreach ($user in $csv) {
        Invoke-Graph POST "$Base/users" @{
            accountEnabled = $true; displayName = $user.DisplayName; passwordProfile = $pwProfile
            city = $user.City; companyName = "Contoso"; country = $user.Country
            mailNickname = $user.MailNickName; postalCode = $user.PostalCode; streetAddress = $user.StreetAddress
            surname = $user.Surname; givenName = $user.GivenName
            userPrincipalName = ($user.UserPrincipalName -replace 'contoso\.com$', $domain)
        } | Out-Null
    }
}

$users = @(Get-GraphAll "$Base/users?`$filter=userType eq 'Member'&`$select=id,displayName,userPrincipalName,mailNickname&`$top=999" |
    Where-Object { $_.userPrincipalName -notlike "ADMIN.*" })
Write-Host "$($users.Count) users"
if ($users.Count -lt 2) { throw "Not enough users. Rerun with -CreateUsers." }

Write-Host "Setting department + usageLocation"
foreach ($user in $users) {
    Invoke-Graph PATCH "$Base/users/$($user.id)" @{ department = ($Departments | Get-Random); usageLocation = "US" } | Out-Null
}

# --- Groups ------------------------------------------------------------------
Write-Host "Creating groups"
foreach ($dept in $Departments) {
    Invoke-Graph POST "$Base/groups" @{
        displayName = $dept; description = "Dynamic group for $dept"; mailEnabled = $false
        mailNickname = ($dept -replace '[^a-zA-Z0-9]',''); securityEnabled = $true
        groupTypes = @("DynamicMembership")
        membershipRule = "(user.department -contains `"$dept`")"
        membershipRuleProcessingState = "On"
    } | Out-Null
}
1..50 | ForEach-Object {
    Invoke-Graph POST "$Base/groups" @{
        displayName = "Security Group $_"; mailEnabled = $false
        mailNickname = "SecurityGroup$_"; securityEnabled = $true
    } | Out-Null
}

# dynamic DEVICE group - device.* rules, not user.*
Invoke-Graph POST "$Base/groups" @{
    displayName = "All Windows Devices"; mailEnabled = $false; mailNickname = "AllWindowsDevices"
    securityEnabled = $true; groupTypes = @("DynamicMembership")
    membershipRule = '(device.deviceOSType -eq "Windows")'; membershipRuleProcessingState = "On"
} | Out-Null

# --- Admin accounts ----------------------------------------------------------
Write-Host "Creating admin accounts"
$admins = @()
foreach ($src in ($users | Get-Random -Count ([math]::Min(15,$users.Count)))) {
    $newAdmin = Invoke-Graph POST "$Base/users" @{
        displayName = "Admin $($src.displayName)"; passwordProfile = $pwProfile
        userPrincipalName = "ADMIN.$($src.userPrincipalName)"; accountEnabled = $true
        mailNickname = "admin$($src.mailNickname)"; passwordPolicies = "DisablePasswordExpiration"
    }
    if ($newAdmin) { $admins += $newAdmin }
}
Write-Host "$($admins.Count) admins"

# break-glass account - excluded from every CA policy below
$breakGlass = Invoke-Graph POST "$Base/users" @{
    displayName = "Break Glass"; userPrincipalName = "breakglass@$domain"; mailNickname = "breakglass"
    accountEnabled = $true; passwordProfile = $pwProfile; passwordPolicies = "DisablePasswordExpiration"
}
if (-not $breakGlass) { $breakGlass = Invoke-Graph GET "$Base/users/breakglass@$domain" }

$users | Get-Random -Count ([math]::Min(5,$users.Count)) | ForEach-Object {
    Invoke-Graph PATCH "$Base/users/$($_.id)" @{ accountEnabled = $false } | Out-Null
}

# --- Directory roles ---------------------------------------------------------
Write-Host "Assigning roles"
$roleDefs = Get-GraphAll "$Base/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,isEnabled"
$roles = @($roleDefs | Where-Object { $_.isBuiltIn -and $_.isEnabled -and ($_.displayName -like "*Administrator*" -or $_.displayName -like "*Reader*") })

foreach ($role in $roles) {
    if ($admins.Count -eq 0) { break }
    $n = Get-Random -Minimum 1 -Maximum ($admins.Count + 1)   # distinct picks, no duplicate 400s
    foreach ($admin in ($admins | Get-Random -Count $n)) {
        Invoke-Graph POST "$Base/roleManagement/directory/roleAssignments" @{
            principalId = $admin.id; roleDefinitionId = $role.id; directoryScopeId = "/"
        } | Out-Null
    }
}

# --- Guests ------------------------------------------------------------------
Write-Host "Inviting guests"
$emails = (Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Guest.txt").Content -split "`r?`n" |
    Where-Object { $_.Trim() } | Select-Object -Unique
foreach ($email in $emails) {
    Invoke-Graph POST "$Base/invitations" @{
        invitedUserEmailAddress = $email.Trim(); inviteRedirectUrl = "https://myapps.microsoft.com"
        sendInvitationMessage = [bool](@($true,$false) | Get-Random)
    } | Out-Null
}

$guests = @(Get-GraphAll "$Base/users?`$filter=userType eq 'Guest'&`$select=id&`$top=999")
$appAdmin = $roleDefs | Where-Object displayName -eq "Application Administrator" | Select-Object -First 1
if ($guests.Count -and $appAdmin) {
    Invoke-Graph POST "$Base/roleManagement/directory/roleAssignments" @{
        principalId = ($guests | Get-Random).id; roleDefinitionId = $appAdmin.id; directoryScopeId = "/"
    } | Out-Null
}

# --- Memberships + owners ----------------------------------------------------
Write-Host "Populating groups"
$groups = @(Get-GraphAll "$Base/groups?`$select=id,displayName,groupTypes&`$top=999")
$static = @($groups | Where-Object { $_.groupTypes -notcontains "DynamicMembership" })

foreach ($grp in $static) {
    $n = Get-Random -Minimum 10 -Maximum ([math]::Min(400,$users.Count) + 1)
    $ids = @($users | Get-Random -Count $n | Select-Object -ExpandProperty id)
    # members@odata.bind: 20 per PATCH instead of one POST per member
    for ($i = 0; $i -lt $ids.Count; $i += 20) {
        $chunk = $ids[$i..([math]::Min($i+19,$ids.Count-1))]
        Invoke-Graph PATCH "$Base/groups/$($grp.id)" @{
            "members@odata.bind" = @($chunk | ForEach-Object { "$Base/directoryObjects/$_" })
        } | Out-Null
    }
}

1..30 | ForEach-Object {
    $grp = $groups | Get-Random
    $user = $users | Get-Random
    Add-Ref "$Base/groups/$($grp.id)/owners/`$ref" $user.id
}

$static | Get-Random -Count 3 | ForEach-Object {
    $gid = $_.id
    foreach ($member in (Get-GraphAll "$Base/groups/$gid/members?`$select=id&`$top=999")) {
        Invoke-Graph DELETE "$Base/groups/$gid/members/$($member.id)/`$ref" | Out-Null   # delete puts the id in the path
    }
}

# --- Administrative units ----------------------------------------------------
Write-Host "Creating administrative units"
foreach ($region in @("US-East","US-West","EMEA","APAC")) {
    $au = Invoke-Graph POST "$Base/directory/administrativeUnits" @{
        displayName = "$region Administrative Unit"; description = "Lab AU for $region"
    }
    if (-not $au) { continue }
    foreach ($user in ($users | Get-Random -Count ([math]::Min(25,$users.Count)))) {
        Add-Ref "$Base/directory/administrativeUnits/$($au.id)/members/`$ref" $user.id
    }
}

# --- Custom security attributes ----------------------------------------------
# Needs the Attribute Definition Administrator role - Global Admin does NOT have it by default.
Write-Host "Creating custom security attributes"
$attrSet = Invoke-Graph POST "$Base/directory/attributeSets" @{
    id = "Engineering"; description = "Attributes for engineering projects"; maxAttributesPerSet = 25
}
if ($attrSet) {
    Invoke-Graph POST "$Base/directory/customSecurityAttributeDefinitions" @{
        attributeSet = "Engineering"; name = "ProjectCode"; description = "Project code"
        type = "String"; status = "Available"; isCollection = $false; isSearchable = $true
        usePreDefinedValuesOnly = $false
    } | Out-Null

    foreach ($user in ($users | Get-Random -Count ([math]::Min(20,$users.Count)))) {
        Invoke-Graph PATCH "$Base/users/$($user.id)" @{
            customSecurityAttributes = @{
                Engineering = @{
                    "@odata.type" = "#microsoft.graph.customSecurityAttributeValue"
                    ProjectCode = "PROJ-$(Get-Random -Minimum 1000 -Maximum 9999)"
                }
            }
        } | Out-Null
    }
}

# --- Policies + settings -----------------------------------------------------
Write-Host "Creating policies and settings"
if ((Get-GraphAll "$Base/groupLifecyclePolicies").Count -eq 0) {
    Invoke-Graph POST "$Base/groupLifecyclePolicies" @{
        groupLifetimeInDays = 99; managedGroupTypes = "All"; alternateNotificationEmails = "bob@contoso.com"
    } | Out-Null
}

$tpl = Get-GraphAll "$Base/groupSettingTemplates" | Where-Object displayName -eq "Group.Unified" | Select-Object -First 1
$cur = Get-GraphAll "$Base/groupSettings" | Where-Object displayName -eq "Group.Unified" | Select-Object -First 1
if ($tpl -and -not $cur) {
    $cur = Invoke-Graph POST "$Base/groupSettings" @{
        displayName = $tpl.displayName; templateId = $tpl.id
        values = @($tpl.values | ForEach-Object { @{ name = $_.name; value = $_.defaultValue } })
    }
}
if ($cur) {
    $vals = @($cur.values | ForEach-Object { @{ name = $_.name; value = $_.value } })
    foreach ($set in @{ AllowToAddGuests = "False"; AllowGuestsToAccessGroups = "True" }.GetEnumerator()) {
        $v = $vals | Where-Object name -eq $set.Key | Select-Object -First 1
        if ($v) { $v.value = $set.Value }
    }
    Invoke-Graph PATCH "$Base/groupSettings/$($cur.id)" @{ values = $vals } | Out-Null
}

# Password Rule Settings (banned passwords + lockout) - beta directorySettings surface
$pwTpl = Get-GraphAll "$BetaBase/directorySettingTemplates" |
    Where-Object id -eq "5cf42378-d67d-4f36-ba46-e8b86229381d" | Select-Object -First 1
if ($pwTpl -and -not (Get-GraphAll "$BetaBase/settings" | Where-Object templateId -eq $pwTpl.id)) {
    $pwVals = @($pwTpl.values | ForEach-Object { @{ name = $_.name; value = $_.defaultValue } })
    foreach ($set in @{
        LockoutThreshold          = "15"
        LockoutDurationInSeconds  = "30"
        BannedPasswordList        = "contoso`ncontoso123`nfabrikam`nseattle`nredmond"
        EnableBannedPasswordCheck = "True"
        BannedPasswordCheckOnPremisesMode = "Enforced"
    }.GetEnumerator()) {
        $v = $pwVals | Where-Object name -eq $set.Key | Select-Object -First 1
        if ($v) { $v.value = $set.Value }
    }
    Invoke-Graph POST "$BetaBase/settings" @{ displayName = $pwTpl.displayName; templateId = $pwTpl.id; values = $pwVals } | Out-Null
}

Invoke-Graph POST "$Base/policies/homeRealmDiscoveryPolicies" @{
    displayName = "BasicAutoAccelerationPolicy"
    definition = @('{"HomeRealmDiscoveryPolicy":{"AccelerateToFederatedDomain":true}}')
} | Out-Null

Invoke-Graph POST "$Base/policies/claimsMappingPolicies" @{
    displayName = "TransformClaimsExample"
    definition = @('{"ClaimsMappingPolicy":{"Version":1,"IncludeBasicClaimSet":"true","ClaimsSchema":[{"Source":"user","ID":"extensionattribute1"},{"Source":"transformation","ID":"DataJoin","TransformationId":"JoinTheData","JwtClaimType":"JoinedData"}],"ClaimsTransformations":[{"ID":"JoinTheData","TransformationMethod":"Join","InputClaims":[{"ClaimTypeReferenceId":"extensionattribute1","TransformationClaimType":"string1"}],"InputParameters":[{"ID":"string2","Value":"sandbox"},{"ID":"separator","Value":"."}],"OutputClaims":[{"ClaimTypeReferenceId":"DataJoin","TransformationClaimType":"outputClaim"}]}]}}')
} | Out-Null

# Enable Temporary Access Pass
Invoke-Graph PATCH "$Base/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass" @{
    "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
    state = "enabled"; defaultLifetimeInMinutes = 60; defaultLength = 8
    isUsableOnce = $false; minimumLifetimeInMinutes = 10; maximumLifetimeInMinutes = 480
} | Out-Null

# --- Applications ------------------------------------------------------------
Write-Host "Creating applications"
$demoSps = @()
foreach ($i in @(1..10 + 16..20)) {
    $days = if ($i -le 10) { 365 } else { 20 }
    $app = Invoke-Graph POST "$Base/applications" @{ displayName = "Demo App $i" }
    if (-not $app) { continue }
    # api://{appId} - https://localhost:N is rejected where verified-domain URIs are enforced
    Invoke-Graph PATCH "$Base/applications/$($app.id)" @{ identifierUris = @("api://$($app.appId)") } | Out-Null
    $sp = Invoke-Graph POST "$Base/servicePrincipals" @{ appId = $app.appId }
    if (-not $sp) { continue }
    $demoSps += $sp
    $secret = Invoke-Graph POST "$Base/servicePrincipals/$($sp.id)/addPassword" @{
        passwordCredential = @{
            displayName = "Demo App $i secret"
            startDateTime = [DateTime]::UtcNow.ToString("o")
            endDateTime = [DateTime]::UtcNow.AddDays($days).ToString("o")
        }
    }
    if ($secret.secretText) { Write-Warning "Demo App $i secret (shown once): $($secret.secretText)" }
}

# Grant Graph permissions to a few SPs - gives app-consent findings to hunt in assessments
Write-Host "Granting Graph permissions to demo apps"
$graphSp = Invoke-Graph GET "$Base/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')"
if ($graphSp -and $demoSps.Count) {
    $appRoles = @("Directory.Read.All","User.Read.All","Mail.Read","Group.Read.All")
    foreach ($sp in ($demoSps | Get-Random -Count ([math]::Min(5,$demoSps.Count)))) {
        $roleName = $appRoles | Get-Random
        $appRole = $graphSp.appRoles | Where-Object { $_.value -eq $roleName -and $_.allowedMemberTypes -contains "Application" } | Select-Object -First 1
        if ($appRole) {
            Invoke-Graph POST "$Base/servicePrincipals/$($sp.id)/appRoleAssignments" @{
                principalId = $sp.id; resourceId = $graphSp.id; appRoleId = $appRole.id
            } | Out-Null
        }
        # tenant-wide delegated consent
        Invoke-Graph POST "$Base/oauth2PermissionGrants" @{
            clientId = $sp.id; consentType = "AllPrincipals"; resourceId = $graphSp.id
            scope = "User.Read User.ReadBasic.All"
        } | Out-Null
    }
}

# --- Conditional Access ------------------------------------------------------
# Pulls the recommended policy set + Tor exit node list from the Azure_Active_Directory repo.
Write-Host "Importing conditional access policies"

$capUrl = "https://raw.githubusercontent.com/chadmcox/Azure_Active_Directory/master/Conditional%20Access%20Policy/JSON/recommended_conditional_access_policies.json"
$torUrl = "https://raw.githubusercontent.com/chadmcox/Azure_Active_Directory/master/Conditional%20Access%20Policy/JSON/Tor_Exit_Notes.json"

$torLocationId = $null
function Get-TorLocationId {
    if ($script:torLocationId) { return $script:torLocationId }
    Write-Host "  Importing tor exit node named location"
    $body = (Invoke-WebRequest -UseBasicParsing $torUrl).Content | ConvertFrom-Json
    $loc = Invoke-Graph POST "$Base/identity/conditionalAccess/namedLocations" $body
    $script:torLocationId = $loc.id
    return $script:torLocationId
}

# strip read-only properties (id/createdDateTime/modifiedDateTime/templateId) - they 400 on POST
$caps = @(((Invoke-WebRequest -UseBasicParsing $capUrl).Content | ConvertFrom-Json).value |
    Select-Object displayName, state, conditions, grantControls, sessionControls)

# Deliberate gap: 3 policies get NO break-glass exclusion, so an assessment has
# something real to flag. Everything else excludes it.
$noBreakGlass = @($caps | Get-Random -Count ([math]::Min(3,$caps.Count)) | Select-Object -ExpandProperty displayName)
Write-Host "  Break glass intentionally NOT excluded from: $($noBreakGlass -join '; ')"

# Random group exclusions - pull from the security groups created earlier
$excludableGroups = @($groups | Where-Object { $_.displayName -like "Security Group *" })

foreach ($cap in $caps) {
    Write-Host "  $($cap.displayName)"

    if ($cap.displayName -eq "Report Only - All Users - Block Tor Exit Nodes") {
        $torId = Get-TorLocationId
        if ($torId) { $cap.conditions.locations.includeLocations = @($torId) } else { continue }
    }

    # lab safety: never enforce unless explicitly asked
    if (-not $EnableCAPolicies) { $cap.state = "enabledForReportingButNotEnforced" }

    # signed-in admin always excluded so you can't lock yourself out
    $exUsers = @($cap.conditions.users.excludeUsers) + $me.id
    if ($breakGlass -and $cap.displayName -notin $noBreakGlass) { $exUsers += $breakGlass.id }
    $cap.conditions.users.excludeUsers = @($exUsers | Where-Object { $_ } | Select-Object -Unique)

    # 1-3 random group exclusions on roughly half the policies
    if ($excludableGroups.Count -and (Get-Random -Minimum 0 -Maximum 2)) {
        $picks = @($excludableGroups | Get-Random -Count (Get-Random -Minimum 1 -Maximum ([math]::Min(4,$excludableGroups.Count + 1))))
        $exGroups = @($cap.conditions.users.excludeGroups) + @($picks | Select-Object -ExpandProperty id)
        $cap.conditions.users.excludeGroups = @($exGroups | Where-Object { $_ } | Select-Object -Unique)
        Write-Host "    excluding groups: $(($picks | Select-Object -ExpandProperty displayName) -join ', ')"
    }

    Invoke-Graph POST "$Base/identity/conditionalAccess/policies" $cap | Out-Null
}

# extra named locations to make the CA blade look lived-in
Write-Host "Creating named locations"
Invoke-Graph POST "$Base/identity/conditionalAccess/namedLocations" @{
    "@odata.type" = "#microsoft.graph.ipNamedLocation"
    displayName = "Corporate HQ"; isTrusted = $true
    ipRanges = @(
        @{ "@odata.type" = "#microsoft.graph.iPv4CidrRange"; cidrAddress = "12.34.221.11/22" }
        @{ "@odata.type" = "#microsoft.graph.iPv4CidrRange"; cidrAddress = "40.77.182.32/27" }
    )
} | Out-Null

Invoke-Graph POST "$Base/identity/conditionalAccess/namedLocations" @{
    "@odata.type" = "#microsoft.graph.countryNamedLocation"
    displayName = "Allowed Countries"; countriesAndRegions = @("US","CA","GB")
    includeUnknownCountriesAndRegions = $false
} | Out-Null

# --- Hybrid sync / Entra Connect ABA decoys ----------------------------------
# Seeds objects that mirror the risky configurations described in the
# Entra Connect Sync Application-Based Authentication chapter of the
# AzureAD-Attack-Defense playbook (Cloud-Architekt). These are INERT lab decoys:
# no real sync is configured and nothing here connects to on-prem AD. The point
# is to give assessment tooling, hunting queries, and Defender for Identity
# something real to flag in a demo tenant.
Write-Host "Seeding hybrid sync / Entra Connect ABA decoys"

# 1. Sync service principal with credentials on it.
#    ABA replaces the old Sync_* account with an app + certificate. The abuse
#    path is an operator adding their OWN credential to that app. We create a
#    decoy app and stack multiple long-lived credentials on it.
$syncApp = Invoke-Graph POST "$Base/applications" @{
    displayName = "LAB Entra Connect Sync (decoy)"
    description = "Inert lab decoy - mimics Entra Connect ABA sync app. Not a real sync endpoint."
    signInAudience = "AzureADMyOrg"
}
$syncSp = $null
if ($syncApp) {
    $syncSp = Invoke-Graph POST "$Base/servicePrincipals" @{ appId = $syncApp.appId }

    # multiple overlapping secrets with long lifetimes = classic finding
    foreach ($n in 1..3) {
        Invoke-Graph POST "$Base/applications/$($syncApp.id)/addPassword" @{
            passwordCredential = @{
                displayName   = "sync credential $n"
                startDateTime = [DateTime]::UtcNow.ToString("o")
                endDateTime   = [DateTime]::UtcNow.AddDays(730).ToString("o")   # 2 years
            }
        } | Out-Null
    }

    # a self-signed cert credential, mirroring how ABA authenticates
    $cert = New-SelfSignedCertificate -Subject "CN=LAB-EntraConnectSync" `
        -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable `
        -KeySpec Signature -NotAfter (Get-Date).AddYears(2) -ErrorAction SilentlyContinue
    if ($cert) {
        Invoke-Graph PATCH "$Base/applications/$($syncApp.id)" @{
            keyCredentials = @(@{
                type  = "AsymmetricX509Cert"; usage = "Verify"
                key   = [Convert]::ToBase64String($cert.RawData)
                displayName = "CN=LAB-EntraConnectSync"
            })
        } | Out-Null
        Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }

    # 2. Low-privileged user as OWNER of the privileged sync app.
    #    App owners can mint new credentials, so this is a real escalation path.
    $lowPrivOwner = $users | Get-Random
    Add-Ref "$Base/applications/$($syncApp.id)/owners/`$ref" $lowPrivOwner.id
    if ($syncSp) { Add-Ref "$Base/servicePrincipals/$($syncSp.id)/owners/`$ref" $lowPrivOwner.id }
    Write-Host "  Sync app owner (low priv): $($lowPrivOwner.userPrincipalName)"
}

# 3. Directory Synchronization Accounts role on the decoy SP.
#    Entra blocks assignment of this role in many tenants - expect a 400/403.
$dirSyncRole = $roleDefs | Where-Object displayName -eq "Directory Synchronization Accounts" | Select-Object -First 1
if ($dirSyncRole -and $syncSp) {
    Invoke-Graph POST "$Base/roleManagement/directory/roleAssignments" @{
        principalId = $syncSp.id; roleDefinitionId = $dirSyncRole.id; directoryScopeId = "/"
    } | Out-Null
}

# 4. Hybrid Identity Administrator on a normal user account.
#    That role can reconfigure sync and reach the sync app's credentials.
$hybridRole = $roleDefs | Where-Object displayName -eq "Hybrid Identity Administrator" | Select-Object -First 1
if ($hybridRole) {
    $hybridUser = $users | Get-Random
    Invoke-Graph POST "$Base/roleManagement/directory/roleAssignments" @{
        principalId = $hybridUser.id; roleDefinitionId = $hybridRole.id; directoryScopeId = "/"
    } | Out-Null
    Write-Host "  Hybrid Identity Administrator: $($hybridUser.userPrincipalName)"
}

# 5. Legacy-style sync service account, cloud-only, password never expires,
#    no MFA. This is the pre-ABA account the playbook's earlier chapter covers.
$legacySync = Invoke-Graph POST "$Base/users" @{
    displayName = "Sync_LABSERVER_0123456789ab"; mailNickname = "SyncLABSERVER"
    userPrincipalName = "Sync_LABSERVER_0123456789ab@$domain"
    accountEnabled = $true; passwordProfile = $pwProfile
    passwordPolicies = "DisablePasswordExpiration"
    jobTitle = "On-Premises Directory Synchronization Service Account"
    department = "Information Technology"
}
if (-not $legacySync) { $legacySync = Invoke-Graph GET "$Base/users/Sync_LABSERVER_0123456789ab@$domain" }

# 6. Users that look synced from on-prem (immutableId set).
#    Gives soft-match / hard-match scenarios something to operate against.
foreach ($user in ($users | Get-Random -Count ([math]::Min(30,$users.Count)))) {
    $guid = [guid]::NewGuid()
    Invoke-Graph PATCH "$Base/users/$($user.id)" @{
        onPremisesImmutableId = [Convert]::ToBase64String($guid.ToByteArray())
    } | Out-Null
}

# 7. Multi-tenant app holding directory write permissions - the shape of an
#    over-permissioned partner/sync integration.
$partnerApp = Invoke-Graph POST "$Base/applications" @{
    displayName = "LAB Partner Sync Integration (decoy)"
    signInAudience = "AzureADMultipleOrgs"
    description = "Inert lab decoy - over-permissioned multi-tenant integration."
}
if ($partnerApp -and $graphSp) {
    $partnerSp = Invoke-Graph POST "$Base/servicePrincipals" @{ appId = $partnerApp.appId }
    $wantRoles = @("Directory.ReadWrite.All","User.ReadWrite.All","Application.ReadWrite.All")
    foreach ($rn in $wantRoles) {
        $ar = $graphSp.appRoles | Where-Object { $_.value -eq $rn -and $_.allowedMemberTypes -contains "Application" } | Select-Object -First 1
        if ($ar -and $partnerSp) {
            Invoke-Graph POST "$Base/servicePrincipals/$($partnerSp.id)/appRoleAssignments" @{
                principalId = $partnerSp.id; resourceId = $graphSp.id; appRoleId = $ar.id
            } | Out-Null
        }
    }
}

# 8. Exclude the sync accounts from CA - a very common real-world gap and one of
#    the reasons sync identities are attractive targets.
$syncExclusionGroup = Invoke-Graph POST "$Base/groups" @{
    displayName = "LAB CA Exclusion - Sync Accounts"; mailEnabled = $false
    mailNickname = "LABCAExclusionSync"; securityEnabled = $true
    description = "Inert lab decoy - service accounts excluded from Conditional Access."
}
if ($syncExclusionGroup) {
    foreach ($acct in @($legacySync) ) {
        if ($acct) { Add-Ref "$Base/groups/$($syncExclusionGroup.id)/members/`$ref" $acct.id }
    }
    # attach the exclusion to a few existing policies
    $existingCaps = @(Get-GraphAll "$Base/identity/conditionalAccess/policies?`$select=id,displayName,conditions")
    foreach ($pol in ($existingCaps | Get-Random -Count ([math]::Min(3,$existingCaps.Count)))) {
        $ex = @($pol.conditions.users.excludeGroups) + $syncExclusionGroup.id
        Invoke-Graph PATCH "$Base/identity/conditionalAccess/policies/$($pol.id)" @{
            conditions = @{ users = @{ excludeGroups = @($ex | Where-Object { $_ } | Select-Object -Unique) } }
        } | Out-Null
    }
}

# --- Manager hierarchy -------------------------------------------------------
Write-Host "Building manager hierarchy"
$ceo = Invoke-Graph POST "$Base/users" @{
    accountEnabled = $true; displayName = "Bill Gates"; passwordProfile = $pwProfile
    city = "Seattle"; state = "WA"; companyName = "Contoso"; country = "US"
    mailNickname = "BillGates"; postalCode = "99999"; streetAddress = "One Contoso Way"
    surname = "Gates"; givenName = "Bill"; userPrincipalName = "bg@$domain"
}
if (-not $ceo) { $ceo = Invoke-Graph GET "$Base/users/bg@$domain" }
if (-not $ceo) { throw "No CEO account." }

$users = @(Get-GraphAll "$Base/users?`$filter=userType eq 'Member'&`$select=id,department&`$top=999")
foreach ($dept in $Departments) {
    $members = @($users | Where-Object { $_.department -eq $dept -and $_.id -ne $ceo.id })
    if (-not $members) { continue }
    Set-Ref "$Base/users/$($members[0].id)/manager/`$ref" $ceo.id
    foreach ($user in ($members | Select-Object -Skip 1)) {
        Set-Ref "$Base/users/$($user.id)/manager/`$ref" $members[0].id
    }
}

Write-Host "Done."
