[CmdletBinding()]
param(
    [switch]$CreateUsers,
    [switch]$EnableCAPolicies,   # default is report-only
    [switch]$SkipUsers,
    [switch]$SkipGroups,
    [switch]$SkipAdmins,
    [switch]$SkipRoles,
    [switch]$SkipGuests,
    [switch]$SkipAdminUnits,
    [switch]$SkipCustomAttributes,
    [switch]$SkipPolicies,
    [switch]$SkipApps,
    [switch]$SkipConditionalAccess,
    [switch]$SkipSyncDecoys,
    [switch]$SkipManagers,
    [switch]$WhatIfGraph          # log writes instead of sending them
)

$ErrorActionPreference = "Stop"
$Base     = "https://graph.microsoft.com/v1.0"
$BetaBase = "https://graph.microsoft.com/beta"

$RequiredScopes = @(
    "User.ReadWrite.All","User.Invite.All","Group.ReadWrite.All","Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration",
    "Policy.Read.All","Policy.ReadWrite.ConditionalAccess","Policy.ReadWrite.AuthenticationMethod",
    "AdministrativeUnit.ReadWrite.All","CustomSecAttributeDefinition.ReadWrite.All",
    "CustomSecAttributeAssignment.ReadWrite.All","Organization.ReadWrite.All"
)

#region ----- plumbing --------------------------------------------------------

function Invoke-Graph {
    param(
        [ValidateSet("GET","POST","PATCH","PUT","DELETE")]$Method,
        $Uri,
        $Body,
        [switch]$Quiet
    )

    if ([string]::IsNullOrWhiteSpace($Uri) -or $Uri -notmatch '^https://graph\.microsoft\.com/') {
        Write-Warning "Bad URI (null or variable clobbered): '$Uri'"
        return $null
    }
    # an array leaking into an interpolated id shows up as whitespace in the path
    $path = ($Uri -split '\?')[0]
    if ($path -match '\s') {
        Write-Warning "Malformed URI path (array leaked into an id?): $path"
        return $null
    }

    if ($WhatIfGraph -and $Method -ne "GET") {
        Write-Host "  [WhatIf] $Method $Uri" -ForegroundColor DarkGray
        return $null
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
            if (-not $Quiet) {
                $msg = $_.ErrorDetails.Message
                if ($msg -and $msg.Length -gt 400) { $msg = $msg.Substring(0,400) }
                Write-Warning "$Method $Uri [$code] $msg"
            }
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
        $resp.value
        $Uri = $resp.'@odata.nextLink'
    }
}

# Get-Random -Count throws on 0 and on counts larger than the pool.
function Get-RandomSome {
    param($Pool, [int]$Count)
    $arr = @($Pool) | Where-Object { $null -ne $_ }
    if ($arr.Count -eq 0 -or $Count -le 0) { return @() }
    return @($arr | Get-Random -Count ([math]::Min($Count, $arr.Count)))
}

function Get-RandomOne {
    param($Pool)
    $arr = @($Pool) | Where-Object { $null -ne $_ -and $_.id }
    if ($arr.Count -eq 0) { return $null }
    return ($arr | Get-Random)
}

function Get-RandomInt {
    param([int]$Min, [int]$Max)          # Max is exclusive
    if ($Max -le $Min) { return $Min }
    return (Get-Random -Minimum $Min -Maximum $Max)
}

# $ref is a LITERAL path segment; the object id goes in the BODY as @odata.id.
# Application/servicePrincipal owner refs want /users/, not /directoryObjects/.
function Add-Ref {
    param(
        $Uri,
        $Id,
        [ValidateSet("directoryObjects","users","groups")]$Collection = "directoryObjects",
        [switch]$Quiet
    )
    if (-not $Id) { Write-Warning "Add-Ref called with empty id for $Uri"; return }
    Invoke-Graph POST $Uri @{ "@odata.id" = "$Base/$Collection/$Id" } -Quiet:$Quiet | Out-Null
}

function Set-Ref {
    param($Uri, $Id)
    if (-not $Id) { Write-Warning "Set-Ref called with empty id for $Uri"; return }
    Invoke-Graph PUT $Uri @{ "@odata.id" = "$Base/users/$Id" } | Out-Null
}

function Get-SettingValue {
    param($Values, $Name)
    @($Values) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
}

#endregion

#region ----- connect + preflight ---------------------------------------------

Connect-MgGraph -NoWelcome -Scopes $RequiredScopes

# Get-MgContext reports what was REQUESTED. The token is what matters, and MSAL
# will silently reuse a cached token that predates any scopes you added.
$ctx = Get-MgContext
if (-not $ctx) { throw "Connect-MgGraph failed." }

$tokenScopes = @()
try {
    $probe = Invoke-MgGraphRequest GET "$Base/me" -OutputType HttpResponseMessage
    $jwt   = $probe.RequestMessage.Headers.Authorization.Parameter
    $seg   = $jwt.Split('.')[1]
    $claims = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($seg.PadRight([math]::Ceiling($seg.Length/4)*4,'='))
    ) | ConvertFrom-Json
    $tokenScopes = $claims.scp -split ' '
    Write-Host "Token issued: $([DateTimeOffset]::FromUnixTimeSeconds($claims.iat).LocalDateTime)"
} catch {
    Write-Warning "Could not decode token; falling back to Get-MgContext scopes."
    $tokenScopes = $ctx.Scopes
}

$missing = @($RequiredScopes | Where-Object { $_ -notin $tokenScopes })
if ($missing.Count) {
    Write-Warning "Scopes MISSING from the actual token: $($missing -join ', ')"
    Write-Warning "This is usually a stale cached token. To fix:"
    Write-Warning "  Disconnect-MgGraph; Remove-Item `"`$env:USERPROFILE\.graph`" -Recurse -Force; Connect-MgGraph -Scopes ... -ContextScope Process"
    if ((Read-Host "Continue anyway? Yes/No") -notmatch '^(y|yes)$') { return }
}

$domain = (Get-GraphAll "$Base/domains?`$select=id,isDefault" | Where-Object { $_.isDefault }).id
if (-not $domain) { throw "Could not resolve the default domain." }

$me = Invoke-Graph GET "$Base/me?`$select=id,userPrincipalName"
if (-not $me -or -not $me.id) { throw "Could not resolve the signed-in user." }
Write-Host "Domain: $domain / Signed in: $($me.userPrincipalName)"

$pwProfile = @{ password = "b0gus p@s3w0rd yay!"; forceChangePasswordNextSignIn = $false }

# Always defined - the manager hierarchy and group creation both need it.
$Departments = @(
    "Logistics","Information Technology","IT Support","Strategic Information Systems","Data Entry",
    "Research and Development","Strategic Sourcing","Purchasing","Operations","Public Relations",
    "Corporate Communications","Advertising","Market Research","Strategic Marketing","Customer service",
    "Telesales","Account Management","Marketing","Sales","Payroll","Recruitment","Training",
    "Human Resource","Accounting","Financial"
)

#endregion

#region ----- users -----------------------------------------------------------

if ($CreateUsers) {
    Write-Host "Creating users"
    $csv = (Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Users.txt").Content |
        ConvertFrom-Csv -Header MailNickName,GivenName,Surname,DisplayName,UserPrincipalName,x1,StreetAddress,City,x2,PostalCode,Country
    foreach ($u in $csv) {
        Invoke-Graph POST "$Base/users" @{
            accountEnabled = $true; displayName = $u.DisplayName; passwordProfile = $pwProfile
            city = $u.City; companyName = "Contoso"; country = $u.Country
            mailNickname = $u.MailNickName; postalCode = $u.PostalCode; streetAddress = $u.StreetAddress
            surname = $u.Surname; givenName = $u.GivenName
            userPrincipalName = ($u.UserPrincipalName -replace 'contoso\.com$', $domain)
        } -Quiet | Out-Null
    }
}

# ALWAYS queried, even with -SkipUsers - everything downstream depends on it.
$users = @(Get-GraphAll "$Base/users?`$filter=userType eq 'Member'&`$select=id,displayName,userPrincipalName,mailNickname,department&`$top=999" |
    Where-Object { $_.id -and $_.userPrincipalName -notlike "ADMIN.*" })
Write-Host "$($users.Count) member users"
if ($users.Count -lt 2) { throw "Not enough users. Rerun with -CreateUsers." }

if (-not $SkipUsers) {
    Write-Host "Setting department + usageLocation"
    foreach ($u in $users) {
        Invoke-Graph PATCH "$Base/users/$($u.id)" @{
            department = ($Departments | Get-Random); usageLocation = "US"
        } -Quiet | Out-Null
    }
}

#endregion

#region ----- groups ----------------------------------------------------------

if (-not $SkipGroups) {
    Write-Host "Creating groups"
    foreach ($dept in $Departments) {
        Invoke-Graph POST "$Base/groups" @{
            displayName = $dept; description = "Dynamic group for $dept"; mailEnabled = $false
            mailNickname = ($dept -replace '[^a-zA-Z0-9]',''); securityEnabled = $true
            groupTypes = @("DynamicMembership")
            membershipRule = "(user.department -contains `"$dept`")"
            membershipRuleProcessingState = "On"
        } -Quiet | Out-Null
    }

    1..50 | ForEach-Object {
        Invoke-Graph POST "$Base/groups" @{
            displayName = "Security Group $_"; mailEnabled = $false
            mailNickname = "SecurityGroup$_"; securityEnabled = $true
        } -Quiet | Out-Null
    }

    Invoke-Graph POST "$Base/groups" @{
        displayName = "All Windows Devices"; mailEnabled = $false; mailNickname = "AllWindowsDevices"
        securityEnabled = $true; groupTypes = @("DynamicMembership")
        membershipRule = '(device.deviceOSType -eq "Windows")'; membershipRuleProcessingState = "On"
    } -Quiet | Out-Null
}

# ALWAYS queried - CA exclusions and the sync decoys both need $groups.
$groups = @(Get-GraphAll "$Base/groups?`$select=id,displayName,groupTypes&`$top=999" | Where-Object { $_.id })
$static = @($groups | Where-Object { $_.groupTypes -notcontains "DynamicMembership" })
Write-Host "$($groups.Count) groups ($($static.Count) static)"

if (-not $SkipGroups -and $static.Count) {
    Write-Host "Populating group membership"
    foreach ($grp in $static) {
        $n   = Get-RandomInt 10 ([math]::Min(400,$users.Count) + 1)
        $ids = @(Get-RandomSome -Pool $users -Count $n | Select-Object -ExpandProperty id)
        if (-not $ids.Count) { continue }
        # members@odata.bind takes 20 refs per PATCH - vastly fewer calls than /$ref singles
        for ($i = 0; $i -lt $ids.Count; $i += 20) {
            $chunk = @($ids[$i..([math]::Min($i+19, $ids.Count-1))])
            Invoke-Graph PATCH "$Base/groups/$($grp.id)" @{
                "members@odata.bind" = @($chunk | ForEach-Object { "$Base/directoryObjects/$_" })
            } -Quiet | Out-Null
        }
    }

    Write-Host "Assigning group owners"
    1..30 | ForEach-Object {
        $grp = Get-RandomOne -Pool $groups
        $usr = Get-RandomOne -Pool $users
        if ($grp -and $usr) { Add-Ref "$Base/groups/$($grp.id)/owners/`$ref" $usr.id -Quiet }
    }

    Write-Host "Emptying a few groups"
    foreach ($grp in (Get-RandomSome -Pool $static -Count 3)) {
        foreach ($m in (Get-GraphAll "$Base/groups/$($grp.id)/members?`$select=id&`$top=999")) {
            # DELETE is the one case where the id IS in the path - and $ref still trails it
            Invoke-Graph DELETE "$Base/groups/$($grp.id)/members/$($m.id)/`$ref" -Quiet | Out-Null
        }
    }
}

#endregion

#region ----- admins + break glass --------------------------------------------

$admins = @()
if (-not $SkipAdmins) {
    Write-Host "Creating admin accounts"
    foreach ($src in (Get-RandomSome -Pool $users -Count 15)) {
        $a = Invoke-Graph POST "$Base/users" @{
            displayName = "Admin $($src.displayName)"; passwordProfile = $pwProfile
            userPrincipalName = "ADMIN.$($src.userPrincipalName)"; accountEnabled = $true
            mailNickname = "admin$($src.mailNickname)"; passwordPolicies = "DisablePasswordExpiration"
        } -Quiet
        if ($a -and $a.id) { $admins += $a }
    }
    Write-Host "$($admins.Count) admin accounts"

    foreach ($u in (Get-RandomSome -Pool $users -Count 5)) {
        Invoke-Graph PATCH "$Base/users/$($u.id)" @{ accountEnabled = $false } -Quiet | Out-Null
    }
}

# ALWAYS created/resolved - the CA section excludes it.
$breakGlass = Invoke-Graph POST "$Base/users" @{
    displayName = "Break Glass"; userPrincipalName = "breakglass@$domain"; mailNickname = "breakglass"
    accountEnabled = $true; passwordProfile = $pwProfile; passwordPolicies = "DisablePasswordExpiration"
} -Quiet
if (-not $breakGlass) { $breakGlass = Invoke-Graph GET "$Base/users/breakglass@$domain" -Quiet }
if ($breakGlass) { Write-Host "Break glass: $($breakGlass.userPrincipalName)" }

#endregion

#region ----- directory roles -------------------------------------------------

# ALWAYS queried - the sync decoys look up roles by name.
$roleDefs = @(Get-GraphAll "$Base/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,isEnabled")

if (-not $SkipRoles -and $admins.Count) {
    Write-Host "Assigning directory roles"
    $roles = @($roleDefs | Where-Object {
        $_.isBuiltIn -and $_.isEnabled -and
        ($_.displayName -like "*Administrator*" -or $_.displayName -like "*Reader*")
    })
    foreach ($role in $roles) {
        $n = Get-RandomInt 1 ($admins.Count + 1)
        foreach ($a in (Get-RandomSome -Pool $admins -Count $n)) {
            Invoke-Graph POST "$Base/roleManagement/directory/roleAssignments" @{
                principalId = $a.id; roleDefinitionId = $role.id; directoryScopeId = "/"
            } -Quiet | Out-Null
        }
    }
}

#endregion

#region ----- guests ----------------------------------------------------------

if (-not $SkipGuests) {
    Write-Host "Inviting guests"
    $emails = (Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Guest.txt").Content -split "`r?`n" |
        Where-Object { $_.Trim() } | Select-Object -Unique
    foreach ($email in $emails) {
        Invoke-Graph POST "$Base/invitations" @{
            invitedUserEmailAddress = $email.Trim(); inviteRedirectUrl = "https://myapps.microsoft.com"
            sendInvitationMessage = [bool](@($true,$false) | Get-Random)
        } -Quiet | Out-Null
    }

    $guests   = @(Get-GraphAll "$Base/users?`$filter=userType eq 'Guest'&`$select=id&`$top=999")
    $appAdmin = $roleDefs | Where-Object { $_.displayName -eq "Application Administrator" } | Select-Object -First 1
    $guest    = Get-RandomOne -Pool $guests
    if ($guest -and $appAdmin) {
        Invoke-Graph POST "$Base/roleManagement/directory/roleAssignments" @{
            principalId = $guest.id; roleDefinitionId = $appAdmin.id; directoryScopeId = "/"
        } -Quiet | Out-Null
    }
}

#endregion

#region ----- administrative units --------------------------------------------

if (-not $SkipAdminUnits) {
    Write-Host "Creating administrative units"
    foreach ($region in @("US-East","US-West","EMEA","APAC")) {
        $au = Invoke-Graph POST "$Base/directory/administrativeUnits" @{
            displayName = "$region Administrative Unit"; description = "Lab AU for $region"
        } -Quiet
        if (-not $au -or -not $au.id) { continue }
        foreach ($u in (Get-RandomSome -Pool $users -Count 25)) {
            Add-Ref "$Base/directory/administrativeUnits/$($au.id)/members/`$ref" $u.id -Quiet
        }
    }
}

#endregion

#region ----- custom security attributes --------------------------------------

# Needs Attribute Definition Administrator. Global Admin does NOT include it.
if (-not $SkipCustomAttributes) {
    Write-Host "Creating custom security attributes"
    $attrSet = Invoke-Graph POST "$Base/directory/attributeSets" @{
        id = "Engineering"; description = "Attributes for engineering projects"; maxAttributesPerSet = 25
    } -Quiet
    if (-not $attrSet) {
        $attrSet = Invoke-Graph GET "$Base/directory/attributeSets/Engineering" -Quiet
    }
    if (-not $attrSet) {
        Write-Warning "  attributeSets unavailable - assign 'Attribute Definition Administrator' and rerun. Skipping."
    }
    else {
        Invoke-Graph POST "$Base/directory/customSecurityAttributeDefinitions" @{
            attributeSet = "Engineering"; name = "ProjectCode"; description = "Project code"
            type = "String"; status = "Available"; isCollection = $false; isSearchable = $true
            usePreDefinedValuesOnly = $false
        } -Quiet | Out-Null

        foreach ($u in (Get-RandomSome -Pool $users -Count 20)) {
            Invoke-Graph PATCH "$Base/users/$($u.id)" @{
                customSecurityAttributes = @{
                    Engineering = @{
                        "@odata.type" = "#microsoft.graph.customSecurityAttributeValue"
                        ProjectCode   = "PROJ-$(Get-Random -Minimum 1000 -Maximum 9999)"
                    }
                }
            } -Quiet | Out-Null
        }
    }
}

#endregion

#region ----- policies + settings ---------------------------------------------

if (-not $SkipPolicies) {
    Write-Host "Creating policies and settings"

    if (@(Get-GraphAll "$Base/groupLifecyclePolicies").Count -eq 0) {
        Invoke-Graph POST "$Base/groupLifecyclePolicies" @{
            groupLifetimeInDays = 99; managedGroupTypes = "All"; alternateNotificationEmails = "bob@contoso.com"
        } -Quiet | Out-Null
    }

    $tpl = @(Get-GraphAll "$Base/groupSettingTemplates") | Where-Object { $_.displayName -eq "Group.Unified" } | Select-Object -First 1
    $cur = @(Get-GraphAll "$Base/groupSettings")         | Where-Object { $_.displayName -eq "Group.Unified" } | Select-Object -First 1
    if ($tpl -and -not $cur) {
        $cur = Invoke-Graph POST "$Base/groupSettings" @{
            displayName = $tpl.displayName; templateId = $tpl.id
            values = @($tpl.values | ForEach-Object { @{ name = $_.name; value = [string]$_.defaultValue } })
        } -Quiet
    }
    if ($cur) {
        $vals = @($cur.values | ForEach-Object { @{ name = $_.name; value = [string]$_.value } })
        foreach ($kv in @{ AllowToAddGuests = "False"; AllowGuestsToAccessGroups = "True" }.GetEnumerator()) {
            $v = Get-SettingValue -Values $vals -Name $kv.Key
            if ($v) { $v.value = $kv.Value }
        }
        Invoke-Graph PATCH "$Base/groupSettings/$($cur.id)" @{ values = $vals } -Quiet | Out-Null
    }

    # Password Rule Settings lives on the beta directorySettings surface.
    $pwTpl = @(Get-GraphAll "$BetaBase/directorySettingTemplates") |
        Where-Object { $_.id -eq "5cf42378-d67d-4f36-ba46-e8b86229381d" } | Select-Object -First 1
    $pwExisting = @(Get-GraphAll "$BetaBase/settings") |
        Where-Object { $_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d" -or $_.displayName -eq "Password Rule Settings" }

    if ($pwTpl -and -not $pwExisting) {
        # every value must be a non-null STRING or the POST 400s
        $pwVals = @($pwTpl.values | ForEach-Object { @{ name = $_.name; value = [string]$_.defaultValue } })
        foreach ($kv in @{
            LockoutThreshold                  = "15"
            LockoutDurationInSeconds          = "30"
            BannedPasswordList                = "contoso`tcontoso123`tfabrikam`tseattle`tredmond"  # TAB delimited
            EnableBannedPasswordCheck         = "True"
            BannedPasswordCheckOnPremisesMode = "Audit"
        }.GetEnumerator()) {
            $v = Get-SettingValue -Values $pwVals -Name $kv.Key
            if ($v) { $v.value = $kv.Value }
        }
        Invoke-Graph POST "$BetaBase/settings" @{
            displayName = $pwTpl.displayName; templateId = $pwTpl.id; values = $pwVals
        } -Quiet | Out-Null
    }

    Invoke-Graph POST "$Base/policies/homeRealmDiscoveryPolicies" @{
        displayName = "BasicAutoAccelerationPolicy"
        definition  = @('{"HomeRealmDiscoveryPolicy":{"AccelerateToFederatedDomain":true}}')
    } -Quiet | Out-Null

    Invoke-Graph POST "$Base/policies/claimsMappingPolicies" @{
        displayName = "TransformClaimsExample"
        definition  = @('{"ClaimsMappingPolicy":{"Version":1,"IncludeBasicClaimSet":"true","ClaimsSchema":[{"Source":"user","ID":"extensionattribute1"},{"Source":"transformation","ID":"DataJoin","TransformationId":"JoinTheData","JwtClaimType":"JoinedData"}],"ClaimsTransformations":[{"ID":"JoinTheData","TransformationMethod":"Join","InputClaims":[{"ClaimTypeReferenceId":"extensionattribute1","TransformationClaimType":"string1"}],"InputParameters":[{"ID":"string2","Value":"sandbox"},{"ID":"separator","Value":"."}],"OutputClaims":[{"ClaimTypeReferenceId":"DataJoin","TransformationClaimType":"outputClaim"}]}]}}')
    } -Quiet | Out-Null

    Invoke-Graph PATCH "$Base/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass" @{
        "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
        state = "enabled"; defaultLifetimeInMinutes = 60; defaultLength = 8
        isUsableOnce = $false; minimumLifetimeInMinutes = 10; maximumLifetimeInMinutes = 480
    } -Quiet | Out-Null
}

#endregion

#region ----- applications ----------------------------------------------------

# ALWAYS resolved - the sync decoys grant Graph app roles.
$graphSp = Invoke-Graph GET "$Base/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')"
$demoSps = @()

if (-not $SkipApps) {
    Write-Host "Creating applications"
    foreach ($i in @(1..10 + 16..20)) {
        $days = if ($i -le 10) { 365 } else { 20 }
        $app = Invoke-Graph POST "$Base/applications" @{ displayName = "Demo App $i" } -Quiet
        if (-not $app -or -not $app.id) { continue }

        # api://{appId} always validates; https://localhost:N is rejected where
        # verified-domain identifier URIs are enforced
        Invoke-Graph PATCH "$Base/applications/$($app.id)" @{ identifierUris = @("api://$($app.appId)") } -Quiet | Out-Null

        $sp = Invoke-Graph POST "$Base/servicePrincipals" @{ appId = $app.appId } -Quiet
        if (-not $sp -or -not $sp.id) { continue }
        $demoSps += $sp

        $secret = Invoke-Graph POST "$Base/servicePrincipals/$($sp.id)/addPassword" @{
            passwordCredential = @{
                displayName   = "Demo App $i secret"
                startDateTime = [DateTime]::UtcNow.ToString("o")
                endDateTime   = [DateTime]::UtcNow.AddDays($days).ToString("o")
            }
        } -Quiet
        if ($secret -and $secret.secretText) { Write-Host "  Demo App $i secret: $($secret.secretText)" }
    }

    if ($graphSp -and $demoSps.Count) {
        Write-Host "Granting Graph permissions to demo apps"
        $wanted = @("Directory.Read.All","User.Read.All","Mail.Read","Group.Read.All")
        foreach ($sp in (Get-RandomSome -Pool $demoSps -Count 5)) {
            $roleName = $wanted | Get-Random
            $appRole  = $graphSp.appRoles | Where-Object {
                $_.value -eq $roleName -and $_.allowedMemberTypes -contains "Application"
            } | Select-Object -First 1
            if ($appRole) {
                Invoke-Graph POST "$Base/servicePrincipals/$($sp.id)/appRoleAssignments" @{
                    principalId = $sp.id; resourceId = $graphSp.id; appRoleId = $appRole.id
                } -Quiet | Out-Null
            }
            Invoke-Graph POST "$Base/oauth2PermissionGrants" @{
                clientId = $sp.id; consentType = "AllPrincipals"; resourceId = $graphSp.id
                scope = "User.Read User.ReadBasic.All"
            } -Quiet | Out-Null
        }
    }
}

#endregion

#region ----- conditional access ----------------------------------------------

if (-not $SkipConditionalAccess) {
    Write-Host "Importing conditional access policies"

    $capUrl = "https://raw.githubusercontent.com/chadmcox/Azure_Active_Directory/master/Conditional%20Access%20Policy/JSON/recommended_conditional_access_policies.json"
    $torUrl = "https://raw.githubusercontent.com/chadmcox/Azure_Active_Directory/master/Conditional%20Access%20Policy/JSON/Tor_Exit_Notes.json"

    $script:torLocationId = $null
    function Get-TorLocationId {
        if ($script:torLocationId) { return $script:torLocationId }
        Write-Host "  Importing tor exit node named location"
        $body = (Invoke-WebRequest -UseBasicParsing $torUrl).Content | ConvertFrom-Json
        $loc  = Invoke-Graph POST "$Base/identity/conditionalAccess/namedLocations" $body -Quiet
        if ($loc) { $script:torLocationId = $loc.id }
        return $script:torLocationId
    }

    # strip read-only props (id/createdDateTime/modifiedDateTime/templateId) - they 400 on POST
    $caps = @(((Invoke-WebRequest -UseBasicParsing $capUrl).Content | ConvertFrom-Json).value |
        Select-Object displayName, state, conditions, grantControls, sessionControls)

    if (-not $caps.Count) {
        Write-Warning "  No policies pulled from the repo - skipping CA import."
    }
    else {
        # deliberate gap: 3 policies get NO break-glass exclusion so an assessment
        # has something real to flag
        $noBreakGlass = @(Get-RandomSome -Pool $caps -Count 3 | Select-Object -ExpandProperty displayName)
        if ($noBreakGlass.Count) {
            Write-Host "  Break glass intentionally NOT excluded from: $($noBreakGlass -join '; ')"
        }

        $excludableGroups = @($groups | Where-Object { $_.displayName -like "Security Group *" })

        foreach ($cap in $caps) {
            Write-Host "  $($cap.displayName)"

            if ($cap.displayName -eq "Report Only - All Users - Block Tor Exit Nodes") {
                $torId = Get-TorLocationId
                if ($torId) { $cap.conditions.locations.includeLocations = @($torId) } else { continue }
            }

            if (-not $EnableCAPolicies) { $cap.state = "enabledForReportingButNotEnforced" }

            # signed-in admin always excluded so you can't lock yourself out
            $exUsers = @($cap.conditions.users.excludeUsers) + $me.id
            if ($breakGlass -and $cap.displayName -notin $noBreakGlass) { $exUsers += $breakGlass.id }
            $cap.conditions.users.excludeUsers = @($exUsers | Where-Object { $_ } | Select-Object -Unique)

            # 1-3 random group exclusions on roughly half the policies
            if ($excludableGroups.Count -and (Get-RandomInt 0 2)) {
                $picks = Get-RandomSome -Pool $excludableGroups -Count (Get-RandomInt 1 4)
                if ($picks.Count) {
                    $exGroups = @($cap.conditions.users.excludeGroups) + @($picks | Select-Object -ExpandProperty id)
                    $cap.conditions.users.excludeGroups = @($exGroups | Where-Object { $_ } | Select-Object -Unique)
                    Write-Host "    excluding: $(($picks | Select-Object -ExpandProperty displayName) -join ', ')"
                }
            }

            Invoke-Graph POST "$Base/identity/conditionalAccess/policies" $cap | Out-Null
        }
    }

    Write-Host "Creating named locations"
    Invoke-Graph POST "$Base/identity/conditionalAccess/namedLocations" @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        displayName = "Corporate HQ"; isTrusted = $true
        ipRanges = @(
            @{ "@odata.type" = "#microsoft.graph.iPv4CidrRange"; cidrAddress = "12.34.221.11/22" }
            @{ "@odata.type" = "#microsoft.graph.iPv4CidrRange"; cidrAddress = "40.77.182.32/27" }
        )
    } -Quiet | Out-Null

    Invoke-Graph POST "$Base/identity/conditionalAccess/namedLocations" @{
        "@odata.type" = "#microsoft.graph.countryNamedLocation"
        displayName = "Allowed Countries"; countriesAndRegions = @("US","CA","GB")
        includeUnknownCountriesAndRegions = $false
    } -Quiet | Out-Null
}

#endregion

#region ----- hybrid sync / Entra Connect ABA decoys --------------------------

# Mirrors risky configurations from the Entra Connect Sync ABA chapter of the
# AzureAD-Attack-Defense playbook. INERT: no sync configured, nothing touches
# on-prem AD. Everything is prefixed LAB/Sync_LABSERVER for easy cleanup.
if (-not $SkipSyncDecoys) {
    Write-Host "Seeding hybrid sync / Entra Connect ABA decoys"

    # 1. sync app with stacked long-lived credentials
    $syncApp = Invoke-Graph POST "$Base/applications" @{
        displayName    = "LAB Entra Connect Sync (decoy)"
        description    = "Inert lab decoy - mimics Entra Connect ABA sync app."
        signInAudience = "AzureADMyOrg"
    } -Quiet

    $syncSp = $null
    if ($syncApp -and $syncApp.id) {
        $syncSp = Invoke-Graph POST "$Base/servicePrincipals" @{ appId = $syncApp.appId } -Quiet

        foreach ($n in 1..3) {
            Invoke-Graph POST "$Base/applications/$($syncApp.id)/addPassword" @{
                passwordCredential = @{
                    displayName   = "sync credential $n"
                    startDateTime = [DateTime]::UtcNow.ToString("o")
                    endDateTime   = [DateTime]::UtcNow.AddDays(730).ToString("o")
                }
            } -Quiet | Out-Null
        }

        if ($IsWindows -ne $false) {
            $cert = New-SelfSignedCertificate -Subject "CN=LAB-EntraConnectSync" `
                -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable `
                -KeySpec Signature -NotAfter (Get-Date).AddYears(2) -ErrorAction SilentlyContinue
            if ($cert) {
                Invoke-Graph PATCH "$Base/applications/$($syncApp.id)" @{
                    keyCredentials = @(@{
                        type = "AsymmetricX509Cert"; usage = "Verify"
                        key  = [Convert]::ToBase64String($cert.RawData)
                        displayName = "CN=LAB-EntraConnectSync"
                    })
                } -Quiet | Out-Null
                Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
            }
        }

        # 2. low-priv user owns the privileged sync app (owners can mint credentials).
        #    app/SP owner refs need /users/, NOT /directoryObjects/ - that combination
        #    returns "Invalid target for navigation property update".
        $lowPrivOwner = Get-RandomOne -Pool $users
        if ($lowPrivOwner) {
            Add-Ref "$Base/applications/$($syncApp.id)/owners/`$ref" $lowPrivOwner.id -Collection users
            if ($syncSp -and $syncSp.id) {
                Add-Ref "$Base/servicePrincipals/$($syncSp.id)/owners/`$ref" $lowPrivOwner.id -Collection users
            }
            Write-Host "  Sync app owner (low priv): $($lowPrivOwner.userPrincipalName)"
        }
    }

    # 3. Directory Synchronization Accounts on the decoy SP (Entra blocks this in
    #    most tenants - the 400/403 is expected)
    $dirSyncRole = $roleDefs | Where-Object { $_.displayName -eq "Directory Synchronization Accounts" } | Select-Object -First 1
    if ($dirSyncRole -and $syncSp -and $syncSp.id) {
        Invoke-Graph POST "$Base/roleManagement/directory/roleAssignments" @{
            principalId = $syncSp.id; roleDefinitionId = $dirSyncRole.id; directoryScopeId = "/"
        } -Quiet | Out-Null
    }

    # 4. Hybrid Identity Administrator on a normal user
    $hybridRole = $roleDefs | Where-Object { $_.displayName -eq "Hybrid Identity Administrator" } | Select-Object -First 1
    $hybridUser = Get-RandomOne -Pool $users
    if ($hybridRole -and $hybridUser) {
        Invoke-Graph POST "$Base/roleManagement/directory/roleAssignments" @{
            principalId = $hybridUser.id; roleDefinitionId = $hybridRole.id; directoryScopeId = "/"
        } -Quiet | Out-Null
        Write-Host "  Hybrid Identity Administrator: $($hybridUser.userPrincipalName)"
    }

    # 5. legacy-style Sync_* service account, password never expires
    $legacySync = Invoke-Graph POST "$Base/users" @{
        displayName = "Sync_LABSERVER_0123456789ab"; mailNickname = "SyncLABSERVER"
        userPrincipalName = "Sync_LABSERVER_0123456789ab@$domain"
        accountEnabled = $true; passwordProfile = $pwProfile
        passwordPolicies = "DisablePasswordExpiration"
        jobTitle = "On-Premises Directory Synchronization Service Account"
        department = "Information Technology"
    } -Quiet
    if (-not $legacySync) {
        $legacySync = Invoke-Graph GET "$Base/users/Sync_LABSERVER_0123456789ab@$domain" -Quiet
    }

    # 6. users that look synced from on-prem
    foreach ($u in (Get-RandomSome -Pool $users -Count 30)) {
        Invoke-Graph PATCH "$Base/users/$($u.id)" @{
            onPremisesImmutableId = [Convert]::ToBase64String([guid]::NewGuid().ToByteArray())
        } -Quiet | Out-Null
    }

    # 7. over-permissioned multi-tenant partner integration
    $partnerApp = Invoke-Graph POST "$Base/applications" @{
        displayName    = "LAB Partner Sync Integration (decoy)"
        signInAudience = "AzureADMultipleOrgs"
        description    = "Inert lab decoy - over-permissioned multi-tenant integration."
    } -Quiet
    if ($partnerApp -and $partnerApp.id -and $graphSp) {
        $partnerSp = Invoke-Graph POST "$Base/servicePrincipals" @{ appId = $partnerApp.appId } -Quiet
        if ($partnerSp -and $partnerSp.id) {
            foreach ($rn in @("Directory.ReadWrite.All","User.ReadWrite.All","Application.ReadWrite.All")) {
                $ar = $graphSp.appRoles | Where-Object {
                    $_.value -eq $rn -and $_.allowedMemberTypes -contains "Application"
                } | Select-Object -First 1
                if ($ar) {
                    Invoke-Graph POST "$Base/servicePrincipals/$($partnerSp.id)/appRoleAssignments" @{
                        principalId = $partnerSp.id; resourceId = $graphSp.id; appRoleId = $ar.id
                    } -Quiet | Out-Null
                }
            }
        }
    }

    # 8. sync accounts excluded from CA
    $syncExclusionGroup = Invoke-Graph POST "$Base/groups" @{
        displayName = "LAB CA Exclusion - Sync Accounts"; mailEnabled = $false
        mailNickname = "LABCAExclusionSync"; securityEnabled = $true
        description = "Inert lab decoy - service accounts excluded from Conditional Access."
    } -Quiet

    if ($syncExclusionGroup -and $syncExclusionGroup.id) {
        if ($legacySync -and $legacySync.id) {
            Add-Ref "$Base/groups/$($syncExclusionGroup.id)/members/`$ref" $legacySync.id -Quiet
        }
        $existingCaps = @(Get-GraphAll "$Base/identity/conditionalAccess/policies?`$select=id,displayName,conditions")
        foreach ($pol in (Get-RandomSome -Pool $existingCaps -Count 3)) {
            $ex = @($pol.conditions.users.excludeGroups) + $syncExclusionGroup.id
            Invoke-Graph PATCH "$Base/identity/conditionalAccess/policies/$($pol.id)" @{
                conditions = @{ users = @{ excludeGroups = @($ex | Where-Object { $_ } | Select-Object -Unique) } }
            } -Quiet | Out-Null
        }
    }
}

#endregion

#region ----- manager hierarchy -----------------------------------------------

if (-not $SkipManagers) {
    Write-Host "Building manager hierarchy"
    $ceo = Invoke-Graph POST "$Base/users" @{
        accountEnabled = $true; displayName = "Bill Gates"; passwordProfile = $pwProfile
        city = "Seattle"; state = "WA"; companyName = "Contoso"; country = "US"
        mailNickname = "BillGates"; postalCode = "99999"; streetAddress = "One Contoso Way"
        surname = "Gates"; givenName = "Bill"; userPrincipalName = "bg@$domain"
    } -Quiet
    if (-not $ceo) { $ceo = Invoke-Graph GET "$Base/users/bg@$domain" -Quiet }

    if (-not $ceo -or -not $ceo.id) {
        Write-Warning "  No CEO account - skipping manager hierarchy."
    }
    else {
        # re-query so departments set earlier are reflected
        $hierUsers = @(Get-GraphAll "$Base/users?`$filter=userType eq 'Member'&`$select=id,department&`$top=999" |
            Where-Object { $_.id })

        foreach ($dept in $Departments) {
            $members = @($hierUsers | Where-Object { $_.department -eq $dept -and $_.id -ne $ceo.id })
            if ($members.Count -eq 0) { continue }
            Set-Ref "$Base/users/$($members[0].id)/manager/`$ref" $ceo.id
            foreach ($u in ($members | Select-Object -Skip 1)) {
                Set-Ref "$Base/users/$($u.id)/manager/`$ref" $members[0].id
            }
        }
    }
}

#endregion

Write-Host "Done."
