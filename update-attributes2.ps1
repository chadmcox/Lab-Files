<#
    Populates onPremisesExtensionAttributes (extensionAttribute1-15) on
    CLOUD-ONLY Entra users.

    Why cloud-only: for a synced user (onPremisesSyncEnabled = true) on-prem AD
    is the source of authority and these are read-only in Graph. The script
    filters synced users out rather than generating a wall of 400s.

    Even some cloud-only users fail with:
      "Unable to update the specified properties for objects that have
       originated within an external service."
    That happens when the object was EVER synced, or when Exchange has taken
    authority. Those must be set via Exchange Online (Set-Mailbox
    -CustomAttribute1..15). The script tracks them and can emit a ready-to-run
    EXO fallback script with -ExoFallbackPath.

    Requires: Microsoft.Graph.Authentication
    Scope   : User.ReadWrite.All
    Role    : User Administrator or Global Administrator

    Examples:
      .\Set-EntraExtensionAttributes.ps1 -WhatIfGraph
      .\Set-EntraExtensionAttributes.ps1
      .\Set-EntraExtensionAttributes.ps1 -Only 1,4,5,14
      .\Set-EntraExtensionAttributes.ps1 -Clear
      .\Set-EntraExtensionAttributes.ps1 -LogPath .\ea-log.csv -ExoFallbackPath .\ea-exo-fallback.ps1
#>

[CmdletBinding()]
param(
    [int[]]$Only,                  # only touch these attribute numbers, e.g. -Only 1,4,14
    [switch]$Clear,                # null out 1-15 instead of populating
    [switch]$IncludeAdminAccounts, # by default ADMIN.* / Sync_* / breakglass are skipped
    [switch]$Overwrite,            # rewrite attributes that already have a value
    [int]$Seed = 49,
    [string]$LogPath,
    [string]$ExoFallbackPath,
    [switch]$WhatIfGraph
)

$ErrorActionPreference = "Stop"
$Base = "https://graph.microsoft.com/v1.0"

Connect-MgGraph -NoWelcome -Scopes @("User.ReadWrite.All","Directory.Read.All")

#region ---------------------------------------------------------- plumbing

function Invoke-Graph {
    param([ValidateSet("GET","POST","PATCH")]$Method, $Uri, $Body, [switch]$Quiet)
    if ($Uri -notmatch '^https://graph\.microsoft\.com/') { Write-Warning "Bad URI: $Uri"; return $null }
    for ($i = 1; $i -le 5; $i++) {
        try {
            $p = @{ Method = $Method; Uri = $Uri; OutputType = "PSObject"; ErrorAction = "Stop" }
            if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 20 -Compress); $p.ContentType = "application/json" }
            return Invoke-MgGraphRequest @p
        }
        catch {
            $code = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
            if ($code -in 429,503,504) { Start-Sleep -Seconds ([math]::Pow(2,$i)); continue }
            if (-not $Quiet) { Write-Warning "$Method $Uri [$code] $($_.ErrorDetails.Message)" }
            return $null
        }
    }
}

# streams results - no += array rewrites
function Get-GraphAll {
    param($Uri)
    while ($Uri) {
        $resp = Invoke-Graph GET $Uri
        if (-not $resp) { break }
        $resp.value
        $Uri = $resp.'@odata.nextLink'
    }
}

#endregion

#region ---------------------------------------------------------- value pools

# Shaped like values real orgs put in these fields, so dynamic group rules,
# sync filters, and CA device filters have something realistic to key on.
# Several pools are weighted (repeated entries) rather than uniform, so you get
# a believable skew instead of an even split.
$Ext = [ordered]@{
    1  = @{ Name = "CostCenter";      Values = @(1000..1400 | ForEach-Object { "CC-$_" }) }
    2  = @{ Name = "EmployeeType";    Values = @("FTE","FTE","FTE","FTE","Contractor","Intern","Vendor","Temp") }
    3  = @{ Name = "BusinessUnit";    Values = @("Corporate","Commercial","Manufacturing","Digital","Field Services","Shared Services","R&D") }
    4  = @{ Name = "Region";          Values = @("AMER","AMER","EMEA","APAC","LATAM") }
    5  = @{ Name = "SiteCode";        Values = @("SCL01","SFO01","RED01","NYC01","PHX01","AUS01","CHI01","ATL01","LON01","DUB01","MUC01","BLR01","HYD01","SIN01","TYO01","SYD01","TOR01","MEX01") }
    6  = @{ Name = "Building";        Values = @(1..40 | ForEach-Object { "BLDG-{0:D2}" -f $_ }) }
    7  = @{ Name = "MailRouting";     Values = @("O365","O365","O365","Hybrid","OnPrem") }
    8  = @{ Name = "LicenseGroup";    Values = @("E3","E3","E5","E5","F3","BusinessPremium") }
    9  = @{ Name = "MfaStatus";       Values = @("Enforced","Enforced","Enforced","Registered","NotRegistered","Exempt") }
    10 = @{ Name = "DataClass";       Values = @("Public","Internal","Internal","Confidential","Restricted") }
    11 = @{ Name = "HRSourceId";      Values = $null }   # generated: WD-######
    12 = @{ Name = "ManagerFlag";     Values = @("IC","IC","IC","IC","IC","People Manager","Senior Leader") }
    13 = @{ Name = "AccessTier";      Values = @("Tier2","Tier2","Tier2","Tier1","Tier0") }
    14 = @{ Name = "MigrationFlag";   Values = @("","","","","odmtmigrate","migrated","pending","excluded") }
    15 = @{ Name = "ProvisionSource"; Values = @("HR-Feed","HR-Feed","HR-Feed","Manual","IDM-Sync","Merger-Import") }
}

$targets = if ($Only) { @($Only | Where-Object { $_ -ge 1 -and $_ -le 15 } | Sort-Object -Unique) } else { @(1..15) }
if (-not $targets.Count) { throw "-Only produced no valid attribute numbers (must be 1-15)." }

#endregion

#region ---------------------------------------------------------- load users

Write-Host "Loading users"
$select = "id,displayName,userPrincipalName,userType,onPremisesSyncEnabled,onPremisesExtensionAttributes"
$all = @(Get-GraphAll "$Base/users?`$filter=userType eq 'Member'&`$select=$select&`$top=999")
Write-Host "  $($all.Count) member users returned"

if ($all.Count -and $all[0].id -isnot [string]) {
    throw "Collection collapsed - 'id' is $($all[0].id.GetType().Name), not a string. Check OutputType."
}

# synced users are read-only for these attributes - exclude, don't fight it
$synced = @($all | Where-Object { $_.onPremisesSyncEnabled -eq $true })
$users  = @($all | Where-Object { $_.onPremisesSyncEnabled -ne $true })

if (-not $IncludeAdminAccounts) {
    $users = @($users | Where-Object {
        $_.userPrincipalName -notlike "ADMIN.*" -and
        $_.userPrincipalName -notlike "Sync_*"  -and
        $_.userPrincipalName -notlike "breakglass@*"
    })
}

Write-Host "  $($synced.Count) synced (skipped - on-prem is source of authority)"
Write-Host "  $($users.Count) cloud-only users to process"
if ($users.Count -eq 0) { throw "No cloud-only users to update." }

#endregion

#region ---------------------------------------------------------- build + submit

$rand = [Random]::new($Seed)     # deterministic across reruns

function Get-RandomFrom {
    param([object[]]$Pool)
    if (-not $Pool -or $Pool.Count -eq 0) { return $null }
    return $Pool[$rand.Next(0, $Pool.Count)]
}

$log        = New-Object System.Collections.Generic.List[object]
$externalSvc = New-Object System.Collections.Generic.List[object]
$pending    = New-Object System.Collections.Generic.List[object]
$pendingMap = @{}                # batch request id -> user object

$ok = 0; $failed = 0; $skipped = 0

function Submit-Pending {
    if ($pending.Count -eq 0) { return }

    if ($WhatIfGraph) {
        Write-Host "  [WhatIf] would PATCH $($pending.Count) users" -ForegroundColor DarkGray
        $script:ok += $pending.Count
        $pending.Clear(); $pendingMap.Clear()
        return
    }

    $resp = Invoke-Graph POST "$Base/`$batch" @{ requests = $pending.ToArray() }
    if (-not $resp) {
        $script:failed += $pending.Count
        $pending.Clear(); $pendingMap.Clear()
        return
    }

    foreach ($r in @($resp.responses)) {
        if ($r.status -ge 200 -and $r.status -lt 300) { $script:ok++; continue }

        $script:failed++
        $msg = $r.body.error.message
        $u   = $pendingMap[$r.id]

        # the classic one: object originated in / was touched by an external service
        if ($msg -like "*originated within an external service*") {
            if ($u) { $externalSvc.Add($u) | Out-Null }
        }
        elseif ($script:failed -le 5) {
            Write-Warning "  [$($r.status)] $($u.userPrincipalName): $msg"
        }
    }

    $pending.Clear(); $pendingMap.Clear()
}

Write-Host "Patching extensionAttributes $($targets -join ',')"
foreach ($u in $users) {

    $ea = @{}
    $existing = $u.onPremisesExtensionAttributes

    foreach ($i in $targets) {
        $attr = "extensionAttribute$i"

        if ($Clear) { $ea[$attr] = $null; continue }

        # leave populated values alone unless told otherwise
        if (-not $Overwrite -and $existing -and $existing.$attr) { continue }

        $val = if ($i -eq 11) {
            "WD-{0:D6}" -f $rand.Next(100000, 999999)
        } else {
            Get-RandomFrom $Ext[$i].Values
        }

        # empty pool entry means "leave this one blank" - send null, not ""
        $ea[$attr] = if ([string]::IsNullOrEmpty($val)) { $null } else { $val }
    }

    if ($ea.Count -eq 0) { $skipped++; continue }

    $reqId = "$($pending.Count + 1)"
    $pendingMap[$reqId] = $u
    $pending.Add(@{
        id      = $reqId
        method  = "PATCH"
        url     = "/users/$($u.id)"
        body    = @{ onPremisesExtensionAttributes = $ea }
        headers = @{ "Content-Type" = "application/json" }
    }) | Out-Null

    if ($LogPath) {
        $row = [ordered]@{ userPrincipalName = $u.userPrincipalName; displayName = $u.displayName }
        foreach ($i in $targets) {
            $row["$($Ext[$i].Name)(EA$i)"] = $ea["extensionAttribute$i"]
        }
        $log.Add([pscustomobject]$row) | Out-Null
    }

    # $batch caps at 20 requests
    if ($pending.Count -ge 20) {
        Submit-Pending
        if (($ok + $failed) % 1000 -lt 20) { Write-Host "  $ok patched..." }
    }
}
Submit-Pending

#endregion

#region ---------------------------------------------------------- report

Write-Host ""
Write-Host ("-" * 56)
Write-Host "Cloud-only users : $($users.Count)"
Write-Host "Patched OK       : $ok"
Write-Host "Skipped          : $skipped   (already populated; use -Overwrite)"
Write-Host "Failed           : $failed"
Write-Host "  external svc   : $($externalSvc.Count)   (needs Exchange Online)"
Write-Host "Synced (skipped) : $($synced.Count)"
Write-Host ("-" * 56)

Write-Host "`nAttribute mapping:"
foreach ($i in $targets) { "  extensionAttribute{0,-3} {1}" -f $i, $Ext[$i].Name }

if ($LogPath -and $log.Count) {
    $log | Export-Csv -Path $LogPath -NoTypeInformation
    Write-Host "`nLog: $LogPath"
}

if ($externalSvc.Count) {
    Write-Host "`n$($externalSvc.Count) users rejected as 'originated within an external service'." -ForegroundColor Yellow
    Write-Host "Those were synced at some point, or Exchange holds authority." -ForegroundColor Yellow
    Write-Host "Set them with Set-Mailbox -CustomAttribute1..15 instead." -ForegroundColor Yellow

    if ($ExoFallbackPath) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("# EXO fallback - generated $(Get-Date -Format s)")
        [void]$sb.AppendLine("# CustomAttribute1-15 map 1:1 to extensionAttribute1-15")
        [void]$sb.AppendLine("Connect-ExchangeOnline")
        [void]$sb.AppendLine("")
        foreach ($u in $externalSvc) {
            $parts = foreach ($i in $targets) {
                $v = if ($i -eq 11) { "WD-{0:D6}" -f $rand.Next(100000,999999) } else { Get-RandomFrom $Ext[$i].Values }
                if (-not [string]::IsNullOrEmpty($v)) { "-CustomAttribute$i '$($v -replace "'","''")'" }
            }
            if ($parts) {
                [void]$sb.AppendLine("Set-Mailbox -Identity '$($u.userPrincipalName)' $($parts -join ' ')")
            }
        }
        $sb.ToString() | Set-Content -Path $ExoFallbackPath -Encoding UTF8
        Write-Host "EXO fallback script: $ExoFallbackPath" -ForegroundColor Cyan
    }
    else {
        Write-Host "Rerun with -ExoFallbackPath .\ea-exo.ps1 to generate the Set-Mailbox commands." -ForegroundColor Yellow
    }
}

# --- spot check + how to query them back ---
if (-not $WhatIfGraph -and $ok -gt 0) {
    Write-Host "`nSpot check:"
    $sample = @($users | Select-Object -First 3)
    foreach ($s in $sample) {
        $chk = Invoke-Graph GET "$Base/users/$($s.id)?`$select=displayName,onPremisesExtensionAttributes" -Quiet
        if ($chk) {
            Write-Host "  $($chk.displayName)"
            foreach ($i in $targets) {
                $v = $chk.onPremisesExtensionAttributes."extensionAttribute$i"
                if ($v) { "    EA{0,-3} {1,-16} {2}" -f $i, $Ext[$i].Name, $v }
            }
        }
    }

    Write-Host "`nTo filter on these, `$count=true AND ConsistencyLevel:eventual are BOTH required:" -ForegroundColor Cyan
    Write-Host '  Invoke-MgGraphRequest GET "https://graph.microsoft.com/v1.0/users?$count=true&$filter=onPremisesExtensionAttributes/extensionAttribute4 eq ''AMER''" -Headers @{ConsistencyLevel="eventual"} -OutputType PSObject'
}

#endregion
