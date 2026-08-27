<#
    Enriches existing tenant users from the lab CSV.

    Sets:
      jobTitle          - random, chosen from a pool matching the user's department
      employeeId        - empnumber from the CSV
      employeeHireDate  - random date in the past N years
      businessPhones    - phone from the CSV
      mail / otherMails - email from the CSV (rewritten to the tenant domain)
      preferredLanguage - derived from the CSV country
      mobilePhone       - optional, same number (-SetMobile)

    Matching: CSV email local-part  ->  tenant userPrincipalName local-part.
    Falls back to employeeId, then displayName.

    Requires: Microsoft.Graph.Authentication
    Requires: User Administrator or Global Administrator

    NOTE on employeeHireDate - it needs User-LifeCycleInfo.ReadWrite.All, which
    is a separate consent from User.ReadWrite.All. If that scope is missing the
    script drops the field and patches everything else.

    NOTE on mail - in many tenants 'mail' is read-only (owned by Exchange).
    The script tries it, and on failure writes otherMails instead.

    Examples:
      .\Set-EntraLabUserAttributes.ps1
      .\Set-EntraLabUserAttributes.ps1 -WhatIfGraph
      .\Set-EntraLabUserAttributes.ps1 -CsvUrl "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Users10k.txt"
#>

[CmdletBinding()]
param(
    [string]$CsvUrl   = "https://raw.githubusercontent.com/chadmcox/Lab-Files/refs/heads/master/Users.txt",
    [string]$CsvPath,                       # use a local file instead of the URL
    [int]$MaxYearsBack = 12,
    [switch]$SetMobile,
    [switch]$SkipMail,
    [switch]$WhatIfGraph
)

$ErrorActionPreference = "Stop"
$Base = "https://graph.microsoft.com/v1.0"

Connect-MgGraph -NoWelcome -Scopes @(
    "User.ReadWrite.All",
    "User-LifeCycleInfo.ReadWrite.All",     # employeeHireDate
    "Directory.ReadWrite.All"
)

$granted   = (Get-MgContext).Scopes
$canHire   = "User-LifeCycleInfo.ReadWrite.All" -in $granted
if (-not $canHire) { Write-Warning "User-LifeCycleInfo.ReadWrite.All not granted - employeeHireDate will be skipped." }

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

# streams - no array rewrites
function Get-GraphAll {
    param($Uri)
    while ($Uri) {
        $resp = Invoke-Graph GET $Uri
        if (-not $resp) { break }
        $resp.value
        $Uri = $resp.'@odata.nextLink'
    }
}

# 20 PATCHes per round trip instead of 20 round trips
function Submit-GraphBatch {
    param([object[]]$Requests)
    if (-not $Requests -or $Requests.Count -eq 0) { return @() }
    $resp = Invoke-Graph POST "$Base/`$batch" @{ requests = $Requests }
    if (-not $resp) { return @() }
    return @($resp.responses)
}

#endregion

#region ---------------------------------------------------------- reference data

# jobTitle pools keyed on the departments the seed script assigns
$TitlesByDept = @{
    "Logistics"                     = @("Logistics Coordinator","Transportation Analyst","Freight Specialist","Distribution Supervisor","Logistics Manager","Fleet Coordinator")
    "Information Technology"        = @("Systems Administrator","Infrastructure Engineer","IT Operations Manager","Platform Engineer","Cloud Architect","Directory Services Engineer","Endpoint Engineer")
    "IT Support"                    = @("Service Desk Technician","Desktop Support Analyst","Support Specialist","Help Desk Lead","Field Support Technician","Escalation Engineer")
    "Strategic Information Systems" = @("Enterprise Architect","Solutions Architect","Integration Engineer","Systems Analyst","Data Platform Engineer","Principal Architect")
    "Data Entry"                    = @("Data Entry Clerk","Records Specialist","Data Quality Analyst","Document Control Coordinator","Data Operations Associate")
    "Research and Development"      = @("Research Engineer","Software Engineer","Senior Software Engineer","Principal Engineer","Applied Scientist","Prototype Developer","R&D Program Manager")
    "Strategic Sourcing"            = @("Sourcing Manager","Category Manager","Supplier Relationship Manager","Sourcing Analyst","Contract Negotiator")
    "Purchasing"                    = @("Buyer","Senior Buyer","Procurement Specialist","Purchasing Coordinator","Vendor Manager","Procurement Analyst")
    "Operations"                    = @("Operations Analyst","Operations Manager","Process Improvement Lead","Site Operations Supervisor","Business Operations Manager")
    "Public Relations"              = @("Public Relations Specialist","Communications Manager","Media Relations Lead","PR Coordinator","Corporate Spokesperson")
    "Corporate Communications"      = @("Internal Communications Manager","Content Strategist","Executive Communications Lead","Communications Specialist","Editorial Manager")
    "Advertising"                   = @("Advertising Coordinator","Campaign Manager","Creative Director","Media Buyer","Copywriter")
    "Market Research"               = @("Market Research Analyst","Consumer Insights Manager","Survey Program Lead","Competitive Intelligence Analyst")
    "Strategic Marketing"           = @("Product Marketing Manager","Brand Manager","Go-To-Market Lead","Marketing Strategist","Partner Marketing Manager")
    "Customer service"              = @("Customer Service Representative","Customer Success Manager","Support Team Lead","Client Services Coordinator","Escalations Specialist")
    "Telesales"                     = @("Inside Sales Representative","Telesales Associate","Sales Development Rep","Lead Qualification Specialist")
    "Account Management"            = @("Account Manager","Senior Account Manager","Client Partner","Account Director","Renewals Manager")
    "Marketing"                     = @("Marketing Specialist","Digital Marketing Manager","Events Manager","Marketing Operations Analyst","SEO Specialist")
    "Sales"                         = @("Account Executive","Senior Account Executive","Sales Engineer","Regional Sales Manager","Territory Manager","Solution Specialist")
    "Payroll"                       = @("Payroll Specialist","Payroll Manager","Compensation Analyst","Payroll Operations Associate")
    "Recruitment"                   = @("Recruiter","Technical Recruiter","Talent Acquisition Partner","Sourcing Specialist","Recruiting Coordinator")
    "Training"                      = @("Training Specialist","Learning and Development Manager","Instructional Designer","Enablement Program Manager","Corporate Trainer")
    "Human Resource"                = @("HR Business Partner","HR Generalist","People Operations Manager","Employee Relations Specialist","Benefits Coordinator")
    "Accounting"                    = @("Staff Accountant","Senior Accountant","Accounts Payable Specialist","Accounts Receivable Analyst","Controller","Tax Analyst")
    "Financial"                     = @("Financial Analyst","Senior Financial Analyst","FP&A Manager","Treasury Analyst","Finance Business Partner")
}

# used when a user has no department, or one not in the map above
$GenericTitles = @("Business Analyst","Program Manager","Project Coordinator","Operations Specialist","Associate","Senior Associate","Consultant")

# preferredLanguage from the CSV country code
$LangByCountry = @{
    "US" = "en-US"; "CA" = "en-CA"; "GB" = "en-GB"; "IE" = "en-IE"
    "AU" = "en-AU"; "SG" = "en-SG"; "IN" = "en-IN"; "ZA" = "en-ZA"
    "MX" = "es-MX"; "BR" = "pt-BR"; "FR" = "fr-FR"; "DE" = "de-DE"
    "NL" = "nl-NL"; "PL" = "pl-PL"; "JP" = "ja-JP"; "AE" = "ar-AE"
}

#endregion

#region ---------------------------------------------------------- load CSV

Write-Host "Loading CSV"
$csv = if ($CsvPath) {
    Get-Content -Raw -Path $CsvPath | ConvertFrom-Csv
} else {
    (Invoke-WebRequest -UseBasicParsing $CsvUrl).Content | ConvertFrom-Csv
}
$csv = @($csv)
Write-Host "  $($csv.Count) CSV rows"
if ($csv.Count -eq 0) { throw "CSV is empty or failed to parse." }

# index by email local-part, employeeId, and display name
$byLocal = @{}; $byEmp = @{}; $byName = @{}
foreach ($row in $csv) {
    if ($row.email) {
        $local = ($row.email -split '@')[0].ToLower()
        if (-not $byLocal.ContainsKey($local)) { $byLocal[$local] = $row }
    }
    if ($row.empnumber -and -not $byEmp.ContainsKey($row.empnumber)) { $byEmp[$row.empnumber] = $row }
    if ($row.display) {
        $dn = $row.display.ToLower()
        if (-not $byName.ContainsKey($dn)) { $byName[$dn] = $row }
    }
}

#endregion

#region ---------------------------------------------------------- load tenant users

Write-Host "Loading tenant users"
$select = "id,displayName,userPrincipalName,department,employeeId,jobTitle,mail,businessPhones,preferredLanguage,userType"
$users  = @(Get-GraphAll "$Base/users?`$filter=userType eq 'Member'&`$select=$select&`$top=999" |
    Where-Object { $_.id -and $_.userPrincipalName -notlike "ADMIN.*" -and $_.userPrincipalName -notlike "Sync_*" })
Write-Host "  $($users.Count) member users"
if ($users.Count -lt 2) { throw "Only $($users.Count) users returned - check permissions." }

$tenantDomain = (($users | Select-Object -First 1).userPrincipalName -split '@')[1]
Write-Host "  tenant domain: $tenantDomain"

#endregion

#region ---------------------------------------------------------- build + submit patches

$rand    = [Random]::new(49)          # deterministic across reruns
$today   = Get-Date
$earliest = $today.AddYears(-$MaxYearsBack)
$spanDays = [int]($today.AddDays(-30) - $earliest).TotalDays

$matched = 0; $unmatched = 0; $ok = 0; $failed = 0
$mailBlocked = $false
$pending = New-Object System.Collections.Generic.List[object]
$pendingIds = New-Object System.Collections.Generic.List[string]

function Flush-Batch {
    if ($pending.Count -eq 0) { return }
    if ($WhatIfGraph) {
        Write-Host "  [WhatIf] would PATCH $($pending.Count) users" -ForegroundColor DarkGray
        $script:ok += $pending.Count
        $pending.Clear(); $pendingIds.Clear()
        return
    }
    foreach ($r in (Submit-GraphBatch -Requests $pending.ToArray())) {
        if ($r.status -ge 200 -and $r.status -lt 300) { $script:ok++ }
        else {
            $script:failed++
            $msg = $r.body.error.message
            if ($msg -like "*mail*" -and $msg -like "*read-only*") { $script:mailBlocked = $true }
            if ($script:failed -le 5) { Write-Warning "  [$($r.status)] $msg" }
        }
    }
    $pending.Clear(); $pendingIds.Clear()
}

Write-Host "Patching users"
foreach ($u in $users) {

    # --- match to a CSV row ---
    $local = ($u.userPrincipalName -split '@')[0].ToLower()
    $row = $null
    if ($byLocal.ContainsKey($local))                       { $row = $byLocal[$local] }
    elseif ($u.employeeId -and $byEmp.ContainsKey($u.employeeId)) { $row = $byEmp[$u.employeeId] }
    elseif ($u.displayName -and $byName.ContainsKey($u.displayName.ToLower())) { $row = $byName[$u.displayName.ToLower()] }

    if (-not $row) { $unmatched++; continue }
    $matched++

    # --- job title from the user's CURRENT department ---
    $pool = if ($u.department -and $TitlesByDept.ContainsKey($u.department)) { $TitlesByDept[$u.department] } else { $GenericTitles }
    $body = @{ jobTitle = $pool[$rand.Next(0, $pool.Count)] }

    # --- employeeId ---
    if ($row.empnumber) { $body.employeeId = [string]$row.empnumber }

    # --- hire date: random day in the window, midnight UTC ---
    if ($canHire) {
        $body.employeeHireDate = $earliest.AddDays($rand.Next(0, $spanDays)).ToString("yyyy-MM-ddT00:00:00Z")
    }

    # --- phone ---
    if ($row.phone) {
        $digits = ($row.phone -replace '\D','')
        $pretty = if ($digits.Length -eq 10) { "+1 {0}-{1}-{2}" -f $digits.Substring(0,3), $digits.Substring(3,3), $digits.Substring(6,4) } else { $row.phone }
        $body.businessPhones = @($pretty)
        if ($SetMobile) { $body.mobilePhone = $pretty }
    }

    # --- mail, rewritten onto the tenant domain ---
    if (-not $SkipMail -and $row.email) {
        $addr = ($row.email -split '@')[0] + "@" + $tenantDomain
        if ($mailBlocked) { $body.otherMails = @($addr) } else { $body.mail = $addr }
    }

    # --- preferred language ---
    if ($row.country -and $LangByCountry.ContainsKey($row.country)) {
        $body.preferredLanguage = $LangByCountry[$row.country]
    } else {
        $body.preferredLanguage = "en-US"
    }

    $pending.Add(@{
        id      = "$($pending.Count + 1)"
        method  = "PATCH"
        url     = "/users/$($u.id)"
        body    = $body
        headers = @{ "Content-Type" = "application/json" }
    }) | Out-Null

    if ($pending.Count -ge 20) {
        Flush-Batch
        if (($ok + $failed) % 1000 -lt 20) { Write-Host "  $ok patched..." }
    }
}
Flush-Batch

#endregion

Write-Host ""
Write-Host ("-" * 52)
Write-Host "CSV rows        : $($csv.Count)"
Write-Host "Tenant users    : $($users.Count)"
Write-Host "Matched         : $matched"
Write-Host "Unmatched       : $unmatched"
Write-Host "Patched OK      : $ok"
Write-Host "Failed          : $failed"
Write-Host ("-" * 52)

if ($mailBlocked) {
    Write-Host "'mail' is read-only in this tenant - otherMails was used instead." -ForegroundColor Yellow
    Write-Host "Rerun to apply otherMails to the users patched before the switch." -ForegroundColor Yellow
}
if ($unmatched -gt 0) {
    Write-Host "Unmatched users had no CSV row by UPN local-part, employeeId, or displayName." -ForegroundColor Yellow
}

# spot check
if (-not $WhatIfGraph -and $ok -gt 0) {
    Write-Host "`nSpot check:"
    Get-GraphAll "$Base/users?`$filter=userType eq 'Member'&`$select=displayName,department,jobTitle,employeeId,employeeHireDate,businessPhones,preferredLanguage&`$top=5" |
        Select-Object -First 5 |
        Format-List displayName, department, jobTitle, employeeId, employeeHireDate, businessPhones, preferredLanguage
}
