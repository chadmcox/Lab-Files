#Requires -module AzureADPreview,MSOnline
<#

This will set up a lot of things on an azure ad tenant
make sure to log on with a global admin account from that tenant
you will need to connect to both msol and azuread


enable your tenant and enable p2 license trial or ems E5
#>

connect-azuread
connect-msolservice
write-host "Set Password Profile"
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = "Going to rush Area 51!"
$domain = (get-azureaddomain | where IsDefault -eq $true).name

write-host "Creating a binch of Users"
$users = (invoke-webrequest -uri "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Users.txt").content
$users.Split([Environment]::NewLine) | foreach{
    write-host "Creating User $((($_.split(","))[3]).replace('"',''))"
    $spat_params = @{AccountEnabled = $true
        DisplayName = (($_.split(","))[3]).replace('"','')
        PasswordProfile = $PasswordProfile
        City = (($_.split(","))[7]).replace('"','')
        CompanyName = "Contoso"
        Country = (($_.split(","))[10]).replace('"','')
        MailNickName = (($_.split(","))[0]).replace('"','')
        PostalCode = (($_.split(","))[9]).replace('"','')
        Streetaddress = (($_.split(","))[6]).replace('"','')
        surname = (($_.split(","))[2]).replace('"','')
        givenname = (($_.split(","))[1]).replace('"','')
        UserPrincipalName = ((($_.split(","))[4]).replace("contoso.com",$domain)).replace('"','')
        }
    new-azureaduser @spat_params
 }

 write-host "Getting All Users for Later"
 $aadusers = get-azureaduser -all $true

 write-host "Updating all users departments"
$Departments = "Logistics","Information Technology","IT Support","Strategic Information Systems","Data Entry","Research and Development","Strategic Sourcing","Purchasing","Strategic Sourcing","Operations","Public Relations","Corporate Communications","Advertising","Market Research","Strategic Marketing","Customer service","Telesales","Account Management","Marketing","Sales","Payroll","Recruitment","Training","Human Resource","Accounting","Financial"
$aadusers | foreach{
    
    Get-AzureADUser -objectid $($_.userprincipalname) | Set-AzureADUser -Department $($departments | get-random)
}

 write-host "Updating all users usage location"
#assign usage location
$aadusers | select -First 900 | Set-AzureADUser -usagelocation "US" -erroraction silentlycontinue

write-host "Creating Dynamic Groups by department"
#create Department Groups
#needs p1 or p2 license
$Departments | foreach{
    $group = $(($_).replace(" ",""))
    New-AzureADMSGroup -DisplayName $($_) `
        -Description "Dynamic group for $($_)" `
        -MailEnabled $False -MailNickName $group `
        -SecurityEnabled $True `
        -GroupTypes "DynamicMembership" `
        -MembershipRule "(user.department -contains ""$($_)"")" `
        -MembershipRuleProcessingState "On"
}

write-host "Creating Security Groups"
#create Several Groups
1..50 | foreach{
    New-AzureADGroup -DisplayName "Security Group $($_)" `
        -MailEnabled $False `
        -MailNickname "SecurityGroup$($_)" `
        -securityenabled $true
}

write-host "create 15 Admin Accounts"
1..15 | foreach{
    $newaadadmin = $aadusers | get-random
    New-AzureADUser -DisplayName "Admin $($newaadadmin.displayname)" `
        -PasswordProfile $PasswordProfile `
        -UserPrincipalName "ADMIN.$($newaadadmin.UserPrincipalName)" `
        -AccountEnabled $true `
        -MailNickName "admin$($newaadadmin.MailNickName)"
}

write-host "Disabling Admin Account Password Expiration"
#get all the admin accounts created
$aadadminusers = Get-AzureADUser -SearchString "Admin"
$aadadminusers | Set-AzureADUser -PasswordPolicies DisablePasswordExpiration

write-host "Disabling 5 Random User Accounts"
1..5 | foreach {
    $aadusers | get-random | set-azureaduser -AccountEnabled $false
}
write-host "enable all administrator directory roles"
#enable all the role templates
Get-AzureADDirectoryRoleTemplate | where {$_.Displayname -like "*Administrator" -or $_.Displayname -like "*Reader"} | foreach{Enable-AzureADDirectoryRole -RoleTemplateId $_.ObjectId}
write-host "randomly placing admin accounts in directory roles"
Get-AzureADDirectoryRole -PipelineVariable role | foreach{
    1..$(get-random -Minimum 3 -Maximum 15) | foreach{
     Add-AzureADDirectoryRoleMember -ObjectId $role.objectid -RefObjectId $(($aadadminusers | get-random).ObjectId) -erroraction silentlycontinue
    }
}
Write-host "Creating Guest Users"
$guestusers = (invoke-webrequest -uri "https://raw.githubusercontent.com/chadmcox/Lab-Files/master/Guest.txt").content
foreach($g in $guestusers.Split([Environment]::NewLine)){
    New-AzureADMSInvitation -InvitedUserEmailAddress "$g" -InviteRedirectURL https://myapps.azure.com -SendInvitationMessage ($true,$false | get-random)
}

$guests = Get-AzureADUser -Filter "UserType eq 'Guest'" -all $true
Write-host "Activating Application Administrator"
Get-AzureADDirectoryRoleTemplate | where {$_.Displayname -eq "Application Administrator"} | foreach{Enable-AzureADDirectoryRole -RoleTemplateId $_.ObjectId}
Get-AzureADDirectoryRole | where {$_.Displayname -eq "Application Administrator"} -OutVariable role
Add-AzureADDirectoryRoleMember -ObjectId $role.objectid -RefObjectId $(($guests | get-random).ObjectId) -erroraction silentlycontinue
Write-host "Randomly adding Guest to roles"
Get-AzureADDirectoryRole -PipelineVariable role | foreach{
    0..$(get-random -Minimum 0 -Maximum 1) | foreach{
        Add-AzureADDirectoryRoleMember -ObjectId $role.objectid -RefObjectId $(($guests | get-random).ObjectId) -erroraction silentlycontinue
    }
}

#Randomize group memberships
write-host "Collecting all Groups"
$aadgroups = get-azureadgroup -all $true
write-host "creating unified group lifecycle policy"
New-AzureADMSGroupLifecyclePolicy -GroupLifetimeInDays 99 -ManagedGroupTypes All -AlternateNotificationEmails "bob@contoso.com"
write-host "Randomly adding users to group memberships"
$aadgroups | foreach{$aadgid = $_.objectid
    1..$(get-random -Minimum 10 -Maximum 400) | foreach{
    Add-AzureADGroupMember -objectid $aadgid -refobjectid $(($aadusers | get-random).ObjectId) -erroraction silentlycontinue
    }
}
write-host "Randomly adding users as group owners"
1..30 | foreach{
    Add-AzureADGroupOwner -objectid $(($aadgroups | get-random).ObjectId) -refobjectid $(($aadusers | get-random).ObjectId) -erroraction silentlycontinue
}
write-host "Randomly removing all users from membership"
1..3 | foreach{
    $aadrgroup = $aadgroups | get-random
    get-azureadgroupmember -objectid $aadrgroup.objectid -pipelinevariable | foreach{
        remove-azureadgroupmember -objectid $aadrgroup.objectid -refobjectid 
    }
}
write-host "Setting Password policy stuff"
$Template = Get-AzureADDirectorySettingTemplate -Id 5cf42378-d67d-4f36-ba46-e8b86229381d
$Setting = $template.CreateDirectorySetting()
$Setting.values
$setting["LockoutThreshold"] = 15
$setting["LockoutDurationInSeconds"] = 30
New-AzureADDirectorySetting -DirectorySetting $setting
write-host "Setting homerealmdiscovery"
New-AzureADPolicy -Definition @("{`"HomeRealmDiscoveryPolicy`":        {`"AccelerateToFederatedDomain`":true}}") -DisplayName BasicAutoAccelerationPolicy -Type HomeRealmDiscoveryPolicy 
write-host "creating unused claim policy"
New-AzureADPolicy -Definition @('{"ClaimsMappingPolicy":{"Version":1,"IncludeBasicClaimSet":"true", "ClaimsSchema":[{"Source":"user","ID":"extensionattribute1"},{"Source":"transformation","ID":"DataJoin","TransformationId":"JoinTheData","JwtClaimType":"JoinedData"}],"ClaimsTransformations":[{"ID":"JoinTheData","TransformationMethod":"Join","InputClaims":[{"ClaimTypeReferenceId":"extensionattribute1","TransformationClaimType":"string1"}], "InputParameters": [{"ID":"string2","Value":"sandbox"},{"ID":"separator","Value":"."}],"OutputClaims":[{"ClaimTypeReferenceId":"DataJoin","TransformationClaimType":"outputClaim"}]}]}}') -DisplayName "TransformClaimsExample" -Type "ClaimsMappingPolicy"

write-host "Setting unified group stuff"
$template = Get-AzureADDirectorySettingTemplate | where-object {$_.displayname -eq “Group.Unified”}
$setting = $template.CreateDirectorySetting()
New-AzureADDirectorySetting -DirectorySetting $setting
$settings = Get-AzureADDirectorySetting | where-object {$_.displayname -eq “Group.Unified”}
$settings["AllowToAddGuests"] = "False"
$settings["AllowGuestsToAccessGroups"] = "True"
Set-AzureADDirectorySetting -Id $settings.Id -DirectorySetting $settings

write-host "Creating 10 applications/sp with 1 year pwd"
1..10 | foreach{
    $myApp = New-AzureADApplication -DisplayName "Demo App $($_)" -IdentifierUris "https://localhost:$($_)"
    $mySP = New-AzureADServicePrincipal -AppId $myApp.AppId

    $spCredParameters = @{
      StartDate = [DateTime]::UtcNow
      EndDate = [DateTime]::UtcNow.AddYears(1)
      Value = 'MySuperAwesomePasswordIs3373'
      ObjectId = $mySP.ObjectID
    }

    New-AzureADServicePrincipalPasswordCredential @spCredParameters
}
write-host "Creating 4 applications/sp with 20 day pwd"
16..20 | foreach{
    $myApp = New-AzureADApplication -DisplayName "Demo App $($_)" -IdentifierUris "https://localhost:$($_)"
    $mySP = New-AzureADServicePrincipal -AppId $myApp.AppId

    $spCredParameters = @{
      StartDate = [DateTime]::UtcNow
      EndDate = [DateTime]::UtcNow.Adddays(20)
      Value = 'MySuperAwesomePasswordIs3373'
      ObjectId = $mySP.ObjectID
    }

    New-AzureADServicePrincipalPasswordCredential @spCredParameters
}
write-host "adding 5 sp to random users as owner"
Get-AzureADServicePrincipal | get-random | select -First 5 | Add-AzureADServicePrincipalOwner -refobjectid $(($aadusers | get-random).objectid)

$spat_params = @{AccountEnabled = $true
        DisplayName = "Bill Gates"
        PasswordProfile = $PasswordProfile
        City = "Seattle"
       State = "WA"
        CompanyName = "Contoso"
        Country = "US"
        MailNickName = "BillGates"
        PostalCode = "99999"
        Streetaddress = "One Contoso Way"
        surname = "Gates"
        givenname = "Bill"
        UserPrincipalName = "bg@$domain"
        }
new-azureaduser @spat_params
$ceo = get-azureaduser -ObjectId "bg@$domain"

foreach($dep in $departments){
    $i = 1
    foreach($aadu in $aadusers | where {$_.department -eq $dep}){
        
        if($i -eq 1){
            $man = $aadu
            write-host "Setting Manager $($ceo.displayname) on $($man.displayname)"
            
            Set-AzureADUserManager -ObjectId $man.objectid -RefObjectId $ceo.objectid
            $i = 2
        }else{
            write-host "Setting Manager $($man.displayname) on $($aadu.displayname)"
            Set-AzureADUserManager -ObjectId $aadu.objectid -RefObjectId $man.objectid
        }
    }
}

#Connect-MsolService
#creates legacy service principal
write-host "creating 5 legacy sp with password"
1..5 | foreach {
    new-msolserviceprincipal -DisplayName "Legacy SP $($_)" -Type Password -Value 'Password1'
}
write-host "creating 15 legacy sp with no password"
100..115 | foreach {
    new-msolserviceprincipal -DisplayName "Legacy SP $($_)"
}
write-host "add legacy sp to "
$azureadsps = Get-AzureADServicePrincipal | where serviceprincipaltype -eq "legacy"
1..7| foreach{
    Add-MsolRoleMember -RoleObjectId $((get-msolrole | get-random).objectid) -RoleMemberType ServicePrincipal -RoleMemberObjectId $(($azureadsps | get-random).objectid)
}

$auth = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$auth.RelyingParty = "*"
$auth.State = "Enabled"
$auth.RememberDevicesNotIssuedBefore = (Get-Date)
write-host "Enabling MFA on 125 Users"
1..125 | foreach{
    Set-MsolUser -UserPrincipalName $(($aadusers | get-random).UserPrincipalName) -StrongAuthenticationRequirements $auth
}
write-host "Enabling MFA on 5 Admin users"
1..5 | foreach{
    Set-MsolUser -UserPrincipalName $(($aadadminusers | get-random).UserPrincipalName) -StrongAuthenticationRequirements $auth
}
write-host "Setting Contact information"
Set-MsolCompanyContactInformation -MarketingNotificationEmails "bob@contoso.com,tom@contoso.com"

Set-MsolCompanySecurityComplianceContactInformation -SecurityComplianceNotificationPhones "555-555-5555" -SecurityComplianceNotificationEmails "bob@contoso.com" 
write-host "changing company settings"
Set-MsolCompanySettings -AllowEmailVerifiedUsers $true -UsersPermissionToCreateLOBAppsEnabled $false -UsersPermissionToUserConsentToAppEnabled $true
write-host "changing password policy"
Set-MsolPasswordPolicy -DomainName $domain -NotificationDays 45 -ValidityPeriod 365
