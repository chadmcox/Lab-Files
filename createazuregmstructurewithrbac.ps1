$lobs = "Logistics","Information Technology","IT Support","Strategic Information Systems","Data Entry","Research and Development","Strategic Sourcing","Purchasing","Operations","Public Relations","Corporate Communications","Advertising","Market Research","Strategic Marketing","Customer service","Telesales","Account Management","Marketing","Sales","Payroll","Recruitment","Training","Human Resource","Accounting","Financial"
New-AzManagementGroup -GroupName "VisualStudios" -ParentId "/providers/Microsoft.Management/managementGroups/$((Get-AzureADTenantDetail).objectid)"
New-AzManagementGroup -GroupName "General" -ParentId "/providers/Microsoft.Management/managementGroups/$((Get-AzureADTenantDetail).objectid)" -OutVariable itmg
get-AzManagementGroup -GroupName "General" -OutVariable itmg
New-AzManagementGroup -GroupName "Regulated" -ParentId "/providers/Microsoft.Management/managementGroups/$((Get-AzureADTenantDetail).objectid)"
New-AzManagementGroup -GroupName "DMZ" -ParentId "/providers/Microsoft.Management/managementGroups/$((Get-AzureADTenantDetail).objectid)"
#get-azureadmsgroup -SearchString "Azure" -all $true | foreach{Remove-AzureADGroup -objectid $_.id}
New-AzureADMSGroup -DisplayName "Azure IT Support" `
        -MailEnabled $False -MailNickName "$name-Azure" `
        -SecurityEnabled $True -OutVariable itg
start-sleep -Seconds 5
get-azureadmsgroup -filter "displayname eq 'Azure IT Support'" -OutVariable itg

#Get-AzRoleDefinition -Scope $itmg.id -Name "contributor" -OutVariable itcrd
New-AzRoleAssignment -ObjectId $itg.id -Scope $itmg.id -RoleDefinitionName "Contributor"
#Get-AzRoleAssignment -Scope $itmg.id
$users = Get-AzureADUser -Filter "userType eq 'member' and AccountEnabled eq true" -all $true | where {$_.Dirsyncenabled -eq $true} 
foreach($lob in $lobs){
    $name = $lob -replace(" ","")
    $parentmg = $itmg.id
    
    try{New-AzureADMSGroup -DisplayName "Azure $lob - Prod Owner" `
        -MailEnabled $False -MailNickName "$($name)ProdOwner" `
        -SecurityEnabled $True }catch{}
    get-AzureADMSGroup -filter "DisplayName eq 'Azure $lob - Prod Owner'" -OutVariable prod_owner | select -First 1

    try{New-AzureADMSGroup -DisplayName "Azure $lob - Prod Contributor" `
        -MailEnabled $False -MailNickName "$($name)ProdContributor" `
        -SecurityEnabled $True }catch{}

    get-AzureADMSGroup -filter "DisplayName eq 'Azure $lob - Prod Contributor'" -OutVariable prod_con  | select -First 1

    try{New-AzureADMSGroup -DisplayName "Azure $lob - Reader" `
        -MailEnabled $False -MailNickName "$($name)ProdReader" `
        -SecurityEnabled $True}catch{}

    get-AzureADMSGroup -filter "DisplayName eq 'Azure $lob - Reader'" -OutVariable prod_read  | select -First 1

    try{New-AzureADMSGroup -DisplayName "Azure $lob - NonProd Owner" `
        -MailEnabled $False -MailNickName "$($name)NonProdowner" `
        -SecurityEnabled $True}catch{} 

    get-AzureADMSGroup -filter "DisplayName eq 'Azure $lob - NonProd Owner'" -OutVariable nonprod  | select -First 1
    try{New-AzManagementGroup -GroupName $name -ParentId $parentmg }catch{}
    get-AzManagementGroup -GroupName $name -OutVariable lobmg
    try{New-AzManagementGroup -GroupName "$($name)Prod" -ParentId $lobmg.id }catch{}
    get-AzManagementGroup -GroupName "$($name)Prod" -OutVariable lobprod
    try{New-AzManagementGroup -GroupName "$($name)NonProd" -ParentId $lobmg.id }catch{}
    get-AzManagementGroup -GroupName "$($name)NonProd" -OutVariable lobnonprod
    start-sleep -Seconds 5
    try{New-AzRoleAssignment -ObjectId $prod_read.id  -Scope $lobmg.id -RoleDefinitionName "Reader"}catch{}

    if((1..100 | get-random) -gt 60){
        try{New-AzRoleAssignment -ObjectId ($users | get-random).objectid  -Scope $lobmg.id -RoleDefinitionName "Owner"}catch{}
    }
    try{New-AzRoleAssignment -ObjectId $prod_owner.id -Scope $lobprod.id -RoleDefinitionName "Owner"}catch{}
    try{New-AzRoleAssignment -ObjectId $prod_con.id -Scope $lobprod.id -RoleDefinitionName "Contributor"}catch{}

    
    try{New-AzRoleAssignment -ObjectId $nonprod.id -Scope $lobnonprod.id -RoleDefinitionName "Owner"}catch{}
}


get-azureadmsgroup -SearchString "Azure" -all $true -pv ag | foreach{
    1..2 | foreach{
        Add-AzureADGroupMember -ObjectId $ag.id   -RefObjectId $(($users | get-random).ObjectId)
    }
}
