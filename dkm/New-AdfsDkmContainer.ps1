[CmdletBinding()] 
param (
   [Parameter(Mandatory=$True)]
   [string]$SvcAcct,
   [Parameter(Mandatory=$True)]
   [string]$LocalAdminAcct
)

function Grant-ReadAccess {
    Param([string]$Account,[string]$DN)
    push-location ad:

    if ($Account.EndsWith("$"))
    {
        $userNameSplit = $SvcAcct.Split("\");
        $strSID = (Get-ADServiceAccount -Identity $userNameSplit[1]).SID
    }
    else
    {
        $objUser = New-Object System.Security.Principal.NTAccount($Account)
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    }

    [System.DirectoryServices.ActiveDirectorySecurityInheritance]$adSecInEnum = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $strSID,"GenericRead","Allow",$adSecInEnum

    $acl = get-acl -Path $DN -ErrorAction Stop

    $acl.AddAccessRule($ace1)

    set-acl -Path $DN -AclObject $acl -ErrorAction Stop

    pop-location

    Write-Verbose ("Granting $Account read access to $DN")
}

function Grant-FullAccess {
    Param([string]$Account,[string]$DN)

    push-location ad:

    if ($Account.EndsWith("$"))
    {
        $userNameSplit = $SvcAcct.Split("\");
        $strSID = (Get-ADServiceAccount -Identity $userNameSplit[1]).SID
    }
    else
    {
        $objUser = New-Object System.Security.Principal.NTAccount($Account)
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    }

    [System.DirectoryServices.ActiveDirectorySecurityInheritance]$adSecInEnum = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $strSID,"GenericRead","Allow",$adSecInEnum
    $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $strSID,"CreateChild","Allow",$adSecInEnum
    $ace3 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $strSID,"WriteOwner","Allow",$adSecInEnum
    $ace4 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $strSID,"DeleteTree","Allow",$adSecInEnum
    $ace5 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $strSID,"WriteDacl","Allow",$adSecInEnum
    $ace6 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $strSID,"WriteProperty","Allow",$adSecInEnum

    $acl = get-acl -Path $DN -ErrorAction Stop

    $acl.AddAccessRule($ace1)
    $acl.AddAccessRule($ace2)
    $acl.AddAccessRule($ace3)
    $acl.AddAccessRule($ace4)
    $acl.AddAccessRule($ace5)
    $acl.AddAccessRule($ace6)

    $acl.SetOwner($strSID)

    set-acl -Path $DN -AclObject $acl -ErrorAction Stop

    pop-location

    Write-Verbose ("Granting $Account full access to $DN")

}

$userNameSplit = $LocalAdminAcct.Split("\");
if ($userNameSplit.Length -ne 2)
{
    throw "Specify LocalAdminAcct in 'domain\username' format"
}

$userNameSplit = $SvcAcct.Split("\");
if ($userNameSplit.Length -ne 2)
{
    throw "Specify SvcAcct in 'domain\username' format"
}

# The AD module is required
import-module ActiveDirectory -ErrorAction Stop 4>$null

# The OU Name is a randomly generated Guid
[string]$guid = [Guid]::NewGuid()
Write-Verbose ("Generated DKM container name $guid")

$ouName = $guid
$microsoftContainer = "CN=Microsoft,CN=Program Data," + (Get-ADDomain).DistinguishedName
$adfsContainer = "CN=ADFS," + $microsoftContainer
$dkmContainer = "CN=" + $ouName + "," + $adfsContainer

#check if ADFS root container already exists,  if not create it.
if ((Get-ADObject -Filter {distinguishedName -eq $adfsContainer}) -eq $null)
{
    Write-Verbose ("Creating ADFS root container " + $adfsContainer)
    New-ADObject -Name "ADFS" -Type Container -Path $microsoftContainer -ErrorAction Stop
}
else
{
    Write-Verbose ("$adfsContainer already exists")
}

New-ADObject -Name $ouName -Type Container -Path $adfsContainer -ErrorAction Stop

Write-Verbose ("Creating generated DKM container: " + $dkmContainer)

Grant-ReadAccess -Account $LocalAdminAcct -DN $adfsContainer
Grant-FullAccess -Account $LocalAdminAcct -DN $dkmContainer
Grant-FullAccess -Account $SvcAcct -DN $dkmContainer

$adminConfig = @{"DKMContainerDn"=$dkmContainer}

write-output $adminConfig