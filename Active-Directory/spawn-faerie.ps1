#Title: Spawn Faerie
# Purpose: Create a vulnerable active directory system that can be used to test against most active directory attacks. Script was modified to build an AD box for the red team village CTF!
# Orginial Credit: @WazeHell https://github.com/WazeHell/vulnerable-AD

# Tested on Windows Server 2016

# Instructions: 



# Base Configuration
$Global:HumansNames = @('Andy', 'Cyan', 'Christopher', 'Craig', 'Eddie', 'Jason', 'Simon', 'Matsuko', 'Helen', 'Tiffany', 'Joe', 'Margaret', 'Billy', 'Jade', 'Lisa', 'Yujiro', 'Gabrielle', 'Simon', 'Phil', 'Max', 'Earl', 'Susan', 'Sara', 'Richard', 'Brock', 'Malebogia', 'Merrick', 'Solomon');
$Global:BadPasswords = @('martindale2020', 'Merio131', 'Santiago1411', 'Svastic11', 'Visuar2626', 'Edusilden2006', 'JuanManuel494', 'JuanManuel494', 'Cris1053', 'Moreno2950', 'Adm2309', 'Vis0165', 'Blue2020$', 'Roman2020', 'BBL4NC41', 'Tito3110', 'fernando2020', 'diego2020', 'Spyre217!', 'Pgmgp128!', 'Fx55t8Ya', 'moneYmor3', 'P@ssw0rdga'); 
$Global:HighGroups = @('Office Admin','IT Admins','Executives');
$Global:MidGroups = @('Senior management','Project management');
$Global:NormalGroups = @('marketing','sales','accounting');
$Global:BadACL = @('GenericAll','GenericWrite','WriteOwner','WriteDACL','Self','WriteProperty');
$Global:ServicesAccountsAndSPNs = @('mssql_svc,mssqlserver','http_svc,httpserver','exchange_svc,exserver');
$Global:CreatedUsers = @();
$Global:AllObjects = @();
$Global:Domain = "";
#Strings 
$Global:Spacing = "`t"
$Global:PlusLine = "`t[+]"
$Global:ErrorLine = "`t[-]"
$Global:InfoLine = "`t[*]"
function Write-Good { param( $String ) Write-Host $Global:PlusLine  $String -ForegroundColor 'Green'}
function Write-Bad  { param( $String ) Write-Host $Global:ErrorLine $String -ForegroundColor 'red'  }
function Write-Info { param( $String ) Write-Host $Global:InfoLine $String -ForegroundColor 'gray' }
function ShowBanner {
    $banner  = @()
    $banner+= $Global:Spacing + ''
$banner+= $Global:Spacing + '@@@@@@@@   @@@@@@   @@@@@@@@  @@@@@@@   @@@  @@@@@@@@'
$banner+= $Global:Spacing + '@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@  @@@@@@@@'
$banner+= $Global:Spacing + '@@!       @@!  @@@  @@!       @@!  @@@  @@!  @@!'
$banner+= $Global:Spacing + '!@!       !@!  @!@  !@!       !@!  @!@  !@!  !@!'
$banner+= $Global:Spacing + '@!!!:!    @!@!@!@!  @!!!:!    @!@!!@!   !!@  @!!!:!'
$banner+= $Global:Spacing + '!!!!!:    !!!@!!!!  !!!!!:    !!@!@!    !!!  !!!!!:'
$banner+= $Global:Spacing + '!!:       !!:  !!!  !!:       !!: :!!   !!:  !!:'
$banner+= $Global:Spacing + ':!:       :!:  !:!  :!:       :!:  !:!  :!:  :!:'
 $banner+= $Global:Spacing +'::       ::   :::   :: ::::  ::   :::   ::   :: ::::'
 $banner+= $Global:Spacing + ':         :   : :  : :: ::    :   : :  :    : :: ::'
    $banner+= $Global:Spacing + ''                                                  
    $banner+= $Global:Spacing + 'Modified by Tj Null'
    $banner | foreach-object {
        Write-Host $_ -ForegroundColor (Get-Random -Input @('red','Cyan','Yellow','gray','white'))
    }                             
}

function Faerie-GetRandom {
   Param(
     [array]$InputList
   )
   return Get-Random -InputObject $InputList
}
function Faerie-AddADGroup {
    Param(
        [array]$GroupList
    )
    foreach ($group in $GroupList) {
        Write-Info "Creating $group Group"
        Try { New-ADGroup -name $group -GroupScope Global } Catch {}
        for ($i=1; $i -le (Get-Random -Maximum 20); $i=$i+1 ) {
            $randomuser = (Faerie-GetRandom -InputList $Global:CreatedUsers)
            Write-Info "Adding $randomuser to $group"
            Try { Add-ADGroupMember -Identity $group -Members $randomuser } Catch {}
        }
        $Global:AllObjects += $group;
    }
}
function Faerie-AddADUser {
    Param(
        [int]$limit = 1
    )
    Add-Type -AssemblyName System.Web
    for ($i=1; $i -le $limit; $i=$i+1 ) {
        $firstname = (Faerie-GetRandom -InputList $Global:HumansNames);
        $lastname = (Faerie-GetRandom -InputList $Global:HumansNames);
        $fullname = "{0} {1}" -f ($firstname , $lastname);
        $SamAccountName = ("{0}.{1}" -f ($firstname, $lastname)).ToLower();
        $principalname = "{0}.{1}" -f ($firstname, $lastname);
        $generated_password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
        Write-Info "Creating $SamAccountName User"
        Try { New-ADUser -Name "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $generated_password -AsPlainText -Force) -PassThru | Enable-ADAccount } Catch {}
        $Global:CreatedUsers += $SamAccountName;
    }

}
function Faerie-AddACL {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Destination,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [System.Security.Principal.IdentityReference]$Source,

            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]$Rights

        )
        $ADObject = [ADSI]("LDAP://" + $Destination)
        $identity = $Source
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]$Rights
        $type = [System.Security.AccessControl.AccessControlType] "Allow"
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
        $ADObject.psbase.ObjectSecurity.AddAccessRule($ACE)
        $ADObject.psbase.commitchanges()
}
function Faerie-BadAcls {
    foreach ($abuse in $Global:BadACL) {
        $ngroup = Faerie-GetRandom -InputList $Global:NormalGroups
        $mgroup = Faerie-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $mgroup
        $SrcGroup = Get-ADGroup -Identity $ngroup
        Faerie-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "BadACL $abuse $ngroup to $mgroup"
    }
    foreach ($abuse in $Global:BadACL) {
        $hgroup = Faerie-GetRandom -InputList $Global:HighGroups
        $mgroup = Faerie-GetRandom -InputList $Global:MidGroups
        $DstGroup = Get-ADGroup -Identity $hgroup
        $SrcGroup = Get-ADGroup -Identity $mgroup
        Faerie-AddACL -Source $SrcGroup.sid -Destination $DstGroup.DistinguishedName -Rights $abuse
        Write-Info "BadACL $abuse $mgroup to $hgroup"
    }
    for ($i=1; $i -le (Get-Random -Maximum 25); $i=$i+1 ) {
        $abuse = (Faerie-GetRandom -InputList $Global:BadACL);
        $randomuser = Faerie-GetRandom -InputList $Global:CreatedUsers
        $randomgroup = Faerie-GetRandom -InputList $Global:AllObjects
        if ((Get-Random -Maximum 2)){
            $Dstobj = Get-ADUser -Identity $randomuser
            $Srcobj = Get-ADGroup -Identity $randomgroup
        }else{
            $Srcobj = Get-ADUser -Identity $randomuser
            $Dstobj = Get-ADGroup -Identity $randomgroup
        }
        Faerie-AddACL -Source $Srcobj.sid -Destination $Dstobj.DistinguishedName -Rights $abuse 
        Write-Info "BadACL $abuse $randomuser and $randomgroup"
    }
}
function Faerie-Kerberoasting {
    $selected_service = (Faerie-GetRandom -InputList $Global:ServicesAccountsAndSPNs)
    $svc = $selected_service.split(',')[0];
    $spn = $selected_service.split(',')[1];
    $password = Faerie-GetRandom -InputList $Global:BadPasswords;
    Write-Info "Kerberoasting $svc $spn"
    Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -RestrictToSingleComputer -PassThru } Catch {}
    foreach ($sv in $Global:ServicesAccountsAndSPNs) {
        if ($selected_service -ne $sv) {
            $svc = $sv.split(',')[0];
            $spn = $sv.split(',')[1];
            Write-Info "Creating $svc services account"
            $password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
            Try { New-ADServiceAccount -Name $svc -ServicePrincipalNames "$svc/$spn.$Global:Domain" -RestrictToSingleComputer -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru } Catch {}

        }
    }
}
function Faerie-ASREPRoasting {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (Faerie-GetRandom -InputList $Global:CreatedUsers)
        $password = Faerie-GetRandom -InputList $Global:BadPasswords;
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADAccountControl -Identity $randomuser -DoesNotRequirePreAuth 1
        Write-Info "AS-REPRoasting $randomuser"
    }
}
function Faerie-DnsAdmins {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (Faerie-GetRandom -InputList $Global:CreatedUsers)
        Add-ADGroupMember -Identity "DnsAdmins" -Members $randomuser
        Write-Info "DnsAdmins : $randomuser"
    }
    $randomg = (Faerie-GetRandom -InputList $Global:MidGroups)
    Add-ADGroupMember -Identity "DnsAdmins" -Members $randomg
    Write-Info "DnsAdmins Nested Group : $randomg"
}
function Faerie-PwdInObjectDescription {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $randomuser = (Faerie-GetRandom -InputList $Global:CreatedUsers)
        $password = ([System.Web.Security.Membership]::GeneratePassword(12,2))
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "User Password $password"
        Write-Info "Password in Description : $randomuser"
    }
}
function Faerie-DefaultPassword {
    for ($i=1; $i -le (Get-Random -Maximum 5); $i=$i+1 ) {
        $randomuser = (Faerie-GetRandom -InputList $Global:CreatedUsers)
        $password = "Changeme123!";
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "New User ,DefaultPassword"
        Set-AdUser $randomuser -ChangePasswordAtLogon $true
        Write-Info "Default Password : $randomuser"
    }
}
function Faerie-PasswordSpraying {
    $same_password = "ncc1701";
    for ($i=1; $i -le (Get-Random -Maximum 12); $i=$i+1 ) {
        $randomuser = (Faerie-GetRandom -InputList $Global:CreatedUsers)
        Set-AdAccountPassword -Identity $randomuser -Reset -NewPassword (ConvertTo-SecureString $same_password -AsPlainText -Force)
        Set-ADUser $randomuser -Description "Shared User"
        Write-Info "Same Password (Password Spraying) : $randomuser"
    }
}
function Faerie-DCSync {
    for ($i=1; $i -le (Get-Random -Maximum 6); $i=$i+1 ) {
        $ADObject = [ADSI]("LDAP://" + (Get-ADDomain $Global:Domain).DistinguishedName)
        $randomuser = (Faerie-GetRandom -InputList $Global:CreatedUsers)
        $sid = (Get-ADUser -Identity $randomuser).sid

        $objectGuidGetChanges = New-Object Guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)

        $objectGuidGetChanges = New-Object Guid 89e95b76-444d-4c62-991a-0facbeda640c
        $ACEGetChanges = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidGetChanges)
        $ADObject.psbase.Get_objectsecurity().AddAccessRule($ACEGetChanges)
        $ADObject.psbase.CommitChanges()

        Set-ADUser $randomuser -Description "Replication Account"
        Write-Info "Giving DCSync to : $randomuser"
    }
}
function Faerie-DisableSMBSigning {
    Set-SmbClientConfiguration -RequireSecuritySignature 0 -EnableSecuritySignature 0 -Confirm -Force
}

function Faerie-ADCS {
# References: 
# https://blog.wiztechtalk.com/2019/04/03/microsoft-powershell-install-and-configure-ad-certificate-services-windows-server-2016/
# https://github.com/Orange-Cyberdefense/GOAD/blob/ecaa13720f77ca3ca2514f00eeec1a5b7c2dd2ef/ansible/roles/adcs/tasks/main.yml
# https://docs.microsoft.com/en-us/powershell/module/adcsadministration/?view=windowsserver2022-ps
# Check to see if the certificates were created: https://docs.microsoft.com/en-us/powershell/module/pki/get-certificate?view=windowsserver2022-ps

    Get-WindowsFeature AD-Certificate
    Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
    Install-WindowsFeature ADCS-Web-Enrollment
    Install-ADcsCertificationAuthority –Credential (Get-Credential) -CAType StandaloneRootCA –CACommonName “domain-faerie-CA-1” –CADistinguishedNameSuffix “DC=domain,DC=com” –CryptoProviderName “RSA#Microsoft Software Key Storage Provider” -KeyLength 2048 –HashAlgorithmName SHA1 –ValidityPeriod Years –ValidityPeriodUnits 3 –DatabaseDirectory “C:\windows\system32\certLog” –LogDirectory “c:\windows\system32\CertLog” –Force
  
}
function Invoke-Faerie {
    Param(
        [int]$UsersLimit = 100,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName
    )
    ShowBanner
    $Global:Domain = $DomainName
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4
    Faerie-AddADUser -limit $UsersLimit
    Write-Good "Users Created"
    Faerie-AddADGroup -GroupList $Global:HighGroups
    Write-Good "$Global:HighGroups Groups Created"
    Faerie-AddADGroup -GroupList $Global:MidGroups
    Write-Good "$Global:MidGroups Groups Created"
    Faerie-AddADGroup -GroupList $Global:NormalGroups
    Write-Good "$Global:NormalGroups Groups Created"
    Faerie-BadAcls
    Write-Good "BadACL Done"
    Faerie-Kerberoasting
    Write-Good "Kerberoasting Done"
    Faerie-ASREPRoasting
    Write-Good "AS-REPRoasting Done"
    Faerie-DnsAdmins
    Write-Good "DnsAdmins Done"
    Faerie-PwdInObjectDescription
    Write-Good "Password In Object Description Done"
    Faerie-DefaultPassword
    Write-Good "Default Password Done"
    Faerie-PasswordSpraying
    Write-Good "Password Spraying Done"
    Faerie-DCSync
    Write-Good "DCSync Done"
    Faerie-DisableSMBSigning
    Write-Good "SMB Signing Disabled"
    Faerie-ADCS
    Write-Good "AD CS Installed"
}
