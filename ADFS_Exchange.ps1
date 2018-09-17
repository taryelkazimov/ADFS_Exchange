# Install DNS, ADDS RSAT
Install-WindowsFeature RSAT-DNS-Server,RSAT-AD-Tools -IncludeAllSubFeature


# Check Grpup Membership

Get-adcomputer 'adfs01' -properties Memberof | Select Memberof
Get-adcomputer 'adfs02' -properties Memberof | Select Memberof

# Create Group in AD add ADFS servers to group

New-ADGroup `
-Name "ADFSServers" `
-SamAccountName ADFSServers `
-GroupCategory Security `
-GroupScope Global `
-Path "CN=Users,DC=contoso,DC=az" `
-Description "ADFS Servers"

Add-ADGroupMember `
-Identity ADFSServers `
-Members adfs01$, adfs02$

# Restart servers to update group membership information

Invoke-Command -ComputerName ADFS02 -ScriptBlock {Restart-Computer -Force}
Restart-Computer

# Check Group Membership again

Get-ADGroupMember AdfsServers

#Create a KDS root key to generate unique passwords for each object in your gMSA
Add-KdsRootKey –EffectiveTime ((get-date).addhours(-10))

# Create Service Account
New-ADServiceAccount -Name adfs -DNSHostName sso.contoso.az `
-PrincipalsAllowedToRetrieveManagedPassword "ADFSServers"

Install-ADServiceAccount "adfs"

Test-ADSErviceAccount "adfs"

############################# ADFS01 Service Configuration ############################# 
# Install ADFS Service
Install-windowsfeature adfs-federation -IncludeManagementTools

# Import certificate
# Copy from CL1.contoso.az to C:\

Import-PfxCertificate –FilePath "C:\Wild.pfx" "cert:\localMachine\my" `
-Password (ConvertTo-SecureString -String "1" -Force –AsPlainText)

# Find Thumbprint
cd Cert:\LocalMachine\my
dir

# ADFS post-install configuration
Install-AdfsFarm `
-CertificateThumbprint '22A6847E903161F12AD4283480C76188515843E6' `
-FederationServiceDisplayName:"Contoso ADFS" `
-FederationServiceName:"sso.contoso.az" `
-GroupServiceAccountIdentifier:"contoso.az\adfs`$"


# For troubleshooting enable IdP and test
Get-AdfsProperties | select EnableIdPInitiatedSignonPage

Set-AdfsProperties -EnableIdPInitiatedSignonPage $true

# Change token certificates expiration date

Set-AdfsProperties -CertificateDuration 1095

Update-ADFSCertificate -CertificateType Token-Signing -Urgent

Update-ADFSCertificate -CertificateType Token-Decrypting -Urgent

Restart-Computer


# Add Relay party trust for OWA/ECP/ActiveSync
Add-AdfsRelyingPartyTrust -Name "Outlook on the web" `
-Notes "This is a trust for https://mail.contoso.az/owa/" `
-Identifier https://mail.contoso.az/owa/ `
-WSFedEndpoint https://mail.contoso.az/owa/ `
-IssuanceAuthorizationRules '@RuleTemplate = "AllowAllAuthzRule"  => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");' `
-IssueOAuthRefreshTokensTo NoDevice


Set-AdfsRelyingPartyTrust -TargetName "Outlook on the web" `
-IssuanceTransformRules '@RuleName = "ActiveDirectoryUserSID" c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => issue(store = "Active Directory", types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"), query = ";objectSID;{0}", param = c.Value);   @RuleName = "ActiveDirectoryUPN" c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"), query = ";userPrincipalName;{0}", param = c.Value);'

Add-AdfsRelyingPartyTrust -Name EAC `
-Notes "This is a trust for https://mail.contoso.az/ecp/" `
-Identifier https://mail.contoso.az/ecp/ `
-WSFedEndpoint https://mail.contoso.az/ecp/ `
-IssuanceAuthorizationRules '@RuleTemplate = "AllowAllAuthzRule"  => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");' `
-IssueOAuthRefreshTokensTo NoDevice

Set-AdfsRelyingPartyTrust -TargetName EAC `
-IssuanceTransformRules '@RuleName = "ActiveDirectoryUserSID" c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => issue(store = "Active Directory", types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"), query = ";objectSID;{0}", param = c.Value);   @RuleName = "ActiveDirectoryUPN" c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"), query = ";userPrincipalName;{0}", param = c.Value);'

Add-AdfsNonClaimsAwareRelyingPartyTrust -Name "ActiveSync" -Notes "Contoso EAS" -Identifier "https://mail.contoso.az/Microsoft-Server-ActiveSync/" -IssuanceAuthorizationRules '=>issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'




############################# ADFS02 Service Configuration ############################# 

# Get ADFS Farm Inforamtion
Get-AdfsFarmInformation


# INSTALL ADFS SERVICE
Install-windowsfeature adfs-federation -IncludeManagementTools

# IMPORT CERTIFICATE
Import-PfxCertificate –FilePath "C:\Wild.pfx" "cert:\localMachine\my" `
-Password (ConvertTo-SecureString -String "1" -Force –AsPlainText)

# JOIN SERVER TO FARM
Add-AdfsFarmNode -GroupServiceAccountIdentifier:"contoso.az\adfs`$" `
-PrimaryComputerName adfs01 `
-CertificateThumbprint '22A6847E903161F12AD4283480C76188515843E6'

# Get ADFS Farm Inforamtion
Get-AdfsFarmInformation


############################# NLB and DNS Configuration ############################# 


# 1. Install ADFS Temapleate
# 2. Create VIP
# 3. Change Healt check URL to /adfs/probe, protocol http and port 80 :)
# Create DNS record for SSO

Enter-PSSession -ComputerName dc01.contoso.az
Add-DnsServerResourceRecordA -ZoneName contoso.az -Name sso -IPv4Address 192.168.0.30
exit

# Test this URL's
# https://sso.contoso.az/adfs/ls/idpinitiatedsignon.htm
# https://sso.contoso.az/federationmetadata/2007-06/federationmetadata.xml



############################# WAP01 Configuration ############################# 

# Install WAP Feature
 Install-WindowsFeature Web-Application-Proxy -IncludeManagementTools

 # Import WildCard Certificate
 certlm.msc

 Import-PfxCertificate –FilePath "C:\Wild.pfx" "cert:\localMachine\my" `
-Password (ConvertTo-SecureString -String "1" -Force –AsPlainText)

# Link WAP01 to ADFS
 Install-WebApplicationProxy `
 -CertificateThumbprint '22A6847E903161F12AD4283480C76188515843E6' `
 -FederationServiceName "sso.contoso.az"


 # Create WAP Rules (Publish)

$VerbosePreference = "continue"
$ExchangeBaseURL = "mail.contoso.az"
$ExternalCertTB = '22A6847E903161F12AD4283480C76188515843E6'
$ExchangeAutodiscover ="autodiscover.contoso.az"


Write-Verbose "Publish Exchange OAB URL" 
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://$ExchangeBaseURL/OAB/" `
-ExternalCertificateThumbprint "$ExternalCertTB" `
-ExternalUrl "https://$ExchangeBaseURL/OAB/" `
-Name "Exchange OAB" `
-ExternalPreAuthentication PassThrough

Write-Verbose "Publish Exchange Autodiscover"
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://$ExchangeAutodiscover/Autodiscover/" `
-ExternalCertificateThumbprint "$ExternalCertTB" `
-ExternalUrl "https://$ExchangeAutodiscover/Autodiscover/" `
-Name "Exchange Autodiscover" `
-ExternalPreAuthentication PassThrough

Write-Verbose "Publish Exchange MAPI"
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://$ExchangeBaseURL/mapi/" `
-ExternalCertificateThumbprint "$ExternalCertTB" `
-ExternalUrl "https://$ExchangeBaseURL/mapi/" `
-Name "Exchange MAPI" `
-ExternalPreAuthentication PassThrough

Write-Verbose "Publish Exchange EWS"
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://$ExchangeBaseURL/EWS/" `
-ExternalCertificateThumbprint "$ExternalCertTB" `
-ExternalUrl "https://$ExchangeBaseURL/EWS/" `
-Name "Exchange EWS" `
-ExternalPreAuthentication PassThrough

Write-Verbose "Publish Exchange RPC"
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://$ExchangeBaseURL/RPC/" `
-ExternalCertificateThumbprint "$ExternalCertTB" `
-ExternalUrl "https://$ExchangeBaseURL/RPC/" `
-Name "Exchange RPC" `
-ExternalPreAuthentication PassThrough

Write-Verbose "Publish Core"
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://$ExchangeBaseURL/" `
-ExternalCertificateThumbprint "$ExternalCertTB" `
-ExternalUrl "https://$ExchangeBaseURL/" `
-Name "Core Site" `
-ExternalPreAuthentication PassThrough

Write-Verbose "Publish Webmail HTTPS"
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://webmail.contoso.az/" `
-ExternalCertificateThumbprint "$ExternalCertTB" `
-ExternalUrl "https://webmail.contoso.az/" `
-Name "Webmail-HTTPS" `
-ExternalPreAuthentication PassThrough

Write-Verbose "Publish Webmail HTTP"
Add-WebApplicationProxyApplication `
-BackendServerUrl "http://webmail.contoso.az/" `
-ExternalUrl "http://webmail.contoso.az/" `
-Name "Webmail-HTTP" `
-ExternalPreAuthentication PassThrough


Add-WebApplicationProxyApplication `
-BackendServerUrl 'https://mail.contoso.az/Microsoft-Server-ActiveSync/' `
-ExternalCertificateThumbprint $ExternalCertTB `
-ExternalUrl 'https://mail.contoso.az/Microsoft-Server-ActiveSync/' `
-Name 'Exchange EAS' `
-ExternalPreAuthentication ADFSforRichClients `
-ADFSRelyingPartyName 'ActiveSync'


Write-Verbose "Publish Outlook on the Web (AD FS)"
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://$ExchangeBaseURL/owa/" `
-ExternalCertificateThumbprint $ExternalCertTB `
-ExternalUrl "https://$ExchangeBaseURL/owa/" `
-Name "Outlook on the Web" `
-ExternalPreAuthentication ADFS `
-ADFSRelyingPartyName "Outlook on the Web" 

Write-Verbose "Publish Exchange ECP (AD FS)"
Add-WebApplicationProxyApplication `
-BackendServerUrl "https://$ExchangeBaseURL/ecp/" `
-ExternalCertificateThumbprint $ExternalCertTB `
-ExternalUrl "https://$ExchangeBaseURL/ecp/" `
-Name "Exchange ECP" `
-ExternalPreAuthentication ADFS `
-ADFSRelyingPartyName "EAC"


############################### WAP02 CONFIGURATION ###################
# Install WAP Feature
Install-WindowsFeature Web-Application-Proxy -IncludeManagementTools

 # Import WildCard Certificate
 certlm.msc

 Import-PfxCertificate –FilePath "C:\Wild.pfx" "cert:\localMachine\my" `
-Password (ConvertTo-SecureString -String "1" -Force –AsPlainText)

# Link WAP to ADFS
Install-WebApplicationProxy `
-CertificateThumbprint '22A6847E903161F12AD4283480C76188515843E6' `
-FederationServiceName sso.contoso.az

############################### WAP NLB CONFIGURATOIN ###################

# 1. Create VIP
# 2. Disable SSL Reencryption
# 3. Add Real Servers
# 4. Set Healt Check Url to /adfs/probe proto. HTTP port 80 :)
# Add NAT Rule on Firewall

netsh interface portproxy add v4tov4 listenport=443 listenaddress=50.50.50.100 connectport=443 connectaddress=172.16.10.30

netsh interface portproxy add v4tov4 listenport=80 listenaddress=50.50.50.100 connectport=80 connectaddress=172.16.10.30



############################### Configure Exchange Services ###################

# Export Token Signing certificate from ADFS

$certRefs = Get-AdfsCertificate -CertificateType Token-Signing
$certBytes=$certRefs[0].Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes("c:\adfs-token-signing.cer", $certBytes)

# Note Certificate Thumbprint
# Import certificate to All Exchange Server T.R.C.S
certlm.msc


$A = New-PSSession `
-ConfigurationName Microsoft.Exchange `
-ConnectionUri http://mbx01.contoso.az/PowerShell/ `
-Credential admin@contoso.az
Import-PSSession $A -AllowClobber


Set-OrganizationConfig -AdfsIssuer https://sso.contoso.az/adfs/ls/ `
-AdfsAudienceUris "https://mail.contoso.az/owa/","https://mail.contoso.az/ecp/" `
-AdfsSignCertificateThumbprint '0e768afd8ede33b79e1220159d7c473824a4815f'

Get-EcpVirtualDirectory
Get-OwaVirtualDirectory


Set-EcpVirtualDirectory -Identity "mbx01\ecp (Default Web Site)" `
-AdfsAuthentication $true `
-BasicAuthentication $false `
-DigestAuthentication $false `
-FormsAuthentication $false `
-WindowsAuthentication $false


Set-EcpVirtualDirectory -Identity "mbx02\ecp (Default Web Site)" `
-AdfsAuthentication $true `
-BasicAuthentication $false `
-DigestAuthentication $false `
-FormsAuthentication $false `
-WindowsAuthentication $false



Set-OwaVirtualDirectory -Identity "mbx01\owa (Default Web Site)" `
-AdfsAuthentication $true `
-BasicAuthentication $false `
-DigestAuthentication $false `
-FormsAuthentication $false `
-WindowsAuthentication $false


Set-OwaVirtualDirectory -Identity "mbx02\owa (Default Web Site)" `
-AdfsAuthentication $true `
-BasicAuthentication $false `
-DigestAuthentication $false `
-FormsAuthentication $false `
-WindowsAuthentication $false

Get-PSSession
Remove-PSSession -Id (Read-Host ID)

Invoke-Command -ComputerName (Read-Host ServerName) -ScriptBlock {cmd.exe /c iisreset /noforce}




############################### ADFS TUNING ###################

$cred = Get-Credential
Update-AdfsArtifactDatabasePermission -Credential $cred

Set-AdfsProperties `
-EnableExtranetLockout $true `
-ExtranetLockoutThreshold 4 `
-ExtranetObservationWindow (new-timespan -Minutes 10) `
-ExtranetLockoutRequirePDC $false `
-ExtranetLockoutMode ADFSSmartLockoutLogOnly

Set-AdfsProperties -ExtranetLockoutMode AdfsSmartLockoutEnforce

Restart-Service adfssrv

Invoke-Command `
-ComputerName (Read-Host Computername) `
-ScriptBlock {Restart-Service adfssrv}


#Check the users ADFS Account Activity

Get-ADFSAccountActivity (Read-Host UPN)

#check to see if the users bad password account in AD is increasing
get-aduser (Read-Host SamAccountName) -properties badPwdCount,lockedout

# Reset ADFS Lock 
Reset-AdfsAccountLockout -UserPrincipalName (Read-Host UPN) -Location Unknown
Reset-AdfsAccountLockout -UserPrincipalName (Read-Host UPN) -Location Familiar


# How to change the primary ADFS Server in a farm
# Open PowerShell on the ADFS Server that you want to set as Primary:

Set-AdfsSyncProperties -Role PrimaryComputer

# Open PowerShell on all remaining ADFS Servers, including the old Primary server if it’s still available:

Set-AdfsSyncProperties -Role SecondaryComputer -PrimaryComputerName <internal_FQDN_of_the_new_Primary_Server>