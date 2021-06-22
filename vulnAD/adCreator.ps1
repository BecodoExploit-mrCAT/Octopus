Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment
$secpass=ConvertTo-SecureString Batata@2021 -AsPlainText -Force
$dmnname = "batata.corp"
$dmnnetbios = "BATATA-01"

Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2012R2" -DomainName $dmnname -DomainNetbiosName $dmnnetbios -ForestMode "Win2012R2" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -SafeModeAdministratorPassword $secpass -Force:$true





