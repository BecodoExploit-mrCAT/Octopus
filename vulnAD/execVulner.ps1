IEX((new-object net.webclient).downloadstring("https://raw.githubusercontent.com/CATx003/Octopus/main/vulnAD/vulner.ps1"));Invoke-VulnAD -UsersLimit 100 -DomainName "batata.corp"
