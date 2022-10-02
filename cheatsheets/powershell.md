# PowerShell useful commands

## credentials

```
$user = 'TESTLAB\dfm.a'
$pwd = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pwd)
```