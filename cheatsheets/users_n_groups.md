# Users and Groups interesting commands

## Linux

## Windows

List users

```cmd
net user
```

Get details of a specific user

```cmd
net user <user>
```

List local groups

```cmd
net localgroup
```

Get details and members of a local group

```cmd
net localgroup <group>
```

Add user

```cmd
net user <new_user> <password> /add
```

Change user password

```cmd
net user <user> <new_pwd>
```

Add user into a local group

```cmd
net localgroup <group> <user> /add
```

### Create user and add to local admin group

```cmd
net user kali P4ssw0rd1 /add
net localgroup Administrators kali /add
```

```bash
xfreerdp /v:<Target IP> /u:kali /p:'P4ssw0rd1'
```
