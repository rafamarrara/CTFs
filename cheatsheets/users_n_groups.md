# Users and Groups interesting commands

## Linux


## Windows

List users
```
net user
```

Get details of a specific user
```
net user <user>
```

List local groups
```
net localgroup
```

Get details and members of a local group
```
net localgroup <group>
```

Add user
```
net user <new_user> <password> /add
```

Change user password
```
net user <user> <new_pwd>
```

Add user into a local group
```
net localgroup <group> <user> /add
```

### 

```
net user kali P4ssw0rd1 /add
net localgroup Administrators kali /add
```


