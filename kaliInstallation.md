# Kali installation

## Hyper-V

[install Hyper-V guest enhanced session mode](https://www.kali.org/docs/virtualization/install-hyper-v-guest-enhanced-session-mode/)

- update hyperv-daemons
```
sudo apt update
sudo apt install hyperv-daemons
```

- enable enhanced session mode inside Kali
```
kali-tweaks
```

- change the transport type from VMBus to HVSocket at Hyper-V host level
```PowerShell
Set-VM "<VM NAME>" -EnhancedSessionTransportType HVSocket
```

- logout or shutdown and start again the VM
- if necessary edit VMConnect to set full screen
```PowerShell
vmconnect.exe <HyperV Host> <VM Name> /edit
```

## Firefox

### Add-ons

- [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)
- [HackTools](https://addons.mozilla.org/en-US/firefox/addon/hacktools/)

### Favorites

- [Crack Station](https://crackstation.net/)


## Burp config

- [Installing Burp's CA certificate in Firefox](https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate/ca-cert-firefox)


## Git

```
git config --global user.name "John Doe"
git config --global user.email johndoe@example.com
```

## AutoRecon

Install AutoRecon and all its dependence
- [AutoRecon](https://github.com/Tib3rius/AutoRecon)


## Flameshot

```
sudo apt install flameshot
```
- [Flameshot](https://flameshot.org/)

## Zaproxy

```
sudo apt install zaproxy
```
[Zaproxy](https://www.kali.org/tools/zaproxy/)


## DBeaver

```
sudo apt install ./dbeaver-ce_22.2.3_amd64.deb 
```
- [DBeaver](https://dbeaver.io/download/)


## VSCode

```
sudo apt install ./code_1.72.2-1665614327_amd64.deb
```
- [VSCode](https://code.visualstudio.com/Download)