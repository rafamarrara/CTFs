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
- [LOLBAS](https://lolbas-project.github.io/)
- [GTFOBins](https://gtfobins.github.io/)
- [WADComs](https://wadcoms.github.io/)
- [RevShell Generator](https://www.revshells.com/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [PayloadsAllTheThingsWeb](https://swisskyrepo.github.io/PayloadsAllTheThingsWeb/)


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


## Bloodhound

### neo4j

```
sudo apt install neo4j
sudo neo4j console &
```

The first time that you start this database you will need to access http://localhost:7474/browser/. You will be asked default credentials (neo4j:neo4j) and you will be required to change the password, so change it and don't forget it.

### bloodhound

```
sudo apt install bloodhound 
bloodhound &
```

### bloodhound-python

```
pip install bloodhound
```
- [bloodhound-python](https://github.com/fox-it/BloodHound.py)


## AActive Directory tools

### ntpdate

```
sudo apt install ntpdate
```

### gMSADumper.py

```
sudo mkdir /opt/microsoft/ad
cd /opt/microsoft/ad
sudo git clone https://github.com/micahvandeusen/gMSADumper.git
cd gMSADumper
sudo chmod +x gMSADumper.py
```
- [gMSADumper.py](https://github.com/micahvandeusen/gMSADumper)

### OSCP Report tools - MK -> PDF

```bash
sudo apt install texlive-latex-recommended texlive-fonts-extra texlive-latex-extra pandoc p7zip-full
```

### NetExec

- [NetExec](https://www.netexec.wiki/)

```bash
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```
