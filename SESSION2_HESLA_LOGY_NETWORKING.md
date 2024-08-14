
#### CVICENIE 2 UZIVATELIA A PRAVA

Vytvorenie užívateľa:
```powershell
`$Password = Read-Host -AsSecureString "Enter the password for TestUser" 
New-LocalUser -Name "TestUser" -Password $Password -FullName "Test User" -Description "Test user account"`

# pridanie uzivatela k Adminom
`Add-LocalGroupMember -Group "Administrators" -Member "TestUser"`

# Pridanie usera do skupiny Users
`Add-LocalGroupMember -Group "Users" -Member "TestUser"`

```
#### PRAVA K ADRESARU

```powershell
`New-Item -Path "C:\Users\YourUsername\Desktop\TestFolder" -ItemType Directory`

`$folderPath = "C:\Users\YourUsername\Desktop\TestFolder" $user = "TestUser"  

`icacls $folderPath`

# Remove the user 
Remove-LocalUser -Name "TestUser"  

# Remove folder
Remove-Item -Path $folderPath -Recurse -Force`
```


## 3. OCHRANA HESLOM 2FA, BIOMETRIA, FIDO KEY

3.1 Silne a zapamatatelne heslo:
``` sql
K@5d1_8tvrtoK_HLADAM_p@pucE
```

3.2 POUZITIE PASSWORD MANAGERA: 
ProtonPassword,
KeePass, 
1PASSWORD, 
LastPass
XPASS

STACI SI POTOM PAMATAT MASTER PASSWORD

>[! warning]
>Akonahle sa hacker dozvie kde mate svoje hesla pokusi sa ich ziskat !!!


#### 3.3 DARKWEB OBCHODOVANIE S HASHMI

Vacsina uniknutych hesiel pochadza z kradezi u velkych poskytovatelov sluzieb ako FB, Adobe atd.

[Have I Been Pwned: Check if your email has been compromised in a data breach](https://haveibeenpwned.com/)


### 3.4 BRUTEFORCE, SLOVNIKOVY UTOK, RAINBOW TABLES

> [! info]
> Naco vylamovat zamky ked mate od chaty kluc ?

``` bash
echo -n heslo | md5sum > pwd.txt
md5sum SUBOR

cat pwd.txt
```

>[!warning]
>HACKER - Narozdiel od predstáv filmových fanúšikov sa nemusí hacker nikam ponáhľať. Má na prienik do systému more času na získanie hesiel, právomocí, prístupov, zbieranie dát

``` powershell
"hello world" | Get-Hash -Algorithm MD5
```
```


>[! warning] TOOLBOX>KALI LINUX : johntheripper - tradicny password cracker


``` bash
john --format=raw-md5 pwd.txt

john --incremental=ASCII --format=raw-md5 pwd.txt
cat .john/john.pot
```
POZNAMKA: Vyhodou johna je automaticka detekcia formatu a kodovania

>[! warning] TOOLBOX>KALI LINUX : hashcat - password cracker s vyuzitim automatickeho vykonu jadier Grafickych kariet 

``` bash
hashcat -b. # benchmark pocitaca
hashcat -m 0 -a 3 --show md5.txt
hashcat -m 0 -a 3 --show md5.txt ?l?d ?1?1?1?1?1
hashcat -m 0 -a 0 --show md5.txt /usr/share/wordlists/rockyou.txt

cat /local/share/hashcat/hashcat.potfile
```

>[!info] TOOLBOX>KALI LINUX : rockyou.txt je dlhy wordlist v adresari [/usr/share/wordlists/]. Je standardne kompressovany v archive .gz
>

``` bash
cd /usr/share/wordlist/
sudo gzip -d rockyou.txt.gz
```

>[! warning] TOOLBOX>KALI LINUX : hydra - Slovnikovy utok priamo  priamo na REMOTE SERVER

``` bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt IP ssh
```

### 3.4.1 RAINBOW TABLES
Databaza Vsetky hashe vsetkych hesiel v roznych formatoch


>[! warning] NESIFROVANE  
[List of Rainbow Tables (project-rainbowcrack.com)](http://project-rainbowcrack.com/table.htm)




### 3.5 MULTI FACTOR AUTHENTIFICATION

MultiFactor autentifikacia je moderne riesenie autentifikacie uzivatela do PC alebo servisu.


Google Authentificator  Android APPKA
[google authenticator - Android Apps on Google Play](https://play.google.com/store/search?q=google+authenticator&c=apps)

Microsoft Authentificator APPKA
[microsoft authenticator - Android Apps on Google Play](https://play.google.com/store/search?q=microsoft%20authenticator&c=apps)

Yubi Key DEVICE  
[yubikey.sk – oficiálny predajca](https://yubikey.sk/)
[YubiKey.cz](https://yubikey.cz/)

Windows Hello : )
BIOMETRIA : )

>[! info]
>APPLE vs. FBI a zablokovany iPhone


## 4. LOGOVANIE

Windows Log je pristupny cez eventViewer alebo cez Powershell:

``` powershell
Get-EventLog -list
Get-EventLog -LogName Systemn -Newest 10
Get-EventLog -LogName System -After '6/5/23 0:00'
Get-EventLog -LogName System -Message '*login*'
Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 | Select-Object TimeGenerated, Message | Format-Table -AutoSize
```


``` powershell
Get-EventLog System -Source Microsoft-Windows-WinLogon -Newest 10
```
Get-EventLog System -Source Microsoft-Windows-WinLogon -Newest 10


Ukazka skriptovania v Powershell:
``` powershell

for ($i=1; $i -le 5; $i++) {
    if ($i -eq 3) {
        Write-Host "The value of i is $i. This is the third iteration."
    }
    else {
        Write-Host "The value of i is $i."
    }
}
```

``` python

for i in range(1,5):
	if i == 3:
		print(f'Hodnota i je {i} TOTO JE TRETIE V PORADI')
	else:
		print(f'Hodnota i je {i}')
```

LINUX ma viacero systemov ako zachytit logy.

najjednoduchsi je skopirovat vsetko z adresara :

``` bash
cp -R /var/log/*  /kamtochceme
cat /etc/passwd
```

DVA SYSTEMY PRISTUPU K LOGOM
``` bash
dmesg
journalctl
```


``` bash
dmesg | tail -n 150 | grep root
```

## 5. OCHRANA SYSTEMU POMOCOU HASH ALGORITMOV

VYPOCITAME HASHSTRINGY PRE JEDNOTLIVE SUBORY AJ CELE ADRESARE

``` powershell
Get-FileHash SUBOR -Algorithm md5
Get-FileHash SUBOR -Algorithm SHA256 | Out-File -FilePath SUBOR
Get-FileHash SUBOR -Algorithm SHA256 | Out-File -FilePath SUBOR -Append
Get-ChildItem -Path .\ADRESAR\ -Recurse -Filter *.* | Get-FileHash -Algorithm md5 | Out-File -FilePath .\pwd.hashes -Append
```

POROVNAME ICH POMOCOU JEDNODUCHEHO ALGORITMU
``` powershell
$hashe_stare = Get-FileHash C:\hashes1.txt
$hash_nove = Get-FileHash C:\hashes2.txt

if ($hashe_stare -eq $hashe_nove) {
    Write-Host "The files are identical."
} else {
    Write-Host "The files are different."
}
```

``` powershell
Compare-Object (Get-Content .\pwd.hashes) (Get-Content .\pwd2.hashes)
```



``` linux
md5sum ADRESAR/* > hashes.txt
find ADRESAR -type f -exec md5sum {} \; > hashes.txt
```

``` bash
diff hashes1.txt hashes2.txt
vimdiff hashes1.txt hashes2.txt
```

## 6. USB KLUCE, KABLE A ZARIADENIA  - HUMAN INTERFACE DEVICE 

### 6.1 RUBBER DUCKY

>[!warning] 
>VYZERA TO AKO KACKA + 
>KVAKA TO AKO KACKA =
>TAK TO BUDE KACKA !

RUBBER DUCKY ZA 5EUR

[GitHub - dbisu/pico-ducky: Create a USB Rubber Ducky like device using a Raspberry PI Pico](https://github.com/dbisu/pico-ducky)

### 6.2 AUTOMOUNT - AUTORUN - SLUZBA ALEBO PREKLIATIE

``` linux
sudo fdisk -l
mkdir USB_KLUC
mount /dev/sd?1 /USB_KLUC
umount USB_KLUC
```



# SIETE A VZNIK A TOPOGRAFIA SIETE

MODEM - Modulator-Demodulator BBS Bulletin Board System (TELEFÓNNA SIEŤ)
WAN - WIDE AREA NETWORK. {SAGE-RADARY US AIR FORCE, ARPANET IP adresy}
LAN - Local Area Network (Novell, Token Ring, Ethernet, MESH)

HVIEZDA

 ![ETHERNET TOPOLOGY ](LAN.png)
 
TOOLBOX:

# OPEN SYSTEM INTERCONECTION MODEL

### 1. FYZICKÁ VRSTVA

Káble podľa tienenia:
UTP - Netienený pár  vodičov- 
STP - Pár vodičov tienený medenou izoláciou 
FTP - Pár vodičov tienený fóliou
S\ FTP - Kombinácia STP a FTP

Káble podľa rýchlosti:
CAT5 max 100Mbps
CAT5e max 1Gbps
CAT6  max 1Gbps
CAT6e max 10Gbps
CAT8 max 40Gbps

Konektory:
RJ45 - 10Mbps, 100Mbps, 1Gbps, 2.5Gbps
SFP(Small FormFactor Pluggable) - 4,25Gbps (NA SWITCHOCH A ROUTROCH)
SFPplus - 10Gbps (NA SWITCHOCH A ROUTROCH)

PoE - Power over Ethernet - Možnosť napájania zariadení priamo cez CAT kábel.


### 2. SPOJOVACIA VRSTVA - DATA LINK LAYER

FRAMES RAMCE KOMUNIKACIE

PROTOCOLS IN FRAME [wth:ip:tcp:ssh]

ETHERNET, PPP, Switch, Bridge
prepojenie siete v sietovych zariadeniach 

ARP protokol  asociuje fyzicku MAC adresu s IP adresou. Tymto prikazom ukazeme vsetky MAC adresy, ktore pocitac pozna.
``` bash
arp -a
```

```powershell
arp -a 
```

### 3. SIETOVA VRSTVA. - NETWORK LAYER

PACKETY 

> [! warning]
> TOOLBOX: WIRESHARK A PROMISC MODE!
> 

```bash
sudo ifconfig eth0 promisc
```

#### IP Internet Protocol ADRESY IPv4 a IPv6, IPSec

max 255.255.255.255 32bit dokopy 4.3 miliardy adries teoreticky
mnozstvo adries je rezervovana pre privatne siete a multicast

max ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff d 128bit dokopy

``` bash
ping 8.8.8.8
traceroute 8.8.8.8
netstat -a
```

ICMP - Internet Control Message Protocol {UNICAST}
IGMP - Internet Group Management Protocol  {host sa prihlasuje do MULTICAST}


> [! info]
> IPSEC tunel medzi dvoma routrami vsetko zasifrovane
> IPSEC transport obsah zasifrovany ale hlavicka NIE

>[!warning]
>POCITAC MOZE MAT AJ INTERNE IP ADRESY, ktore umoznuju aplikaciam poskytovat info napr cez browser ako keby boli na sieti http://localhost alebo
>http://127.0.0.1


ROUTER smerovac balickov  LAN<>WAN (pocitac)
DHCP - Lizingovka pre IP adresy (DHCP je bezpecnejsie ako static)
Maska siete = 255.255.255.0 
GATEWAY = IP adresa routera
NAT - NETWORK ADDRESS TRANSLATION - privatna IP dostava Info cez verejnu.

Staticka verejna IP vs. lokalna neverejna IP

### 4.TRANSPORTNA VRSTVA
SPOJENIA MEDZI IP ADRESAMI

#### 4.1 TCP - Autorizacia, Handshake SYN ACK FIN RST PSH
Na pochopenie TCP protokolu si uvedieme príklad kde sa dvaja ľudia stretnú na ulici:

1. Pozdravia sa a ak sa nepoznajú predstavia sa navzájom. 
2. Potrasú si rukami HANDSHAKE (SYN, SYN-ACK, ACK)
3. Komunikujú slovne (packety)
4. Ukončia komunikáciu, (FIN, ACK-FIN, ACK)
5. Rozlúčia sa a idú každý svojou cestou

Ak sa nechcú baviť RST. 

#### 4.2 UDP - Neautorizovany stream DAT medzi IP

Na pochopenie UDP môžeme použiť príklad keď sa dvaja ľudia pokúšajú na diaľku komunikovať kričaním. Ak by im záležalo na 100 percentnej komunikácií tak by k sebe prišli a podali by si ruky a komunikovali TCP. Ale to sa im nechce. 

Používa sa to napríklad v hrách alebo pri prenose videa. Ak sa nejaký ten obrázok stratí tak nevadí, komunikácia nie je prerušená a dáta idú ďalej. 


#### 4.3 Firewall - Ohnova stena s prisnymi pravidlami (RULES)

>[!warning] TOOLBOX>KALI LINUX : iptables - standardny FIrewall LINUX

```bash

sudo iptables -L 


sudo iptables-save > RULES
cat RULES

sudo iptables -P OUTPUT DROP
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP

sudo iptables -A INPUT -s IP -j DROP
sudo iptables -A OUTPUT -p tcp -d fortisauris.com -j ACCEPT

sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

sudo iptables -F   # FLUSH ALL RULES

```

ufw

>[!warning] TOOLBOX>KALI LINUX : ufw - nekomplikovana nadstavba pre iptables 

```bash
sudo service ufw status
sudo ufw enable

sudo ufw deny OUT 22
sudo ufw deny IN 22

sudo ufw status verbose

sudo ufw reset

```



``` powershell
Import-Module -Name 'NetSecurity'

Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action -First 10
```

``` powershell
$Params = @{ "DisplayName" = 'Block WINS' "Direction" = 'Inbound' "Action" = 'Block' "RemoteAddress" = 'WINS' }

New-NetFirewallRule @Params

New-NetFirewallRule -DisplayName "OUT SSH Port 22" -Direction Outbound -LocalPort 22 -Protocol TCP -Action Block
```

```powershell

Set-NetFirewallRule -DisplayName 'OUT SSH' -Action Allow
Remove-NetFirewallRule -DisplayName "OUT SSH"
```

INE METODY: Disable, Enable, Rename, Show, Copy

```powershell
Get-NetFirewallProfile
Get-NetFirewallSetting
```
INE METODY: Set


Vsetky balicky co nesplnia podmienky zhoria na Ohnivej stene.
DPI Deep Packet Inspection. WAN a LAN

4.5. CISLA SEKVENCIE 
Aby sme PACKETY vedeli pospájať sú im pridelené poradové čísla sekvencie. Takýmto spôsobom vie počítač zložiť posielané dáta do ich pôvodnej formy. Napr. obrázku alebo dokumentu.

### 5. SESSION LAYER - 
Sluzi na nadviazanie, ukoncenia a udrziavania spojenia medzi aplikaciami... udrziavanie spojenia ZNAMOSTI

X.225 alebISO 8327 

PROTOKOLY, KTORE VYUZIVAJU TUTO VRSTVU:

<li>RPC Remote Procedure Call</li>
<li>SQL Structured Query Languague</li>
<li>SOCKS Proxy</li>
<li>SCP Session Control Protocol</li>
<li>RTPC Realtime Transport Control Protocol</li>
<li>PPTP Point2Point Tunelling Protocol</li>
<li>NetBIOS </li>
<li>L2TP Layer2 Tunelling Protocol</li>
<li>Apple Talk Session and Data STream Protocols</li>


#### 5.1 CO JE SESSION. Application Programm Interface
synchronizacne sluzby a a posielanie na sockety
Komunikacia s API alebo sietovym portom

#### 5.2 SIETOVE PORTY

SIETOVE PORTY POCITACA. 
Spolu 65535 portov. Kazdy z nich moze prijimat a posielat packety s informaciami.
<ul>
<li>ftp = port 20 & 21</li>
<li>ssh = port 22</li>
<li>telnet = port 23</li>
<li>smtp = port 25</li>
<li>dns = port 53</li>
<li>http = port 80</li>
<li>pop3 = port 110 & 995 s SSL/TLS</li>
<li>imap = port 143 & 993 s SSL/TLS</li>
<li>https = port 443</li>
</ul>

### 6. PREZENTACNA VRSTVA
Syntax Layer - tu sa deju veci

SSL - System Security Layer. (sifrovanie pomocou klucov a certifikatov)
SSH - System Secure shell. {REMOTE SHELL}
IMAP - Internet Message Access Protocol  {EMAIL}


### 7. APLIKACNA VRSTVA
Sietova vrstva pomocou ktorej ma interakciu so sietovou prevadzkou prostrednictvom aplikacii ktore vyuzivaju priamo obsah balickov

#### 7.1 LEGACY PROTOKOLY  !!!

HTTP - HYPER TEXT TRANSFER PROTOCOL {}
FTP - FILE TRANSFER PROTOCOL {STAHOVANIE A UPLOAD SUBOROV NA REMOTE}
TELNET {SHELL}

>[!warning]
>FTP a TELNET nemaju sifrovanie a preto komunikacia cez nich tecie v packetoch v otvorenej reci. NEPOUZIVAT !!! 
>HTTP je internetovy protokol na komunikaciu s webserverom bez sifrovania. Pripajanie sa k strankam bez sifrovania nepovazujeme za BEZPECNE !!! 

#### 7.2 IRC - INTERNET RELAY PROTOCOL {CHAT}
Oblubeny sposob chatovania pomocou lokalne alebo verejne umiestneneho servera IRC

#### 7.3 SSH - SYSTEM SECURE SHELL {SIFROVANY SHELL}

Na cielovom pocitaci musi bezat ssh server. Oblubene su OpenSSH a Dropbear.

>[!info]
>Vacsina serverov bezi 24/7 v tzv. HEADLESS mode. Je mozne sa k nim pripojit lokalne cez KVM konzolu, alebo na dialku pomocou ssh.



```bash
ssh user@ip
```

pri prvom nadviazani spojenia si pocitace vymenia kryprograficke kluce a dohodnu sa na sifrovani. Tento kluc sa uklada do suboru:

```bash
.ssh\known_hosts
```

Standardne pozaduje zadanie hesla uzivatela.

>[!warning] !!! POZOR prihlasovat sa cez ssh ako root je nebezpecne !

SSH vieme nastavit aby miesto hesla akceptoval dvojicu ktyprografickych klucov.
privatny na strane klienta   a verejny na strane serveru

```bash

ssh-keygen
ssh-copy-id username@host_ip
ssh username@host_ip

```

Na strane servera mozeme vypnut Autentifikaciu pomocu hesla v subore [/etc/ssh/sshd_config] pridame alebo zmenime riadok:

```sshd_config
PasswordAuthentication no
```

Teraz sa mozeme pripajat bez pouzitia hesla za pouzitia kryptografickeho verejneho kluca. 
>[!info] 
>KRYPTOGRAFIU BUDEME PREBERAT V TOMTO KURZE V DALSICH LEKCIACH :)



#### 7.4 SFTP - SECURE FILE TRANSFER PROTOCOL {SIFROVANY PRENOS SUBOROV}

sftp vyuziva sluzby ssh serveru. Umoznuju stahovat subory GET alebo posielat subory PUT na server kde bezi  ssh server.

``` powershell
sftp username@host_ip
help
```

SFTP nam umoznuje prezerat subory na LOKALNOM pocitaci pomocou !dir aj na REMOTE pomocou dir. 

``` powershell
get SUBOR KAM # stiahne SUBOR zo SERVERU 
put subor KAM # posle SUBOR z LOKALNEHO POCITACA NA SERVER
```

SFTP nám umožňuje manipulovať so súbormi a adresármi na oboch koncoch TCP spojenia. Vymazávať, presúvať, vytvárať adresáre a pod.

SCP Secure Copy tiez vyuziva SSH server na kopirovanie suborov a adresarov.

``` bash
scp SUBOR username@hostname:KAM
```

>[!info]
>Alternativa SCP funguje aj v Powershell avsak nepouziva SSH ale HTTPS na to potrebuje mat Certifikaty a kluce cieloveho servera. 



#### 7.5 DNS - DOMAIN NAME SERVER {ZLATE STRANKY IP ADRIES}

DNS je zjednodusene povedane telefonny zoznam. Ak do browseru alebo hocikam kde mozno vlozit adresu URL napr: [https:\\fortisauris.com](https:\\fortisauris.com)
Pocitac skontroluje v DNS zaznamoch mena domen a presmeruje spojenie na IP adresu, ktoru si tak nemusime pamatat. 

A RECORD - SMEROVANIE DOMENY NA VEREJNU STATICKU IP ADRESU
CNAME - SMEROVANIE WEB HOSTINGU NA DOMENU
MX - SMEROVANIE DOMENY NA MAILOVY SERVER

>[!warning] DNSEC je bezpecnejsia verzia DNS, ktora zabezpecuje, ze nebude Vas pocitac presmerovany na inu 'FALOSNU' domenu ci IP adresu. 

#### 7.6 HTTPS - HYPERTEXT TRANSFER PROTOCOL SECURE

Preferovaný štandard pre pripájanie sa k webovým stránkam a API zabezpečene:
1. Server a klient si vymenia verejné šifrovacie kľúče.
2. Platné certifikáty potvrdia, že sa jedná o pravé kľúče.
3. Server s klientom sa dohodnú na šifrovaní.
4. ODTERAZ je obsah packetov zašifrovaný SSL \ TLS(TRANSPORT LAYER SECURITY)

>[!warning]
>VIZUÁLNA KONTROLA V BROWSERI = 
><li>NAĽAVO OD ADRESY SVIETI ZAMKNUTÁ VISIACA ZÁMKA.</li>
><li>SKONTROLUJ PLATNOST CERTIFIKATU</li>
><li>!!! POZOR !!! OKREM PLATNOSTI SKONTROLUJ CI CERTIFIKAT BOL VYDANY NA CIELOVU DOMENU   go.ogle.com NIE JE google.com !!!</li>

## 7.6.1
MITM - MAN IN THE MIDDLE - Utok hackerov kde podstrcia obeti svoj certifikat a kluc cim sa dostanu k nezasifrovanemu obsahu sifrovaneho spojenia. Obet ani cielovy SERVER povazuju komunikaciu za zabezpecenu. Jedina vec co nesedi je, ze CERTIFIKAT je vydany na inu domenu. 


 ![MAN IN THE MIDDLE ATTACK ](MITM.png)


##### 7.6.0 KOMUNIKÁCIA POMOCOU HTTP REQUESTOV

HTTP a HTTPS komunikujú so serverom pomocou tzv. REQUESTOV tzv požiadaviek. Pochopenie tohoto konceptu je aj pochopenie moderneho Internetu.

##### 7.6.1. GET request

Najčastejšia požiadavka je GET request, ziskaj obsah stranky. 

Na posielanie requestov použijeme program curl , ktorý dokáže komunikovať s mnohými protokolmi. Možnosti sú až desivé.
``` powershell
curl https:\\fortisauris.online

curl -X POST https://fortisauris.com -d "param1=value1&param2=value2"

curl -X PUT https://fortisauris.com/resource/1 -d "param1=value1&param2=value2"

curl -X DELETE https://example.com/resource/1

```
Ak server náš request vybavil vráti sa OK kód 200 a požadovaný obsah zo serveru, ktorý možno zobraziť v browseri alebo kde treba : )

Odpoveď obsahuje HEADERS a CONTENT v HTML alebo inom formate.

Ak náš request smeruje na neexistujúcu url adresu vráti sa FILE NOT FOUND a  kód 404. To znamená, že požadovaná stránka alebo súbor neexistuje.

##### 7.6.2 POST request

HTTP protokol nám umožňuje informácie nielen sťahovať zo serveru ale aj posielať informácie na server prostredníctvom POST requestu. Týmto spôsobom sa môžeme logovať, vypĺňať všakovaké formuláre, feedbacky, vkladať informácie do databáz, chatovať, blogovať, reagovať a pod.
```powershell
curl --request POST --header "Content-Type: application/json" --data '{"username":"meno", "heslo":"veslo"}'  https:\\fortisauris.com
```

##### 7.6.3 INE requesty
Okrem týchto dvoch najčastejších requestov HTTP a HTTPS poznajú aj PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT a TRACE

``` powershell
curl -X POST https://example.com/api -H "Content-Type: application/json" -d '{"key1":"value1", "key2":"value2"}'

```

##### 7.6.4 JEDNODUCHA AUTENTIFIKACIA

``` bash & powershell
# meno a heslo
curl -u username:password https://example.com/protected

# bearer token
curl -H "Authorization: Bearer YOUR_TOKEN" https://example.com/protected`
```

>[!warning]
>CSRF (Cross-Site Request Forgery) je útok, pri ktorom útočník prinúti užívateľa, aby nevedomky vykonal neželanú akciu na webovej stránke, na ktorú je prihlásený. Útočník využije dôveryhodnosť, ktorú má prehliadač voči cieľovej stránke, a pošle škodlivú požiadavku s platnými autentifikačnými údajmi obete. Tento útok môže spôsobiť napríklad neúmyselný prevod peňazí alebo zmenu údajov bez vedomia obete.


#### 7.7 SMB Server Message Block protokol

Protokol, ktorý nám umožňuje zdieľať rôzene zariadenia na sieti ako disky, tlaciarne a pod. 

7.7.1 Install SAMBA server


NA STRANE LINUXOVEHO SERVERA
``` bash
sudo apt-get update
sudo apt-get install samba

sudo nano /etc/samba/samba.conf

sudo smbpasswd -a user

sudo service smdb restart
```

NA STRANE LINUXOVEHO KLIENTA:

```bash
smbclient -U user //host_ip/user
smbclient -U user%heslo //host_ip/user

```

``` samba
get file

recurse ON
mget *
```

```powershell
Get-SmbShare

New-SmbMapping -RemotePath '\\server\share' -Username '\domain\username' -Password 'heslo'

New-PSDrive -Name 'X' -PSProvider 'Filesystem' -Root '\\server\share' -Credential () #



```

### 8. ZAKLADNA SEGMENTACIA SIETE

8.1 Chránená LAN - interna siet s danym stupnom ochrany
Intranet, databazove servery, pocitace obsahujuce citlive data.


8.2 DMZ - demilitarizovana zona - miesto kde su umiestnene servery volne pristupne z internetu


 ![ETHERNET TOPOLOGY ](LANwDMZ.png)







## CVICENIE 3 SIETE A LOGY V POWERSHELLY
#### Check Network Status

``` powershell
`Get-NetAdapter`

`Get-NetIPConfiguration`

```

#### Check Event Logs for Errors

``` powershell
`Get-EventLog -LogName System -EntryType Error -Newest 10`

`$reportPath = "C:\Users\YourUsername\Desktop\PC_Diagnostics_Report.txt" (Get-ComputerInfo | Out-String) > $reportPath (Get-WmiObject -Query "SELECT * FROM Win32_Processor" | Out-String) >> $reportPath (Get-WmiObject -Class Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory | Out-String) >> $reportPath (Get-WmiObject -Class Win32_PhysicalMemory | Out-String) >> $reportPath (Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free, @{Name="Used(GB)";Expression={[math]::round($_.Used / 1GB, 2)}}, @{Name="Free(GB)";Expression={[math]::round($_.Free / 1GB, 2)}} | Out-String) >> $reportPath (Get-NetAdapter | Out-String) >> $reportPath (Get-NetIPConfiguration | Out-String) >> $reportPath (Get-EventLog -LogName System -EntryType Error -Newest 10 | Out-String) >> $reportPath`

# vsetky uspesne loginy do tohoto pocitaca
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} | Select-Object TimeCreated, @{Name='User';Expression={$_.Properties[5].Value}}, @{Name='LogonType';Expression={$_.Properties[8].Value}} | Format-Table -AutoSize

```

