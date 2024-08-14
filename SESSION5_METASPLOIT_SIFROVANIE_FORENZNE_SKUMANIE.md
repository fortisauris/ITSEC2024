
## B. METASPLOIT FRAMEWORK- UKÁŽKA 

METASPLOIT je exploitačný framework obsahujúci tisíce možností ako sa nabúrať do Vašeho počítača. Jeho použitie zvládne aj začiatočník. Vie na diaľku využiť zraniteľnosť Vašeho počítača a získať do neho prístup. Vie vytvárať škodlivé kódy, ktoré na Vašom počítači vytvoria backdoory, reverzné shelly, získajú informácie či prístup do shellu. 

auxiliary = rozne nastroje ako scannery, 
exploit = vyuzitie zranitelnosti systemu na ziskanie kontroly alebo informacii
payload  = skodlivy kod ktory treba spustit u USERA
post- CITTE SA AKO DOMA
NOP = Maskovanie pred AV a IDS

``` metasploit

search windows
use module
show info
set RHOST
CMD: exploit, run, payload

sessions -l
sessions -i <CISLO>
background
```



msfvenom = softver na vytvaranie suborov infikovanych PAYLOADOM

meterpreter = VIAC AKO SSH SHELLt

>[! warning ]
>VYBRANE PRIKAZY METERPRETERU:
>keyscan_start = spustenie KeyLoggera, ktorý zaznamenáva všetky stlačené klávesy
>migrate PID = meterpreter sa schová do iného bežiaceho procesu
>screenshot = spraví screenshot obrazovky
>clearev - vymaže všetky zmienky o prítomnosti Hackera z logov. 


## C. KRYPTOGRAFIA

### C.1 Historické šifry
a.  Scytale 
b. Cézarova šifra a ROT13
c. Albertiho Sifrovaci disk 
d. Vernamova šifra

### C.2 ENIGMA - STROJ vs ČLOVEK

Enigma bola elektromechanický šifrovací stroj používaný na šifrovanie komunikácie medzi jednotkami Nacistického Nemecka. Problémom boli predovšetkým útoky nemeckých ponoriek v Atlantiku. 

Alan Turing a tým jeho kryptoanalytikov v Bletchley Park,  postavil prvý počítač, ktorý dokázal túto šifru prelomiť a čítať tieto správy. Operácia ULTRA bola prísne utajená.

### C.3 ADVANCED ENCRYPTION STANDARD

Elektromechanické šifry na báze rotorov slúžili až do 70tych rokov. Potom ich postupne nahrádzala počítačová kryptografia v podobe algoritmu DES a neskôr Triple DES. V 1997 roku NIST (National Institute of Standard and Technology) vypísala súťaž o nový šifrovací štandard. Do súťaže sa prihlásilo viacero kryptografických algoritmov. Vyhral algoritmus menom Rjijandel od Belgických autorov, druhý bol Serpent.

AES256 sa stalo štandardom šifrovania pre priemysel a ochranu utajovaných skutočností. 

V súčasnosti sa uvažuje už o novom štandarde šifrovania. Favoritom sa stáva algoritmus ChaCha.

### C.4 PRINCIPY MODERNÝCH ALGORITMOV
Moderné šifrovanie je založené na jednoduchých matematických a logických operáciach ako je XOR, posun bitov, miešanie matric a podobne. Tieto operácie sa opakujú niekoľkokrát aby ich nebolo možné bez kľúča prelomiť.

#### C.4.1   OPERACIA XOR A NAHODNE CISLA

Ukážeme si jednoduchú operáciu XOR v Pythone
``` python

import random   # NEPOUZIVAT NA KRYPTOGRAFIU !!! 


def apply_xor_operation(value : str, key : str):
    """
    Funkcia aplikuje vypocet bitwise XOR hodnoty a kluca hexadecimalne cislo 0x00 do 0xff v STRINGU.
    Vysledkom je hexadecimalne cislo od 00 do FF tj. 0 do 255.
    parameter::: value - STRING s hex cislom od 0x00 do 0xff
    parameter::: key - STRING s hex cislom od 0x00 do 0xff
    return ::: vysledok vypoctu - hex cislom od 0x00 do 0xff
    """
    value = eval(value)
    key = eval(key)
    return hex(value ^ key)  # tuto sa deju zazraky 


if __name__ == "__main__":
    value = hex(random.randint(0,255))
    key = hex(random.randint(0,255))
    print("VALUE : ", value, " KEY : ", key," RESULT : ",apply_xor_operation( value, key))
```

Aby moderné šifry správne fungovali a kľúče ktoré sa používajú sú tvorené z vygenerovaných náhodných čísel. Ak by čisla neboli dostatočne náhodné dal by sa vytvoriť vzorec a množstvo pravdepodobných kľúčov by sa nám podstatne zúžilo. Preto treba používať generátory pseudonáhodných čísel určené na kryptografiu a nie python modul `random` .


#### C.4.2 VYSOKÉ PRVOČÍSLA

Vysoké prvočísla majú v modernej kryptografii špecifickú úlohu. Ich vlastnosťou je, že sú všade rovnako vypočítateľné a pritom jedinečné. 

#### C.4.3 RYCHLE SIFROVANIE DATOVYCH STREAMOV

AES256 je algoritmus, ktorý môžeme použiť na šifrovanie súboru, disku USB kľúča, mailu a pod. Nie je však vhodný na šifrovanie obrovských streamov dát z jednej IP na druhú ako je VIDEO, ZVUK a pod. Napriek tomu potrebujeme tieto dáta ochrániť. Použijeme jednoduchšie a rýchlejšie formy šifrovania.

``` python
# PRINCIP SBOXU
sbox = [45, 12, 56,9,11,78,120,]
znak_na_zasifrovanie = 65 # ASCII HODNOTA A

def sbox_enc(sbox, znak_na_zasifrovanie)
	'''
	Funkcia SBOX prechadza SBOXOM a zakazdym hodnotu XORuje s dalsim cislom v SBOXE
	SBOXOV byva niekolko za sebou a operacii vela. Vysledkom je totalne
	modifikovana hodnota 65
	'''
	enc = znak_na_zasifrovanie # 
	for i in sbox:
		enc = enc ^ i
	print('VYSLEDOK JE: ', enc)
	# NA DESIFROVANIE STACI OTOCIT PORADIE SBOXU A PREHNAT HODNOTU NASPAT
	return enc

def jednoduchy_permutacny_box(hex_cislo):
	'''
	Hexadecimalna hodnota vstupuje do PERMABOXU nemodifikovana a podla nastavenej 
	modifikacie vychadza z PERMABOXU pozmenena. Opakovaniami v kombinacii s
	dalsimi operaciami mozno vstupnu hodnotu zmenit niekolkokrat. Funguje podobne
	 ako Enigma PLUGBOARD
	'''
	if hex_cislo == '0x0':
		return '0x5'
	if hex_cislo == '0x1':
		return '0xa'
	if hex_cislo == '0x2':
		return '0x3'
	if hex_cislo == '0x3':
		return '0xa'
	if hex_cislo == '0x4':
		return '0xf'
	else:
		return hex_cislo
	
if __name__ == "__main__":
	sbox_enc(sbox, znak_na_zasifrovanie)
	jednoduchy_permutacny_box('0x4')

```


#### C.4.4 ASYMETRICKÁ VÝMENA KĽÚČOV

Problém symetrického šifrovania je, že obe strany musia disponovať rovnakým kľúčom. TO je celkom technická výzva ako tento kľúč doručiť niekomu bez toho aby nemohlo dôjsť ke jeho kompromitácii. 

Asymetricke šífrovanie je postavené na pároch vygenerovaných kľúčov a pomocou zložitého matematického výpočtu si vedia počítače dohodnúť spoločný kľúč. Pomocou neho môžu prejsť na symetrické šifrovanie, ktoré je oveľa rýchlejšie.

PUBLIC = verejný kľúč môžete poslať hocikomu
PRIVATE = súkromný kľúč musíte chrániť ako oko v hlave.

``` python
# ASYMETRICKA VYMENA KLUCOV DIFFIE-HELLMAN

# ALICA
AlicineTajomstvo = 75433

# BOB
BoboTajomstvo = 56575

# Server
g = 5472437625635634658438583468564336543654365346546534 # nahodne vybrane cislo
n = 911 # prvocislo

# Alica ide poslat Bobovi kluc
A_posiela =(g ** AlicineTajomstvo) % n
print("ALICA POSIELA", A_posiela)
# Bob ide poslat kluc Alici
B_posiela = (g ** BoboTajomstvo) % n
print("BOB POSIELA", B_posiela)

# Alica otvara Bobov kluc
Bobov_kluc = (B_posiela ** AlicineTajomstvo) % n
print("Bobov zdielany kluc",Bobov_kluc)

# Bob otvara Alicin kluca
Alicin_Kluc = (A_posiela ** BoboTajomstvo) % n
print("Alicin Zdielany kluc",Alicin_Kluc)
```


#### C.4.5 BUDUCNOST


Moderné metódy šifrovanie strážia nielen naše tajomstvá, ale aj súkromie, biometrické dáta či zdravotné záznamy. V súčasnosti sme si hovorili o ZERO TRUST trende v IT SEC. Aká je budúcnosť šifrovania ? Šifrovanie bude naďalej zohrávať kľúčovú rolu v našom živote. 

Kvantové počítače len zvýšia tlak na vytváranie nových a mocnejších šifier. Šifrovacie algoritmy sú obávaným nepriateľom Autokratických systémov kde je ľuďom upieraná sloboda. Často sú za použitie šifrovacieho algoritmu vysoký trest. Preto slobodne šifrujte ... 


# A. SKUMANIE INCIDENTU ON SITE

Dnes bude rušný deň Ranný telefonát neveští nič dobrého. Kybernetický zločin bujnie na našej sieti. Podľa plánu zvozu sa IRT (Náš Incident Response Tým) dáva do pohybu smer serverovňa. Cestou sa ešte zastavujeme na kávu ... TakeAway :)

## A.1 PASÍVNY PRIESKUM 
#live_forensics

Rozdeľujeme sa do trosch skupín s cieľom zhromaždiť pasívne to znamená bez zásahu do LAN čo najviac informácií o INCIDENTE. Jedna skupina kontruluje `eve.json`  dátový výstup zo Suricaty IDS. ďalšia skupina prehrabáva Logy. Akonáhle sa niečo dozvieme informujeme ostatné skupiny a zapíšeme si čas a miesto kde sa udalosť stala ako aj IP či MAC adresy aktérov.
Posledná skupina má na starosti záznamy v .pcap. Vyzerá to tak, že útok sa udial v čase keď väčšina Endpoitov bola vypnutá. To znamená, že komunikácie bude menej ako vo všedný pracovný deň. Vďaka IDS a centralizovaným logom neprešlo od napadnutia veľa času a je možné, že malware alebo hackeri sú v RECON fáze a zatiaľ nebrnkli na žiaden náš HONEYPOT v chránených segmentoch LAN. 

ZDROJE PASIVNEHO PRIESKUMU:
<li>nahrate .pcap na Suricate, alebo 24/7 nahravky </li>
<li>Log Management, logy, Event-Log</li>
<li>suricata eventy</li>



KOMPROMITACIA SYSTEMU:
Neobvykla komunikacia zo siete
Neobvykla komunikacia medzi klientami
Neobvykle pouzitie Privilegovanych prav
Aktivita Usera z neobvyklych IP
Viacero nepodarenych loginov  (4625, 4771, 4772)
Neobvykle zadania SQL do databazy - netypicke pokusy o ziskanie info z tabuliek
Zmeny v Registri a v suborovom systeme
Neobvykle poziadavky na DNS
Neobvykle casy Patchov a Updatov (Nie podla harmonogramu)
Nevysvetlitelne subory na DMZ produkcnych serveroch Zasifrovane subory!!!
Neobvykle vyuzitie browsera - vela requestov za min, Pulzne vyuzitie, Dlhe URL
Zmeny v spustenych servisoch - PRESNY ZOZNAM
Nahle vytvaranie, zmeny  USEROV, ADMINOV - PRIVILEGE ESCALATION

Teraz máme začíname predstavu, kedy a ako sa dostal útočník na LAN.


## A.2 AKTIVNY PRIESKUM
#live_forensics

### A.2.1  MEMORY DUMP BEZIACEHO POCITACA
#live_forensics
Ak je na napdnutom počítači nejaký škodlivý kód aktívny bude určite spustený v nejakom bežiacom procese, alebo schovaný niekde v pamäti počítača. Najrozumnejšie preto je, skôr ako podnikneme ďalšie kroky získať kópiu pamúti pomocou špecálneho forenzného nástroja pre Windows alebo v Linuxe pomocou príkazu:

``` bash
cat /dev/mem  
memdump -h

```



Ak beží počítač vo VM v Sandboxe môžeme ho spustiť v tzv. Debugger móde a skúmať jeho obsah.
``` powershell
C:\Program Files\Oracle\VirtualBox>vboxmanage startvm "kali_nessus" -E VBOX_GUI_DBG_AUTO_SHOW=true -E VBOX_GUI_DBG_ENABLED=true
```

DEVOPS: DEBUGGER je program, ktorý nám umožňuje pomocou BREAKPOINTOV a KROKOVANIA umožňuje zastavovať a skúmať vnútro bežiaceho programu. Tieto programy sa používajú na nájdenie chýb v kóde, ale aj na pochopenie jeho aktivít ako je to pri REVERZNOM INŽINIERSTVE. 

Ak sa nám podarilo získať kópiu pamäte môžeme ju preskúmať úžasným pythonovským nástrojom Volatility:
https://github.com/volatilityfoundation/volatility


### A.2.2  NMAP ATTACK MODE

Na zistenie zmien na sieti môžeme použiť NMAP nastavená v Attak móde. Zistí nám všetky podrobnosti o počítačoch pripojených v segmente siete. 

``` bash
nmap -T4 -A -v IP/24
```

### A.2.3 WINDOWS FORENSIC TOOLKIT A INE STARINY

Aby sme mali predstavu ako funguje zbieranie dát z jednotlivých počítačov 
UKAZKA - WFT Windows Forensic Toolchest  posledna verzia z 2014

>[!warning]
>POZOR NA STARY SOFTVER
WFT, WinPE a podobne sú staré nástroje, ktoré už nemusia slúžiť ako by mali.


### A.2.4 GOOGLE GRR

Tento nástroj slúži na automatizované skúmanie počítačov na diaľku

Vzdialeny monitoring systemu pomocou Python Clien/Server
https://github.com/google/grr

1. POTREBUJEME MYSQL ALEBO MARIADB SERVER S PRAZDNOU DATABAZOU
``` bash
sudo apt install mysql-server  # ALEBO mariadb-server

sudo mysql -u root -p
HESLO: *****

```


``` sql
CREATE USER 'grr'@ 'localhost' IDENTIFIED BY 'password';
CREATE DATABASE grr;
GRANT ALL ON grr.* to 'grr' @ 'localhost';
exit
```

2. NAINŠTALOVAŤ GRR Z GOOGLEAPIS
``` bash
wget https://storage.googleapis.com/releases.grr-response.com/grr-server_3.4.6-7_amd64.deb   # alebo 3.2.4-6
sudo dpkg -i grr-server_3.2.4-6_amd64.deb
sudo apt-get install -fsudo dpkg
systemctl status grr-server

```
3. GRR SERVER Môžeme nainštalovať aj do Docker kontajneru
``` bash & powershell

docker run --name grr-server --ip 172.17.0.1 -e EXTERNAL_HOSTNAME=localhost -e ADMIN_PASSWORD=demo -p 0.0.0.0:8080:8080 ghcr.io/google/grr:v3.4.6.7
```

warning POZOR NA ŠIFROVANIE. POUŽITIE GRR VYŽADUJE NASTAVENIE ŠIFROVANIA MEDZI KLIENTO A SERVEROM 

4. GRR obsahuje inštalačny pre všetky druhov klientov od Windows, Linux až po MacOS. Tieto inštalačky stiahneme a spustíme na klientovi. 

5. Vytvorime kontajner s klientom:

``` bash & powershell

docker run --name grr-server --ip 172.17.0.2 -e EXTERNAL_HOSTNAME=localhost -e ADMIN_PASSWORD=demo -p 0.0.0.0:8080:8080 ghcr.io/google/grr:v3.4.6.7
```

DEBIAN KLIENTA SKOPIRUJEME DO URCENEHO DEBIAN ALEBO UBUNTU DOCKER KONTAJNERU:
``` bash & powershell
docker cp '.\grr_3.4.6.7_amd64.deb' ID_CONTAINER:/home/user/
```

# TOTO BUDE POKRACOVAT...





### A.2.5 DALSIE UZITOCNE PRIKAZY PRE WINDOWS

``` Powershell
netstat -naob
Taskmgr.exe
wmic qfe list
wmic product list
sigverif

```
### A.2.6 WAZUH

SIEM and XDR riesenie na Endpointy aj na server

### A.2.7 BITSCOUT
https://github.com/vitaly-kamluk/bitscout

### A.2.8 Fast Incident Response
https://github.com/certsocietegenerale/FIR

### A.2.9 Mozzila Mig
https://github.com/mozilla/mig

## A.4  DERATIZACIA
UKAZKA - MALWAREBYTES A SPYBOT Search and Destroy

DEZINFEKCIA TOOLS
malwarebytes.com
SPYBOT Search and Destroy -  safer-networking.com
SOPHOS
ClamAV



### A.5  UROBENIE KOPIE NAKAZENEHO SYSTEMU
WINDOWS : Passmark ImageUSB a potom  winiso
KALI - GUYMAGER robi specialne dd alebo svoje kopie

``` bash
dd if=/disk.dd of=/disk.iso bs=512
```



# B. FORENZIC MODE v KALI
#reverse_eng 

### B.1  HASHDEEP  - KRAL HASHOV

Pomocou hashovacích algoritmov vieme urobiť otlačok každého spistiteľného súboru v počítači. Hashdeep vie aj analyzovať a porovnávať súbory, adresáre či v nich nedošlo k zmene. 

``` bash
hashdeep -r ADRESAR > subor_s_hashmi
hashdeep -a -k subor_s_hashmi -r ADRESAR
```


### B.2 BINWALK - POROVNAVANIE DUMPOV

Ak sme vytvorili zoznam modifikovaných súborov a ak máme niekde originál súboru s inštalačky systému, môžeme ich porovnať pomocou programu BINWALK. Tento program nám dokáže rýchlo nájsť rozdiely  a zozbraziť ich v požadovanom formáte.

binwalk -W FILE FILE

BINWALK vie porovnávať viacero súborov naraz.

POZOR NA ROZNE VERZIE TOHO ISTEHO PROGRAMU. MUSIME VŽDY POROVNAVAŤ ROVNAKÉ VERZIE 


### B.3 AUTOPSY

Na forenzné prezeranie diskov a ich imidžov použijeme AUTOPSY. Tento softvér je určený pre profesionálov akými sú súdni znalci a pod. VIeme prechádzať disk po sektorov, robiť si poznámky, vyhľadávať reťazce a súbory (ÁNO AJ TIE VYMAZANÉ) a pod. 



# C. REVERSE ENGENEERING

Reverzné inžinierstvo sa zapodieva spätným rozoberaním programov, ktoré by mohli obsahovať škodlivý kód alebo zraniteľnosť. 

STROJOVÝ KÓD  > ASSEMBLY > C > JAVA >  PYTHON

KOMPILOVANÝ KÓD je keď zdrojový kód programu pomocou kompilera preložíme do strojového kódu.


C.1 NASM - NETWIDE ASSEMBLER

TO čo je pre normálneho hackera Python3 je pre reverzného inžiniera C a ASSEMBLY. Znalosť týchto jazykov a použitia Debuggerov nám pomôže rozoberať programy na drobné a analyzovať ich zraniteľnosti aj účel. 

[NASM](https://nasm.us/)
ROZNA ARCHITEKTURA = ROZNA SADA INSTRUKCII


``` asm

## Hello World

section	.text
	global _start       ;must be declared for using gcc
_start:                     ;tell linker entry point
	mov	edx, len    ;dlzka spravy
	mov	ecx, msg    ;sprava na zapisanie
	mov	ebx, 1	    ;co s tym (stdout)
	mov	eax, 4	    ;systemove volanie (sys_write)
	int	0x80        ;zavolaj kernel a vykonaj
	mov	eax, 1	    ;systemove volanie (sys_exit)
	int	0x80        ;zavolaj kernel a vykonaj

section	.data

msg	db	'Hello, world!',0xa	;nas text ulozeny v bytoch
len	equ	$ - msg			;vypocitana dlzka naseho textu

```

``` bash 
nasm -f elf64 -o hello.o hello.asm  # skompiluje objekt file
xxd hello.o
ld -s -o hello hello.o  # zlinkuje objekt file na executable
./hello
binwalk -W hello hello.o
```

info ARCHITEKTÚRA 


### C.2 RADARE2 = SKUMANIE BINARNYCH SUBOROV A PROCESOV

DOBRÝ TUTORIÁL:
https://github.com/ifding/radare2-tutorial




rabin2 -I FILE.bin

JEDNORIADKOVY ASSEMBLER SKÚMA KÓD 
rasm2 -a x86 -b 64 "mov eax, 4"
rasm2 -a x86 -b 64 b804000000




Prepnut do vizual modu V

r2 -d FILE alebo PID

-aa

pdf @ funkcia

eco matrix




p sa prepinam medzi printovacimo modami
shift q quit

ma to vselikake debuggeyr a ine nastroje

