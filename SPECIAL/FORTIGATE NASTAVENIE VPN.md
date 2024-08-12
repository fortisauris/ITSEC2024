

Použijeme akékoľvek zariadenie FORTIGATE

IPSEC spojenie 

#### **1.1 LOCAL USER

1. CREATE VPN USER
2. Local User
3. Meno a heslo
4. Urob Usergroup VPN type Firewall

#### **1.2 VPN GROUP

Vytvorime skupinu vpnusers 
VPN type Firewall

#### **1.3 IPSEC WIZARD 

Meno
Remote Access
FortiClielnt
Incoming Interface WAN
Preshared KEY
SELECT USER GROUP
Interface a IP

Rozsah pridelovanych IP adrsies VPN 

AUTOMATICKY SI NASTAVI AJ FIREWALL


VPN CLIENT FortiVPN appka 
meno
REMOTE GATEWAY
PRESHARED KEY
SAVE

USERMNAME 
PASSWORD
CONNECT


#### ** NEZABUDNI NA 2FA 
Pri pripojení cez VPN FortiGate podporuje dvojfaktorovú autentifikáciu (2FA) prostredníctvom nasledovných riešení:

1. **FortiToken**: FortiToken je integrovaný do FortiGate a poskytuje hardvérové alebo softvérové tokeny na generovanie jednorazových hesiel (OTP). Tieto OTP sú použité ako druhý faktor pri prihlásení cez VPN.

2. **Google Authenticator**: FortiGate umožňuje použiť Google Authenticator ako druhý faktor na prihlásenie do VPN. Po zadaní hesla používateľ zadá jednorazové heslo generované touto aplikáciou.

Tieto riešenia zaisťujú, že prístup k VPN bude chránený okrem bežného hesla aj ďalším bezpečnostným faktorom.