# 🕵️‍♂️ UNIT 42 - Quiz Wireshark, Février 2023

🔍[Source](https://unit42.paloaltonetworks.com/feb-wireshark-quiz/) 

✅[Réponses officielles](https://unit42.paloaltonetworks.com/feb-wireshark-quiz-answers/)

---

## 📌 Contexte

- La capture réseau simule une infection par le malware Qakbot dans un environnement Active Directory (AD).
- Le domaine cible est `WORK4US.ORG`, avec un contrôleur de domaine identifié à l’adresse IP `10.0.0.6`.
- Tâche de fournir un rapport d'incident pour documenter l'infection.

### Données spécifiques du LAN :
- LAN : `10.0.0[.]0/24`
- Domain : `WORK4US[.]org`
- Domain Controller IP : `10.0.0[.]6`
- Domain Controller Host : `WORK4US-DC`
- LAN Gateway : `10.0.0[.]1`
- LAN Broadcast : `10.0.0[.]255`


---

## 🧰 Outils utilisés

- [Wireshark](https://www.wireshark.org/download.html)
- [Kali Linux](https://www.kali.org/)
- [VMware](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## 🕵️‍♂️ Rapport d'incident
<details>
  
### 📌 Résumé

Le 2023-02-03 à 17:04 UTC, un poste Windows appartenant à `Damon Bauer` a été compromis par un malware **Qakbot** (aussi connu sous Qbot/Pinkslipbot) dans un environnement **Active Directory** (AD).

L’infection a généré du **trafic malveillant**, instauré une **backdoor** et initié des **communications** avec plusieurs serveurs C2 externes.

Des indices suggèrent une **propagation** possible vers le contrôleur de domaine (`10.0.0.6`), augmentant significativement le risque pour l'ensemble du domaine `WORK4US.ORG`.

<img src="images/killchain.png" alt="killchain" width="800"/>

  [*Source image*](https://securelist.com/qakbot-technical-analysis/103931/)

---

### 🖥️ Détails de la victime

- Utilisateur : `damon.bauer`
- Host : `DESKTOP-E7FHJS4`
- IP locale : `10.0.0[.]149`
- Adresse MAC : `00:21:5d:9e:42:fb`

---
### 🚨 Indicateurs de compromission (IoCs)

- Port 80 → `hxxp://128.254.207[.]55/86607.dat`
- `102.156.32[.]143:443` — HTTPS/SSL/TLS
- `208.187.122[.]74:443` — HTTPS/SSL/TLS
- `5.75.205[.]43:443` — HTTPS/SSL/TLS
- `23.111.114[.]52:65400` — TCP traffic
- `78.31.67[.]7:443` — TCP traffic (activité VNC)
- Diverses adresses IP sur ports TCP **25** et **465** — **SMTP** vers plusieurs serveurs de messagerie
- **ARP scanning** depuis l’hôte infecté
- **Transfert SMB** entre l’hôte compromis et le contrôleur de domaine

### ☣️ Détails du Malware :

- SHA 256 : `713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432`
- Type : DLL 32-bit
- Taille : 1,761,280 bytes
- Description : DLL utilisée par Qakbot
- Méthode d'exécution : `rundll32.exe [filename],Wind`
- Sample disponible sur [MalwareBazaar](https://bazaar.abuse.ch/sample/713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432/)
- Community Score de 55 / 72 sur [VirusTotal](https://www.virustotal.com/gui/file/713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432/details)

</details>

---

## 📝 Méthodologie
<details>

### 💡 IP local
<details>
  
Examiner le trafic web suspect en filtrant les requêtes HTTP et les handshakes TLS.  

`(http.request or tls.handshake.type == 1) and !(ssdp)`

➡️ IP source : `10.0.0[.]149`  
➡️ Adresse MAC : `00:21:5d:9e:42:fb`

<img src="images/1.png" alt="1" width="800"/>

</details>

---

### 💡 Hosts
<details>

Identifier le nom NetBIOS et le nom d'hôte Windows en analysant les protocoles de partage. 

`nbns or smb or smb2`

➡️ Host name : `DESKTOP-E7FHJS4`

<img src="images/2.png" alt="2" width="800"/>

---

Examiner le trafic d'authentification Kerberos pour identifier l’utilisateur :  

`kerberos.CNameString && ip.src == 10.0.0.149`  
- 📝 N.B. : Ajout de `CNameString` en colonne pour faciliter l’identification.

➡️ Utilisateur : `damon.bauer`

<img src="images/3.png" alt="3" width="800"/>

</details>

---

### 💡 Trafic HTTP
<details>

Analyser le trafic HTTP non chiffré pour identifier l'origine de l’infection :   

`http && ip.src == 10.0.0.149`

➡️ HTTP GET suspect vers une IP externe `128.254.207[.]55` → **investigation**  
➡️ HTTP GET vers `cacerts.digicert.com` → trafic légitime généré par OS/navigation normale  

<img src="images/4.png" alt="4" width="800"/>

Suivre le **TCP Stream** pour la requête suspecte vers `128.254.207[.]55` pour le fichier `86607[.]dat` :    
➡️ Headers minimalistes, présence de `CURL` → téléchargement automatisé  
➡️ Fichier exécutable (`MZ` + `This program cannot be run in DOS mod`)  

<img src="images/5.png" alt="5" width="800"/>

---

Exporter le fichier depuis le PCAP : `File → Export Objects → HTTP`  

Après téléchargement :     
✅ Vérification type de fichier : `file 86607.dat` == DLL Windows  
✅ Hash SHA256 : `shasum -a 256 86607.dat`  
✅ [VirusTotal](https://www.virustotal.com/gui/file/713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432/details) : détecté par plusieurs fournisseurs

<img src="images/6.png" alt="6" width="800"/>  
<img src="images/7.png" alt="7" width="800"/>

</details>

---

### 💡 Trafic Post-Infection
<details>

#### HTTPS sans SNI (Server Name Indication)
Filtrer le trafic HTTPS sans nom de domaine :    
`tls.handshake.type == 1 and tls.handshake.extension.type != 0`  
- 📝 N.B. : Les connexions directes vers une IP sont rares et souvent utilisées par des malwares (Qakbot, Trickbot, Emotet).
  
---
#### Trafic C2
Lister les endpoints IPv4 : `Statistics → Endpoints`  

- Repérer les adresses IP externes des serveurs C2 contactées par l’hôte infecté `10.0.0[.]149`.  
➡️ `5.75.205[.]43`  
➡️ `102.156.32[.]143`  
➡️ `208.187.122[.]74`

<img src="images/8.png" alt="8" width="800"/>

---

#### Certificats TLS
Vérifier les certificats TLS (`11`) pour chaque IP :  
`tls.handshake.type == 11 and ip.addr == <IP_C2>`
   
Examiner `rdnSequence` :  
➡️ `102.156.32[.]143` et `208.187.122[.]74` = Valeurs aléatoires, typique de Qakbot  
➡️ `5.75.205[.]43` = Domaine spoofed/inactif (`vipsauna[.]com`) → certificat auto-signé C2  

<img src="images/9.png" alt="9" width="800"/>
<img src="images/10.png" alt="10" width="800"/>

---

#### Trafic C2 (:65400) 
Trafic initié (`SYN == 2`) sur TCP Port `65400` :  
`tcp.port == 65400 && tcp.flags == 2`  

➡️ IP C2 contactée : `23.111.114[.]52`  

<img src="images/11.png" alt="11" width="800"/>

Lorsqu'on suit le TCP Stream, on trouve rapidement les informations de l'hôte infecté :  
➡️ Hôte (string) : `jzbxct683972`  
➡️ IP publique de l'hôte : `71.167.93[.]52`  
- 📝 N.B. : Ce flux est typique d'un malware qui envoie immédiatement des informations sur la victime au serveur C2 pour établir un contrôle initial.  


<img src="images/12.png" alt="12" width="800"/>


---
#### Spambot
Filtrer le trafic `SMTP` pour détecter l'activité de **Spambot** :  
`smtp && ip.src == 10.0.0.149`  

➡️ L’hôte infecté contacte plusieurs serveurs mail publics == suspect dans un environnement AD.

<img src="images/13.png" alt="13" width="800"/>

Plus spécifiquement, on peut détecter/quantifier l'activité du Spambot avec la commande `EHLO` :  
`smtp.req.command contains "EHLO" && ip.src == 10.0.0.149`  

➡️ au moins 5 tentatives de connexions en ~10 minutes = 🚩

<img src="images/14.png" alt="14" width="800"/>

Pour voir l'ensemble du trafic (unencrypted ET encrypted) :  
`tls.handshake.type == 1 and (tcp.port == 25 or tcp.port == 465 or tcp.port == 587) && ip.src == 10.0.0.149`  

➡️ au moins 25 serveurs contactés en ~20 minutes == 🚩 
- 📝 N.B. : Aucun email spambot disponible à analyser/export (`File → Export Objects → IMF`)

<img src="images/15.png" alt="15" width="800"/>
<img src="images/16.png" alt="16" width="800"/>

Verdict :  
✅ L’hôte infecté tente d’envoyer des emails en masse  
✅ Confirme une activité spambot post-infection  
✅ Permet d’identifier la portée de l’infection et les serveurs ciblés  

---

#### Trafic VNC
Protocole de partage de bureau à distance, VNC permet aux acteurs malveillants de prendre le contrôle d'un hôte infecté.
- 📝 N.B. : L'adresse IP `78.31.67[.]7` sur le port TCP `443` est un serveur C2 connu associé au malware Qakbot.  

`ip.addr == 78.31.67[.]7 && tcp.flags == 2`

2 flux TCP détectés :  
➡️ Premier flux : motif répétitif de 13 octets  
➡️ Second flux : flux RFB contenant la **mention ASCII VNC**, indiquant le partage de bureau à distance   
- 📝 N.B. : Cette séquence est caractéristique d’un malware exploitant VNC pour contrôler l’hôte à distance.

<img src="images/17.png" alt="17" width="800"/>
<img src="images/18.png" alt="18" width="800"/>


---

#### ARP Scanning
Les attaquants utilisent parfois le ARP scanning pour découvrir d’autres adresses IP actives sur un **réseau compromis**.  
Cela se fait au niveau des **adresses MAC**, en envoyant des requêtes ARP à l’adresse de broadcast `ff:ff:ff:ff:ff:ff` pour toutes les IP d’un segment réseau.  

Dans ce PCAP, l’hôte infecté (`00:21:4d:9e:42:fb`) balaie le segment de `10.0.0[.]254` à `10.0.0[.]2`.   
`arp && eth.dst == ff:ff:ff:ff:ff:ff`

Les adresses déjà connues sont exclues :  
➡️ Hôte infecté : `10.0.0[.]149`   
➡️ Contrôleur de domaine : `10.0.0[.]6`  
➡️ Passerelle réseau : `10.0.0[.]1`  
➡️ Adresse broadcast : `10.0.0[.]255`  

Si l’hôte infecté détecte une IP active, il envoie un ping `ICMP` puis tente de se connecter sur différents ports TCP/UDP.
- 📝 N.B. : Technique n’est pas spécifique à Qakbot et a été observée avec Bumblebee, IcedID, Emotet et d’autres familles de malware. 

<img src="images/19.png" alt="19" width="800"/>
<img src="images/20.png" alt="20" width="800"/>

---
#### SMB
Analyse des transferts SMB pour identifier les fichiers suspects : `File → Export Objects → SMB`  
- 📝 N.B. : Fichiers `DLL` avec des **noms aléatoires** == 🚩, confirment une activité post-infection dans l'AD.  

<img src="images/21.png" alt="21" width="800"/>

➡️ Fichiers `.dll` (1,761 KB) : DLL Windows     
➡️ Fichiers `.bin.cfg` (105 bytes) : fichiers de données binaires  
➡️ SHA256 : `713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432` = Identique au DLL initial récupéré via HTTP au début de l’infection   


<img src="images/22.png" alt="22" width="800"/>
<img src="images/23.png" alt="23" width="800"/>


SMB2



</details>

</details>



---











