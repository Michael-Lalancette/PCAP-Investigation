## 🕵️‍♂️ MTA-quiz-feb2023 

🔍[Source](https://unit42.paloaltonetworks.com/feb-wireshark-quiz/) 

✅[Réponses officielles](https://unit42.paloaltonetworks.com/feb-wireshark-quiz-answers/)

---

### 📌 Contexte

- La capture réseau simule une infection par le malware Qakbot dans un environnement Active Directory (AD).
- Le domaine cible est `WORK4US.ORG`, avec un contrôleur de domaine identifié à l’adresse IP `10.0.0.6`.
- Tâche de founir un rapport d'incident pour documenter l'infection.

#### Données spécifiques du LAN :
- LAN : `10.0.0[.]0/24`
- Domain : `WORK4US[.]org`
- Domain Controller IP : `10.0.0[.]6`
- Domain Controller Host : `WORK4US-DC`
- LAN Gateway : `10.0.0[.]1`
- LAN Broadcast : `10.0.0[.]255`


---

### 🧰 Outils utilisés

- [Wireshark](https://www.wireshark.org/download.html)
- [Kali Linux](https://www.kali.org/)
- [VMware](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CyberChef](https://gchq.github.io/CyberChef/)

---

### 🕵️‍♂️ Rapport d'incident
<details>
  
#### 📌 Résumé

Le 2023-02-03 à 17:04 UTC, un poste Windows appartenant à `Damon Bauer` a été compromis par un malware **Qakbot** (aussi connu sous Qbot/Pinkslipbot) dans un environnement **Active Directory** (AD).

L’infection a généré du **trafic malveillant**, instauré une **backdoor** et initié des **communications** avec plusieurs serveurs C2 externes.

Des indices suggèrent une **propagation** possible vers le contrôleur de domaine (`10.0.0.6`), augmentant significativement le risque pour l'ensemble du domaine `WORK4US.ORG`.

<img src="images/killchain.png" alt="killchain" width="800"/>

  [*Source image*](https://securelist.com/qakbot-technical-analysis/103931/)

---

#### 🖥️ Détails de la victime

- Utilisateur : `damon.bauer`
- Host : `DESKTOP-E7FHJS4`
- IP locale : `10.0.0[.]149`
- Adresse MAC : `00:21:5d:9e:42:fb`

---
#### 🚨 Indicateurs de compromission (IoCs)

- Port 80 → `hxxp://128.254.207[.]55/86607.dat`
- `102.156.32[.]143:443` — HTTPS/SSL/TLS
- `208.187.122[.]74:443` — HTTPS/SSL/TLS
- `5.75.205[.]43:443` — HTTPS/SSL/TLS
- `23.111.114[.]52:65400` — TCP traffic
- `78.31.67[.]7:443` — TCP traffic (activité VNC)
- Diverses adresses IP sur ports TCP **25** et **465** — **SMTP** vers plusieurs serveurs de messagerie
- **ARP scanning** depuis l’hôte infecté
- **Transfert SMB** entre l’hôte compromis et le contrôleur de domaine

#### ☣️ Détails du Malware :

- SHA 256 : `713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432`
- Type : DLL 32-bit
- Taille : 1,761,280 bytes
- Description : DLL utilisée par Qakbot
- Méthode d'exécution : `rundll32.exe [filename],Wind`
- Sample disponible sur [MalwareBazaar](https://bazaar.abuse.ch/sample/713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432/)
- Community Score de 55 / 72 sur [VirusTotal](https://www.virustotal.com/gui/file/713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432/details)

</details>

---

### 📝 Méthodologie 
<details>
  
#### 💡 LOCAL IPs

Examiner le trafic web suspect en filtrant les requêtes HTTP et les tentatives de handshakes TLS. 

Utilisons le filtre suivant :
`(http.request or tls.handshake.type eq 1) and !(ssdp)`

Résultats : 
- IP source : `10.0.0[.]149`
- Adresse MAC : `00:21:5d:9e:42:fb`

<img src="images/1.png" alt="1" width="800"/>


---

#### 💡 HOST NAMES

Pour identifier le nom NetBIOS et le nom d'hôte WIndows de la machine compromise, il est recommandé d'analyser les protocoles de partage de fichiers.

Utilisons le filtre suivant :
`nbns or smb or smb2`

Résultats : 
- Host name : `DESKTOP-E7FHJS4`
  
<img src="images/2.png" alt="2" width="800"/>


Ensuite, il est possible d’examiner le trafic d’authentification Kerberos afin d’identifier le nom de l’utilisateur.

Utilisons le filtre suivant (N.B. que j'ai appliqué le CNameString en colonne pour mieux trouver l'information) :
`kerberos.CNameString && ip.src == 10.0.0.149`

Résultats : 
- Utilisateur : `damon.bauer`

<img src="images/3.png" alt="3" width="800"/>

---

#### 💡 HTTP (80)

Après avoir collecté les détails de la victime, trouver quand/où/comment le trafic malveillant a commencé en analysant le trafic HTTP non chiffré sur le port 80.

Utilisons le filtre suivant :
`http && ip.src == 10.0.0.149`

Résultats : 

Ce filtre retourne uniquement 2 entrées :
- La première entrée est un HTTP GET vers une adresse IP externe, ce qui est suspect et nécessite une investigation approfondie.
- La seconde entrée correspond à un HTTP GET vers `cacerts.digicert.com`, une requête typique générée par le système d’exploitation ou lors d’une navigation normale.

<img src="images/4.png" alt="4" width="800"/>

Suivre le TCP Stream pour la requête suspecte vers `128.254.207[.]55` pour le fichier `86607[.]dat`.

Résultats : 
- Request Headers minimaux (typique d'un téléchargement automatisé par un malware) - header contient `CURL`, indiquant un outil de téléchargement automatisé.
- Fichier exécutable (DLL ou .exe) - présence de la signature `MZ` et `This program cannot be run in DOS mode` confirment qu'il s'agit d'un exécutable Windows.

<img src="images/5.png" alt="5" width="800"/>

Exporter le fichier suspect depuis le PCAP

`File → Export Objects → HTTP`

Après le téléchargement du fichier :
- Il est analysé dans le terminal à l’aide de la commande file `86607.dat`, permettant de confirmer qu’il s’agit d’une DLL Windows.
- Le hash SHA256 est ensuite calculé avec la commande `shasum -a 256 86607.dat` afin d’être soumis à VirusTotal pour identification.
- L’analyse du hash SHA256 sur [VirusTotal](https://www.virustotal.com/gui/file/713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432/details) suggère que le fichier est détecté comme malveillant par plusieurs fournisseurs de sécurité.

<img src="images/6.png" alt="6" width="800"/>

<img src="images/7.png" alt="7" width="800"/>



</details>












