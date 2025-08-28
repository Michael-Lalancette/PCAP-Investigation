## 🕵️‍♂️ MTA-2025-01-22

🔍[Source](https://www.malware-traffic-analysis.net/2025/01/22/index.html) 


---

### 📌 Contexte

- Un utilisateur télécharge un faux logiciel (Google Authenticator) depuis un site frauduleux, entraînant l’infection de son poste Windows et la communication avec plusieurs serveurs C2. 
- Ce document contient une **analyse pas-à-pas avec captures d’écran** pour chaque question.  

---

### 🧰 Outils utilisés

- Wireshark
- Kali Linux
- VMware

---

### 📝 Questions & Analyse

#### Q1. What is the IP address of the infected Windows client?
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : Ouvrir le PCAP (via terminal ou fichier directement)

  - Étape 2 : Filtrer le fichier avec le Basic filter pour trouver la première requête HTTP suspecte
      - Basic filter = `(http.request or tls.handshake == 1) and !(ssdp)`
</details>


<details>
  <summary>✅ Réponse</summary>
  
`10.1.17.215`
</details>

<details>
  <summary>📷 Captures</summary>
<img src="images/q1.png" alt="q1" width="800"/>
</details>


---

#### Q2. What is the mac address of the infected Windows client?
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : Filtrer le fichier avec le Basic filter pour trouver la première requête HTTP suspecte
      - Basic filter = `(http.request or tls.handshake == 1) and !(ssdp)`
</details>


<details>
  <summary>✅ Réponse</summary>
  
`00:d0:b7:26:4a:74`
</details>

<details>
  <summary>📷 Captures</summary>
<img src="images/q2.png" alt="q2" width="800"/>
</details>


---

#### Q3. What is the host name of the infected Windows client?
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : Dans certains PCAPs, tu peux retrouver le nom d’hôte Windows de la victime grâce au trafic **NBNS ou SMB/SMB2**. Utiliser le filtre approprié.
      - Filtre = `nbns or smb or smb2`
</details>


<details>
  <summary>✅ Réponse</summary>
  
`DESKTOP-L8C5GSJ`
</details>

<details>
  <summary>📷 Captures</summary>
<img src="images/q3.png" alt="q3" width="800"/>
</details>


---

#### Q4. What is the user account name from the infected Windows client?
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : Filtrer les paquets Kerberos provenant de la machine infectée.
      - Filtre = `ip.src == 10.1.17.215 and kerberos.CNameString`
  - Étape 2 : Inspecter le champ `CNameString` dans le panneau *Packet Details* pour relever le nom d’utilisateur.
</details>


<details>
  <summary>✅ Réponse</summary>
  
`shutchenson`
</details>

<details>
  <summary>📷 Captures</summary>
<img src="images/q4.png" alt="q4" width="800"/>
</details>


---

#### Q5. What is the likely domain name for the fake Google Authenticator page?
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : xxx
</details>


<details>
  <summary>✅ Réponse</summary>
  
`xxx`
</details>

<details>
  <summary>📷 Captures</summary>
<img src="images/q5.png" alt="q5" width="800"/>
</details>


---




LAN SEGMENT DETAILS FROM THE PCAP
LAN segment range:  10.1.17[.]0/24   (10.1.17[.]0 through 10.1.17[.]255)
Domain:  bluemoontuesday[.]com
Active Directory (AD) domain controller:  10.1.17[.]2 - WIN-GSH54QLW48D
AD environment name:  BLUEMOONTUESDAY
LAN segment gateway:  10.1.17[.]1
LAN segment broadcast address:  10.1.17[.]255


What are the IP addresses used for C2 servers for this infection?
