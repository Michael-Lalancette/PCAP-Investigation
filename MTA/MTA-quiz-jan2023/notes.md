## 🕵️‍♂️ MTA-quiz-jan2023 

🔍[Source](https://unit42.paloaltonetworks.com/january-wireshark-quiz/) 

✅[Réponses officielles](https://unit42.paloaltonetworks.com/january-wireshark-quiz-answers/)

---

### 📌 Contexte

- Capture réseau simulant une infection par un malware.  
- Objectif : Extraire les informations système et réseau depuis le pcap à l’aide de Wireshark.  
- Ce document contient une **analyse pas-à-pas avec captures d’écran** pour chaque question.  

---

### 🧰 Outils utilisés

- Wireshark
- Kali Linux
- VMware

---

### 📝 Questions & Analyse

#### Q1. When did the malicious traffic start in UTC?
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : Ouvrir le PCAP dans Wireshark

  - Étape 2 : Filtrer le fichier pour trouver la première requête HTTP suspecte
</details>


<details>
  <summary>✅ Réponse</summary>
  
`2023-01-05 22:51 UTC`
</details>

<details>
  <summary>📷 Captures</summary>
<img src="images/q1a.png" alt="q1a" width="800"/>
<img src="images/q1b.png" alt="q1b" width="800"/>
</details>


---


#### Q2. What is the victim’s IP address?
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : Regarder dans le panneau *Frame Details* pour trouver l'adresse IP src
</details>

<details>
  <summary>✅ Réponse</summary>
  
`192.168.1[.]27`
</details>

<details>
  <summary>📷 Captures</summary>
<img src="images/q2.png" alt="q2" width="800"/>
</details>


---


#### Q3. What is the victim’s MAC address?
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : Regarder dans le panneau *Frame Details* pour trouver l'adresse MAC src
</details>

<details>
  <summary>✅ Réponse</summary>
  
`bc:ea:fa:22:74:fb`
</details>

<details>
  <summary>📷 Captures</summary> 
<img src="images/q2.png" alt="q2" width="800"/>
</details>


---


#### Q4. What is the victim’s Windows host name?
<details>
    <summary>💡 Étapes</summary>
  
  - Étape 1 : Dans certains PCAPs, tu peux retrouver le nom d’hôte Windows de la victime grâce au trafic **NBNS ou SMB/SMB2**. Utiliser le filtre approprié.
</details>


<details>
  <summary>✅ Réponse</summary>
  
`DESKTOP-WIN11PC`
</details>

<details>
  <summary>📷 Captures</summary> 
<img src="images/q4.png" alt="q4" width="800"/>
</details>


---


#### Q5. What is the victim’s Windows user account name
<details>
    <summary>💡 Étapes</summary>

  - Étape 1 : Le protocole SMTP (port 25 par défaut) peut transmettre des emails en clair. Utiliser le filtre approprié.
  
  - Étape 2 : Inspecter le TCP Stream
    
  - Étape 3 : Relever l'information spécifique 
</details>

<details>
  <summary>✅ Réponse</summary>
  
`windows11user`
</details>

<details>
  <summary>📷 Captures</summary> 
<img src="images/q5a.png" alt="q5a" width="800"/>
<img src="images/q5b.png" alt="q5b" width="800"/>
</details>

---

#### Q6. How much RAM does the victim’s host have?
<details>
    <summary>💡 Étapes</summary>
  
  - Étape 1 : Le protocole SMTP (port 25 par défaut) peut transmettre des emails en clair. Utiliser le filtre approprié.
  
  - Étape 2 : Inspecter le TCP Stream
    
  - Étape 3 : Relever l'information spécifique 
</details>

<details>
  <summary>✅ Réponse</summary>
  
  `32GB`
</details>

<details>
  <summary>📷 Captures</summary> 
<img src="images/q6.png" alt="q6" width="800"/>
</details>


---

#### Q7. What type of CPU is used by the victim’s host?
<details>
    <summary>💡 Étapes</summary>
  
  - Étape 1 : Le protocole SMTP (port 25 par défaut) peut transmettre des emails en clair. Utiliser le filtre approprié.
  
  - Étape 2 : Inspecter le TCP Stream
    
  - Étape 3 : Relever l'information spécifique 
</details>

<details>
  <summary>✅ Réponse</summary>
  
`Intel i5-13600K`
</details>

<details>
  <summary>📷 Captures</summary> 
<img src="images/q7.png" alt="q7" width="800"/>
</details>

---


#### Q8. What is the public IP address of the victim’s host?
<details>
    <summary>💡 Étapes</summary>
  
  - Étape 1 : Le protocole SMTP (port 25 par défaut) peut transmettre des emails en clair. Utiliser le filtre approprié.
  
  - Étape 2 : Inspecter le TCP Stream
    
  - Étape 3 : Relever l'information spécifique 
</details>

<details>
  <summary>✅ Réponse</summary>
  
`173.66.44[.]112`
</details>

<details>
  <summary>📷 Captures</summary> 
<img src="images/q8.png" alt="q8" width="800"/>
</details>


---


#### Q9. What type of account login data was stolen by the malware?
<details>
    <summary>💡 Étapes</summary>
  
  - Étape 1 : Le protocole SMTP (port 25 par défaut) peut transmettre des emails en clair. Utiliser le filtre approprié.
  
  - Étape 2 : Inspecter le TCP Stream
    
  - Étape 3 : Relever l'information spécifique

  - Étape optionnelle (non présentée dans les captures) : Exporter l’email depuis le PCAP (File → Export Objects → IMF) et l’ouvrir dans un email client pour visualiser plus clairement/facilement les données.
</details>

<details>
  <summary>✅ Réponse</summary>
  
`Usernames/Passwords en clair (unencrypted) pour différents services.`
</details>


<details>
  <summary>📷 Captures</summary> 
<img src="images/q9.png" alt="q9" width="800"/>
</details>


