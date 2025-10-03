# 🖥️ Analyse de PCAPs avec Wireshark
Ce dépôt contient mes analyses personnelles de fichiers PCAP provenant du site [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/).    

Chaque cas inclut des notes détaillées, des indicateurs de compromission (IOCs) et la méthodologie utilisée pour investiguer le trafic réseau.

---

### 🌐 Source des PCAPs
- Tous les fichiers PCAP analysés dans ce dépôt proviennent de [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/).

> ⚠️ Certains liens du site mènent vers des exercices disponibles sur le *Learning Hub* de [Palo Alto Networks - Unit 42](https://unit42.paloaltonetworks.com/category/learning-hub/).

---

### 🧰 Outils utilisés
- **[VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)** - Hyperviseur
- **[Kali Linux](https://www.kali.org/)** - Distribution Linux orientée forensic/pentest
- **[Wireshark](https://www.wireshark.org/download.html)** – Analyse des paquets réseau
- **[VirusTotal](https://www.virustotal.com/gui/home/url)** – Vérification de réputation de fichiers/URLs
- **[MITRE ATT&CK Framework](https://attack.mitre.org/)** - Référentiel des tactiques, techniquers et procédures (TTPs)
- **[Cyberchef](https://cyberchef.io/)** - Outil de décodage, déchiffrement et transformation de données


---

### 📂 Index des cas étudiés
1. [MTA Quiz – Janvier 2023](MTA/MTA-quiz-jan2023/notes.md) – Analyse du trafic réseau infecté par le malware OriginLogger (Agent Tesla)
2. [MTA - Download from fake software site](MTA/MTA-2025-01-22/notes.md) - Analyse du trafic réseau lié au téléchargement d’un exécutable malveillant depuis un site frauduleux usurpant l’identité de Google Authenticator.
3. [MTA Quiz - Février 2023](MTA/MTA-quiz-feb23/notes.md) - Analyse du trafic réseau infecté par le malware Qakbot dans un environnement Active Directory (AD)


*(La liste sera mise à jour au fur et à mesure que je progresse à travers les exercices)*

---

### 📌 Parcourir ce dépôt
- Chaque dossier de cas contient `notes.md` avec méthodologie et résultats détaillés.  
