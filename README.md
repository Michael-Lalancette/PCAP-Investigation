# 🖥️ PCAP-Investigation
Ce dépôt contient mes analyses personnelles de fichiers PCAP provenant du site [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/).    

Chaque cas inclut des notes détaillées, des indicateurs de compromission (IOCs) et la méthodologie utilisée pour investiguer le trafic réseau.

---

### 🌐 Source des PCAPs
- Tous les fichiers PCAP utilisés dans ce projet proviennent de [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/).

> ⚠️ Certains liens du site mènent vers des exercices disponibles sur le *Learning Hub* de [Palo Alto Networks - Unit 42](https://unit42.paloaltonetworks.com/category/learning-hub/).

---

### 🧰 Outils utilisés
- **VMware Workstation Pro** - Environnement isolé
- **Kali Linux** - Distribution Linux spécialisée pour l'analyse forensique
- **Wireshark** – Inspection détaillée des PCAPs
- **VirusTotal** – Vérification de réputation de fichiers/URLs
- **Python / Bash / PowerShell** – Automatisation et scripts d’investigation  

---

### 📂 Index des cas étudiés
1. [MTA Quiz – Janvier 2023](MTA/MTA-quiz-jan2023/notes.md) – Analyse d’un trafic réseau infecté par le malware *OriginLogger (Agent Tesla)*


*(La liste sera mise à jour au fur et à mesure que je progresse à travers les exercices)*

---

### 📌 Parcourir ce dépôt
- Chaque dossier de cas contient `notes.md` avec méthodologie et résultats détaillés.  
- Les scripts utilisés pour automatiser l’analyse ou enrichir les données se trouvent dans le sous-dossier `scripts/` lorsque nécessaire.  
