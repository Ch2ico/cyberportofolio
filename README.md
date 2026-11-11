# Cyberportofolio

Je m'appelle Thomas Floret et je cherche un premier poste d'analyste SOC à Lyon, après une reconversion. Ce dépôt réunit mes travaux pratiques : analyses de captures réseau et de malware, un playbook de réponse à incident et une étude de risque EBIOS RM.

À lire en premier : [l'analyse dynamique de Kongtuke / ClickFix](malware/2026-09-11-kongtuke-dynamique/).

## Analyses d'incidents

| Date | Analyse | Outils | Thèmes |
| --- | --- | --- | --- |
| 2026-10-11 | [FormBook / Xloader : identification d'un poste infecté](incidents/2026-08-09-formbook-xloader/) | Wireshark, CyberChef | pcap, Active Directory, C2 HTTP, domaines leurres |

## Triage de malware

| Date | Analyse | Outils | Thèmes |
| --- | --- | --- | --- |
| 2026-10-12 | [Kongtuke / ClickFix : analyse d'un poste infecté](malware/2026-09-11-kongtuke-clickfix/) | Terminal Linux, VirusTotal | ClickFix, persistance registre, DLL malveillante |
| 2026-11-03 | [Kongtuke / ClickFix : analyse dynamique en lab isolé](malware/2026-09-11-kongtuke-dynamique/) | FLARE-VM, REMnux, INetSim, Process Monitor | détonation, C2, proxy, Defender |

## Playbooks

| Date | Playbook | Modèle | Lien |
| --- | --- | --- | ---|
| 2026-10-13 | [Kongtuke / ClickFix : réponse à une infection (Playbook)](playbooks/clickfix/) | Fiches IRM | s'appuie sur l'analyse de Kongtuke |

## GRC

| Date | Pièce | Méthode | Thèmes |
| --- | --- | --- | --- |
| 2026-11-06 | [EBIOS RM : étude de risque d'une PME e-commerce (fictive)](grc/ebios-rm-ecommerce/) | EBIOS Risk Manager (ANSSI) | gravité, scénario ClickFix, MFA, risque résiduel |

## Homelab

| Date | Pièce | Outils | Thèmes |
| --- | --- | --- | --- |
| 2026-10-23 | [Homelab SOC : segmentation, détection et durcissement Samba](homelab/) | OPNsense, Suricata, Zeek, Proxmox, Kali, Metasploit | VLAN, IDS, CVE-2007-2447, moindre privilège |

