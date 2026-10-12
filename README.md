# Cyberportofolio

Portfolio de Thomas Floret, analyste SOC junior : analyses d'incidents, playbooks et travaux GRC.

Les analyses portent sur des environnements d'exercice publics. Les indicateurs de compromission sont neutralisés (`hxxp`, `[.]`).

## Analyses d'incidents

| Date | Analyse | Outils | Thèmes |
| --- | --- | --- | --- |
| 2026-08 | [FormBook / XLoader : identification d'un poste infecté à partir d'alertes IDS](incidents/2026-08-09-formbook-xloader/) | Wireshark, CyberChef | pcap, Active Directory, C2 HTTP, domaines leurres |

## Triage de malware

| Date | Analyse | Outils | Thèmes |
| --- | --- | --- | --- |
| 2026-09 | [Kongtuke / ClickFix : triage d'un poste infecté](malware/2026-09-11-kongtuke-clickfix/) | terminal Linux, VirusTotal | ClickFix, persistance registre, DLL side-loading |

## Méthode

Chaque analyse répond aux questions de l'exercice au format Question / Capture / Réponse, puis résume les IOC, les techniques MITRE ATT&CK et les recommandations. Un [modèle de rapport](templates/rapport-incident.md) plus complet sert de base.
