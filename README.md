# Cyberportofolio

Portfolio de Thomas Floret, analyste SOC junior : analyses d'incidents, playbooks et travaux GRC.

Les analyses portent sur des environnements d'exercice publics. Les indicateurs de compromission sont neutralisés (`hxxp`, `[.]`).

## Analyses d'incidents

| Date | Analyse | Outils | Thèmes |
| --- | --- | --- | --- |
| 2026-08 | [FormBook / XLoader : identification d'un poste infecté à partir d'alertes IDS](incidents/2026-08-09-formbook-xloader/) | Wireshark, CyberChef | pcap, Active Directory, C2 HTTP, domaines leurres |

## Méthode

Chaque analyse suit le même [modèle de rapport](templates/rapport-incident.md) : contexte, identification du poste, investigation, chronologie, IOC, MITRE ATT&CK, recommandations.
