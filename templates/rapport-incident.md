# [Titre court de l'incident] - Analyse de trafic réseau

| | |
| --- | --- |
| **Date de l'analyse** | AAAA-MM-JJ |
| **Source** | [nom de l'exercice ou du lab](lien) |
| **Outils** | Wireshark, ... |
| **Verdict** | Vrai positif / Faux positif - [famille de malware] |
| **Sévérité** | Faible / Moyenne / Élevée / Critique |

> Environnement d'exercice public. Les indicateurs (IP, domaines, URL) sont neutralisés (`hxxp`, `[.]`) pour éviter tout clic accidentel.

## 1. Résumé

Trois à cinq phrases pour un responsable non technique : ce qui s'est passé, quel poste et quel utilisateur, le niveau de risque, ce qu'il faut faire maintenant.

## 2. Contexte et alerte de départ

- Alerte(s) reçue(s) : signature, heure (UTC), IP de destination
- Périmètre : plage réseau, domaine AD, contrôleur de domaine, passerelle
- Question posée : quel poste est infecté, par quoi, depuis quand

## 3. Identification du poste compromis

| Élément | Valeur | Comment je l'ai trouvé |
| --- | --- | --- |
| Adresse IP | | filtre Wireshark |
| Adresse MAC | | |
| Nom d'hôte | | |
| Compte utilisateur | | |
| Nom complet | | |

## 4. Investigation

Une sous-partie par étape, dans l'ordre où je les ai menées. Pour chacune : le filtre ou la requête utilisé, ce que je vois (capture d'écran), ce que j'en conclus.

### 4.1 Point de départ : l'alerte
### 4.2 Vecteur d'infection initial
### 4.3 Communication avec le C2

## 5. Chronologie (UTC)

| Heure | Événement | Source |
| --- | --- | --- |
| | | |

## 6. Indicateurs de compromission (IOC)

| Type | Valeur | Contexte |
| --- | --- | --- |
| Domaine | | |
| IP | | |
| URL | | |
| Hash SHA256 | | |

## 7. Correspondance MITRE ATT&CK

| Tactique | Technique | ID | Observation |
| --- | --- | --- | --- |
| | | | |

## 8. Recommandations

**Immédiat (confinement)** : isoler le poste, ...
**Court terme (éradication, remédiation)** : réinitialiser les identifiants du compte, ...
**Prévention** : règles de détection, blocage des IOC, sensibilisation, ...

## 9. Ce que j'ai appris

Deux ou trois points : une difficulté rencontrée, une technique nouvelle, ce que je ferais autrement.
