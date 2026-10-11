# FormBook / XLoader : identifier un poste infecté à partir d'alertes IDS

**Exercice :** [Malware-Traffic-Analysis.net, 2026-08-09 « First to Last »](https://www.malware-traffic-analysis.net/2026/08/09/index.html)

**Outils :** Wireshark, CyberChef, VirusTotal

## Contexte

L'IDS remonte des alertes `ET MALWARE FormBook CnC Checkin (GET)` vers plusieurs IP externes, à partir de 02:13 UTC (Attention: Mes captures Wireshark affichent l'heure locale (UTC+2)).

ATTENTION: L'énoncé indique que le contrôleur de domaine est 172.16.8[.]2, mais dans la capture de trafic, c'est 172.16.8[.]8 qui répond aux requêtes SMB,DNS... 

![Énoncé de l'exercice](img/01-enonce.png)

## Poste infecté

### Quelle est l'adresse IP du poste infecté ?

![Trafic vers une IP de l'alerte](img/02-trafic-c2.png)
**Réponse :** 172.16.8[.]49. Partir de l'IP issus de l'alerte pour identifier l'adresse IP du poste infecté.<br>

Filtre : `ip.addr == 146.59.71.167 && http.request`



### Quelle est son adresse MAC ?

![Adresse MAC](img/03-mac.png)


**Réponse :** 00:12:f0:28:d4:34, il suffit de regarder la couche Ethernet d'un paquet émis par le poste.<br>

Filtre : `ip.src == 172.16.8.49`



### Quel est son nom d'hôte ?

![Nom d'hôte](img/04-hostname-nbns.png)


**Réponse :** DESKTOP-5NLV63K, Le nom du poste peut se trouver dans l'enregistrement NetBIOS du poste ou une requête DHCP.<br>

Filtre : `ip.addr == 172.16.8.49 && nbns`



### Quel est le compte utilisateur ?

![Compte utilisateur](img/05-compte-kerberos.png)


**Réponse :** rvance, le nom du compte peut être trouver dans les échanges Kerberos avec le contrôleur de domaine.<br>

Filtre : `ip.addr == 172.16.8.49 && kerberos.CNameString`



### Quel est le nom complet de l'utilisateur ?

![Nom complet](img/06-nom-complet-samr.png)


**Réponse :** Raymond Vance, dans la réponse SAMR `QueryUserInfo` du contrôleur de domaine.<br>

Filtre : `ip.addr == 172.16.8.49 && samr`



## Comportement du malware

- **Vecteur d'infection non visible** : la capture commence à 02:07. Jusqu'à 02:13, on ne voit que du trafic légitime. La capture ne montre uniquement la phase Commande and Control de l'attaque.
- **Rotation de domaines** : à partir de 02:13, le poste contacte 16 domaines l'un après l'autre. 14 d'entre eux reçoivent 7 requêtes POST puis 1 GET (`/xxxx/?2kn1=...`)
- **Domaines leurres** : la liste commence avec un vrai site (www.independent[.]ie, un journal irlandais légitime). Le C2 fait tourner des URL leurres qui se resolve en erreurs (501,404,500..). Seule l'URL www.taibeinan[.]cc, se traduit par un « 200 OK » mais la page renvoyé est un 404. Au final, le vrai C2 n'est pas identifiable sur la capture.
- **Données chiffrées** : les données sont en Base64. Une fois décodées, leur entropie est de 7,93 bits/octet (le maximum est 8) : elles sont chiffrées et illisibles.

![Requête POST vers un domaine de la rotation](img/07-c2-post.png)

Domaines contactés (hors leurre) : grinswakebthu[.]info, taibeinan[.]cc, legenda-sochi[.]com, titanium303[.]com, 21207628[.]shop, vjscloudjsns[.]beer, kentmediallc[.]com, earthframe[.]site, p3x63q[.]garden, z61gqw[.]beer, www-bet456[.]co, moxom[.]online, thvwzs[.]com, devinnovationhab[.]team, amlgames[.]site

## Recommandations

- Informer l'utilisateur Raymond Vance que son poste a été infecté.
- Isoler DESKTOP-5NLV63K et le réinstaller.
- Réinitialiser les mots de passe du compte rvance.
- Black-lister les domaines ci-dessus.

## Ce que j'ai appris

- Il est important de partir de l'IP de l'alerte pour canaliser ses recherches.
- Un code « 200 OK » ne suffit pas : il faut lire le contenu de la réponse.
