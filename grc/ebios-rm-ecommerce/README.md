# EBIOS RM : étude de risque d'une PME e-commerce (fictive)

**Méthode :** [EBIOS Risk Manager](https://cyber.gouv.fr/la-methode-ebios-risk-manager) (ANSSI), 5 ateliers, version courte<br>
Le scénario d'attaque s'appuie sur la chaîne Kongtuke / ClickFix que j'ai analysée ([triage statique](../../malware/2026-09-11-kongtuke-clickfix/), [analyse dynamique](../../malware/2026-09-11-kongtuke-dynamique/)).

## Contexte

PME fictive de quelques dizaines d'employés qui vend des piles en ligne. Le site et la base clients sont chez un hébergeur cloud. Le paiement passe par un prestataire : la PME ne stocke pas les numéros de carte (périmètre PCI DSS réduit).

Socle de sécurité : sauvegardes régulières du site et de la base clients, mise en place du MFA sur la console de l'hébergeur, pas de MFA sur le back-office du site.

> [!NOTE]
> Étude volontairement courte : deux sources de risque et un seul scénario lié à une attaque de type ClickFix.

## Atelier 1 : cadrage

**Valeurs métier :** la vente en ligne et la gestion des données clients. L'e-réputation est traitée comme un impact : le dommage réputationnel dégrade l'activité mais ne l'arrête pas.

**Échelle de gravité :**

| Niveau       | Définition                                                                                                                                                                    |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Critique     | L'entreprise ne s'en remet pas sans aide extérieure majeure, les salariés risquent de perdre leur emploi (ex. : vente arrêtée durablement, cessation de paiement...)          |
| Grave        | L'entreprise s'en sort avec de sérieuses difficultés et des moyens exceptionnels (ex. : activité paralysée plusieurs jours, prestataire de réponse à incident, prêt bancaire) |
| Significatif | L'entreprise absorbe l'impact avec ses moyens courants (ex. : interruption de quelques heures, impact modéré sur la trésorerie)                                               |
| Mineur       | Impact limité, sans conséquence durable                                                                                                                                       |

**Événements redoutés** (pire cas réaliste, socle compris) :

| Événement redouté | Gravité | Pourquoi |
| --- | --- | --- |
| Interruption de service | Grave | Plusieurs jours sans commande, prestataire extérieur nécessaire pour relancer le site |
| Modification des prix | Significatif | Commandes à annuler ou reprendre, sans mettre la trésorerie en péril |
| Divulgation de la base clients | Grave | Prestataire de réponse à incident, déclaration à la CNIL, perte de confiance des clients |
| Perte ou modification de données | Grave | Restauration depuis les sauvegardes avec un prestataire, commandes récentes perdues |

## Atelier 2 : sources de risque

- Cybercriminel motivé par l'argent (retenu pour le scénario)
- Menace interne : salarié ou prestataire ayant un accès légitime (retenue, non développée)

## Atelier 3 : scénario stratégique

**Écosystème :** clients, fournisseurs connectés, hébergeur cloud, prestataire de paiement, agence web, éditeur de la plateforme e-commerce.

**Scénario :** un cybercriminel cherche à obtenir une rançon. Un poste de salarié est infecté par ClickFix et lui sert de porte d'entrée sur le réseau d'entreprise. L'attaquant obtient un accès persistant à son poste (observé dans mon analyse). Il peut ensuite voler des identifiants, accéder au back-office du site ou au panneau d'administration de l'hébergeur pour y déployer un rançongiciel. L'attaquant peut mettre en place une double extorsion (exfiltration des données clients et chiffrement de l'infrastructure de l'entreprise). Ce scénario atteint trois événements redoutés : l'interruption de service, la divulgation des données clients et la perte de données de l'entreprise.

## Atelier 4 : scénario opérationnel

| Phase | Actions | Vraisemblance |
| --- | --- | --- |
| Connaître | Trouver des sites vulnérables et y injecter le script (attaque opportuniste) | - |
| Rentrer (observé) | Fausse vérification, commande collée dans Win+R, installation de deux branches, contact avec le C2, persistance par la clé Run | V3 |
| Trouver (supposé) | Vol des identifiants du poste, mouvement latéral, identifiants d'un administrateur du back-office | V3 |
| Exploiter (supposé) | Export de la base clients par le back-office sans MFA | V3 |
| Exploiter (suite) | Chiffrement du site, qui demande de passer le MFA de la console | V2 |

Le scénario est aussi vraisemblable que sa phase la plus difficile. Il a donc deux branches : **fuite de données en V3**, **chiffrement en V2**.

## Atelier 5 : traitement du risque

| Phase | Mesure |
| --- | --- |
| Rentrer | Sensibilisation au ClickFix, blocage de Win+R par stratégie de groupe |
| Trouver | Segmentation du réseau, poste dédié à l'administration du back-office |
| Exploiter | MFA par clé physique FIDO2 sur le back-office, sessions courtes |

Mesure prioritaire si une seule est finançable : le MFA sur le back-office, parce qu'il ferme la porte qui rend la fuite de données V3. Limite : un cookie de session volé contourne tout MFA, d'où les sessions courtes.

**Risque résiduel :**

| Branche | Avant | Après |
| --- | --- | --- |
| Fuite de données | Grave / V3 | Grave / V2 |
| Chiffrement | Grave / V2 | Grave / V1 |

Les mesures baissent la vraisemblance, pas la gravité : si l'attaque réussit malgré tout, l'impact reste le même. Le risque restant est accepté par la direction.

## Ce que j'ai appris

La mise en place d'un MFA physique (FIDO2) protège contre le phishing, mais pas contre la réutilisation de cookies volés. En effet, l'attaquant peut contourner le MFA en se connectant directement à la session ciblée avec les cookies de la victime. Ainsi plus la durée de vie du cookie volé est longue, plus le risque est élevé et plus le MFA est fragilisé.
