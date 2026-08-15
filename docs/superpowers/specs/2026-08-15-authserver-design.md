# authserver Design — Serveur de test pour attaque par dictionnaire

Date: 2026-08-15

## Objectif

Construire un serveur de connexion TCP **volontairement fragile** (sans
limitation de tentatives, sans chiffrement) pour tester une attaque par
dictionnaire sur ses propres identifiants, en local, à des fins éducatives
uniquement. Le serveur est écrit en Python (standard library only).

> Éducatif : on n'attaque que des identifiants qu'on possède, sur 127.0.0.1,
> avec l'autorisation explicite du propriétaire.

## Deliverables

- `authserver/server.py` — serveur de connexion TCP (socket), protocole
  USER/PASS, vérification SHA-256 avec sel.
- `authserver/gen_hash.py` — outil qui génère sel + hash pour la config.
- `authserver/users.conf` — config, une ligne par utilisateur
  (`username:salt:hash`, commentaires avec `#`), avec un compte de test
  documenté.
- `authserver/tests/test_server.py` — tests pytest.
- `authserver/README.md` — explication d'utilisation.

## Comportement du serveur

- Écoute sur `127.0.0.1` par défaut ; port par défaut `9999`, modifiable via
  `--port` en ligne de commande.
- Accepte plusieurs connexions en parallèle (un thread par connexion).
- Protocole texte (lignes terminées par `\n`) :
  - `USER <name>` -> `USER OK` ou `USER NOT FOUND`
  - `PASS <password>` -> `PASS OK` ou `PASS FAILED`
  - Commande inconnue -> `ERROR`
- Vérification : `sha256(salt + mot_de_passe)` comparé au hash de la config.
  Aucun mot de passe en clair stocké ou vérifié en clair.
- Aucune limitation de tentatives : faille voulue pour l'exercice.
- Journalisation console : heure, IP, utilisateur, mot de passe tenté, résultat.
- Gestion d'erreurs socket par connexion : une connexion qui se ferme
  brutalement ne fait pas planter le serveur.

## Génération des identifiants

- `python gen_hash.py <mot_de_passe>` affiche `salt=<sel> hash=<hash>` à coller
  dans `users.conf`.
- Le sel est généré aléatoirement (module `secrets`).

## Protocole et interfaces

- Format config : `username:salt:hash`, un utilisateur par ligne, `#` pour les
  commentaires, lignes vides ignorées.
- `gen_hash.py` et `server.py` n'utilisent que la stdlib.

## Tests (pytest)

Démarre le serveur dans un thread sur un port libre, se connecte en socket et
vérifie :

- `USER` d'un utilisateur existant -> `USER OK`
- `USER` d'un utilisateur inconnu -> `USER NOT FOUND`
- `PASS` correct -> `PASS OK`
- `PASS` incorrect -> `PASS FAILED`
- Commande inconnue -> `ERROR`
- Plusieurs connexions simultanées fonctionnent.

## Non-goals

- Pas de chiffrement (pas de TLS).
- Pas de client d'attaque par dictionnaire (phase suivante).
- Pas de base de données ; config en fichier texte uniquement.
- Pas d'anti-déni-de-service (c'est le but : être vulnérable).
