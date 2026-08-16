# dictattack Design — Attaque par dictionnaire dans tinyscanner

Date: 2026-08-16

## Objectif

Étendre `tinyscanner` avec une attaque par dictionnaire sur le service
`authserver` du projet (protocole USER/PASS en TCP, `sha256(salt + mot de
passe)`), à des fins éducatives uniquement, en local.

> Éducatif : on n'attaque que des identifiants qu'on possède, sur 127.0.0.1,
> avec l'autorisation explicite du propriétaire. Le authserver est volontairement
> vulnérable (aucune limitation de tentatives).

## Deliverables

- `dictattack.py` — nouveau module de logique d'attaque (au même niveau que
  `scanner.py`).
- `tinyscanner.py` — ajout des options CLI `--dict-auth`, `--user`, `--dict`.
- `tests/test_dictattack.py` — tests pytest.
- `docs/superpowers/specs/2026-08-16-dictattack-design.md` — ce document.

## Architecture

```
tinyscanner.py (CLI, existant)
   ├── scanner.py        (logique de scan, existant, inchangé)
   └── dictattack.py     (NOUVEAU : logique d'attaque)
```

- `dictattack.py` suit le pattern de `scanner.py` : logique réutilisable,
  importée par la CLI.
- `scanner.py` n'est pas modifié.

## Fonctions de `dictattack.py`

- `probe_service(host, port, timeout)` -> `bool`
  Connecte en TCP, lit la première ligne (banner). Retourne `True` si le
  service répond au protocole USER/PASS (le banner du authserver), `False`
  sinon (port fermé, refus, time out, ou banner inattendu).
- `dict_attack(host, port, user, words, timeout)` -> `str | None`
  Pour chaque mot de passe de `words`, envoie `USER <name>` puis `PASS <mot>`
  (une seule connexion par port). Retourne le premier mot accepté (`PASS OK`)
  ou `None` si aucun ne marche. Arrêt au 1er succès.

## Interface CLI (`tinyscanner.py`)

```
tinyscanner -p 9999 --dict-auth --user francis 127.0.0.1
tinyscanner --dict-auth --dict mon_mots.txt --user alice 127.0.0.1 9999
```

- `--dict-auth` — active l'attaque par dictionnaire après le scan. Le scan
  (host, port, `-p`, `-t`/`-u`) reste requis comme aujourd'hui.
- `--user <name>` — compte à attaquer, obligatoire avec `--dict-auth`.
- `--dict <file>` — fichier de dictionnaire, défaut `words.txt` (dans le
  répertoire de travail).

Déroulement après le scan :

1. Le scan s'exécute normalement.
2. Pour chaque port ouvert : `probe_service` ; si USER/PASS détecté, lance
   `dict_attack`.
3. Affichage sobre, résultat uniquement :
   - succès : `Port <port>: password for <user> is '<mot>' (attempt <n>)`
   - échec : `Port <port>: no password found for <user> (<n> attempts)`

## Gestion d'erreurs et cas limites

- Fichier `--dict` introuvable ou illisible → erreur avant tout scan, code 1.
- Dictionnaire vide → message `dictionary is empty`, arrêt, code 1.
- Connexion qui échoue en cours d'attaque (service fermé) → arrêt sur ce port,
  message sobre, on passe au port suivant.
- Aucun port ouvert → rien à attaquer, code 0.
- `--dict-auth` sans `--user` → erreur d'usage, code 1.
- Réponse serveur inattendue (ni `PASS OK` ni `PASS FAILED`) → comptée comme
  échec, on continue (robuste face à une connexion qui se ferme).
- Sortie : 0 si mot trouvé, 0 si rien trouvé, 1 si erreur d'utilisation ou de
  fichier.

## Tests (pytest)

`tests/test_dictattack.py`, cible = serveur `authserver` existant démarré en
thread sur un port libre (`authserver.server.load_users` + `LoginServer`) :

- `probe_service` : port avec banner USER/PASS → `True` ; port fermé → `False`.
- `dict_attack` : petit dictionnaire contenant le bon mot → mot retourné ;
  dictionnaire sans le bon mot → `None` ; arrêt au 1er succès.
- CLI tinyscanner : `--dict-auth` sans `--user` → erreur ; `--dict` inexistant →
  erreur avant scan.

## Non-goals

- Pas de multi-utilisateurs (un seul `--user`).
- Pas de délai entre tentatives (vitesse maximale, c'est le but pédagogique).
- Pas d'attaque d'autres services (ftp, ssh...).
- Pas de modification de `scanner.py`.
