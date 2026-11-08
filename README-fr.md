# RAMP

*[English](README.md) · Français*

Panneau de contrôle portable pour un serveur web local sous Windows : **Apache, MariaDB, PHP et phpMyAdmin**, écrit en Rust avec [Slint](https://slint.dev).

Un seul `ramp.exe` à poser dans un dossier vide. Au premier lancement, il télécharge les versions que vous choisissez, les vérifie et les installe à côté de lui. Ensuite, il démarre et arrête les serveurs, ouvre leurs fichiers de configuration et de logs, et les met à jour.

## Points forts

- **Portable** : tout s'installe dans le dossier de `ramp.exe`. Le dossier peut être déplacé ou renommé : les chemins sont recalés au lancement suivant.
- **Aucun service Windows** : les serveurs sont de simples processus lancés et arrêtés par le panneau. Les droits administrateur ne sont pas nécessaires.
- **Versions au choix à l'installation** : branches LTS de MariaDB (sans celles en fin de vie), branches de PHP encore maintenues par php.net (support actif ou correctifs de sécurité seulement), builds Apache 2.4 d'Apache Lounge, dernier phpMyAdmin.
- **PHP complet d'emblée** : chaque extension livrée avec PHP est testée à l'installation, et toutes celles qui se chargent seules sont activées (OPcache compris).
- **Mises à jour sûres** : uniquement des archives, jamais d'installateurs. Le SHA256 est vérifié systématiquement, l'ancienne version est sauvegardée, la nouvelle doit démarrer, et sinon tout est remis en place. Un bouton *Restore* revient à la version précédente.
- **Prudent par défaut** : MariaDB n'écoute que sur `127.0.0.1` et phpMyAdmin n'est accessible que depuis la machine. Les listes de versions et les sommes de contrôle ne transitent qu'en HTTPS, donc une archive servie par un miroir n'est acceptée que si son SHA256 correspond. L'alias `php-cgi` est retiré (CVE-2024-4577).
- **Léger** : rendu logiciel, sans OpenGL, donc utilisable en machine virtuelle ou en bureau à distance.

## Installation

### Prérequis

- Windows 10 ou 11, 64 bits.
- Le runtime **Microsoft Visual C++ 2015-2022 (x64)**, nécessaire aux builds Windows d'Apache et de PHP. S'il manque, RAMP le détecte et propose le lien de téléchargement de Microsoft.
- Un accès Internet au premier lancement et pour les mises à jour, vers `www.apachelounge.com`, `downloads.mariadb.org`, `windows.php.net`, `www.php.net`, `files.phpmyadmin.net` et `api.github.com`. Si un pare-feu les bloque, la fenêtre d'installation affiche *Retry*.

### Premier lancement

1. Téléchargez `RAMP-<version>-win64.zip` depuis la page [Releases](https://github.com/loonaire/RAMP/releases). Vous pouvez comparer son empreinte avec le fichier `.sha256` publié à côté :
   ```powershell
   Get-FileHash .\RAMP-0.5.0-win64.zip -Algorithm SHA256
   ```
2. Extrayez `ramp.exe` dans un dossier dédié et accessible en écriture, par exemple `C:\RAMP`. Évitez `Program Files`, où l'écriture demande les droits administrateur.
3. Lancez `ramp.exe`. La fenêtre *Install RAMP* propose les versions disponibles, les plus récentes présélectionnées. Cliquez sur *Install* : environ 150 Mo sont téléchargés, ce qui prend d'une minute à quelques minutes selon la connexion. *Later* reporte l'installation au lancement suivant.

## Utilisation

La fenêtre principale affiche une ligne par serveur (Apache, MySQL/MariaDB) avec ses PID, ses ports et son état :

| Bouton | Action |
|---|---|
| **Start / Stop** | Démarre ou arrête le serveur. |
| **Admin** | Ouvre `http://localhost/` (Apache) ou phpMyAdmin (MariaDB) dans le navigateur. |
| **Config** | Liste les fichiers de configuration (`httpd.conf`, `php.ini`, `my.ini`, `config.inc.php`…) et les ouvre dans l'éditeur. |
| **Logs** | Liste les fichiers de logs et les ouvre dans l'éditeur. |

Les menus donnent accès à l'explorateur sur le dossier d'installation, aux réglages (ports, éditeur, navigateur), à la fenêtre des mises à jour et à la fenêtre *About*, qui indique la version et le type de build. Quitter le panneau arrête les serveurs qu'il a démarrés.

### Adresses par défaut

| Service | Adresse |
|---|---|
| Site web (`htdocs\`) | http://localhost/ et https://localhost/ (certificat auto-signé) |
| phpMyAdmin | http://localhost/phpmyadmin |
| MariaDB | `127.0.0.1:3306`, utilisateur `root` **sans mot de passe** |

> **Sécurité.** RAMP est fait pour le développement local. Donnez un mot de passe à `root` dès l'installation. Apache écoute sur toutes les interfaces réseau : c'est le pare-feu Windows qui décide si le site est joignable depuis le réseau local.

Les ports se changent dans *File > Settings*. RAMP les écrit directement dans les fichiers de configuration des serveurs ; redémarrez un serveur en marche pour les appliquer.

### Contenu du dossier d'installation

```
C:\RAMP\
├── ramp.exe
├── ramp.ini        réglages du panneau
├── ramp.log        journal (complété à chaque fermeture)
├── apache\         Apache httpd (Apache Lounge)
├── mysql\          MariaDB, données dans mysql\data\
├── php\            PHP, php.ini
├── phpMyAdmin\
├── htdocs\         racine du site
├── cgi-bin\
├── tmp\            fichiers temporaires, recréé au démarrage des serveurs
└── .backup\        versions remplacées par les mises à jour
```

## Mises à jour

Le menu *Updates* indique s'il y a des mises à jour en attente et ouvre la fenêtre *Component Updates*. Pour chaque composant, elle affiche la version installée, la version cible, la taille de l'archive et l'état de support de la branche.

Une mise à jour suit toujours les mêmes étapes :
1. téléchargement de l'archive officielle et vérification de son SHA256 ;
2. extraction, et contrôle que l'archive contient bien la version annoncée ;
3. sauvegarde de l'ancienne version dans `.backup\`, avec ses fichiers de configuration. Pour MariaDB, le dossier de données est copié aussi, jusqu'à `DataBackupLimitMB` ;
4. remplacement, puis démarrage du nouveau serveur ;
5. retour automatique à l'ancienne version si une étape échoue.

La case *Offer other release lines* propose aussi les branches supérieures (PHP 8.4 vers 8.5, MariaDB 11.8 vers 12.3…), en plus des correctifs de la branche installée.

## Réglages (`ramp.ini`)

Le fichier est créé à côté de `ramp.exe` ; la plupart des clés se modifient depuis *File > Settings*.

| Section | Clé | Défaut | Rôle |
|---|---|---|---|
| `ServicePorts` | `Apache`, `ApacheSSL`, `MySQL` | `80`, `443`, `3306` | Ports des serveurs. Ceux réellement configurés dans `httpd.conf` et `my.ini` sont prioritaires. |
| `Checks` | `CheckDefaultPorts` | `1` | Avant de démarrer un serveur, vérifie que ses ports sont libres. |
| `Common` | `Editor` | `notepad.exe` | Éditeur des fichiers de configuration et de logs. |
| `Common` | `Browser` | *(vide)* | Navigateur ; vide = navigateur par défaut. |
| `Common` | `Debug` | `0` | Messages de débogage dans le journal. |
| `Updates` | `AllowMajor` | `1` | Propose les branches supérieures. |
| `Updates` | `TargetLine` | *(vide)* | Fige MariaDB sur une branche (`11.8`, par exemple). |
| `Updates` | `KeepBackups` | `2` | Nombre de sauvegardes conservées dans `.backup\` (les plus récentes, tous composants confondus). |
| `Updates` | `DataBackupLimitMB` | `2048` | Taille maximale du dossier de données MariaDB copié avant une mise à jour. |

## Ligne de commande

`ramp.exe` est une application graphique, sans console : ces commandes ouvrent le panneau, écrivent leur résultat dans le journal et dans `ramp.log`, puis le referment.

```text
ramp --first-run [--no-verify] [--apache <version>] [--mariadb <branche|version>] [--php <branche|version>]
ramp --update-check [--json]
ramp --update-apply <apache|mysql|php|pma> [branche|version]
ramp --update-restore <apache|mysql|php|pma> [dossier_de_sauvegarde]
```

Exemple : `ramp --first-run --php 8.4 --mariadb 11.8` installe sans fenêtre de choix, avec les dernières versions de ces branches.

## Compiler depuis les sources

RAMP se compile avec la chaîne GNU de [MSYS2](https://www.msys2.org), environnement **UCRT64**. `windres` sert à intégrer l'icône dans l'exécutable.

```bash
pacman -S mingw-w64-ucrt-x86_64-rust mingw-w64-ucrt-x86_64-binutils
cargo build --release
cargo test
```

Ne lancez pas l'installation depuis le dossier de build de cargo : un `cargo clean` effacerait les serveurs et les bases de données. RAMP refuse d'ailleurs d'y installer. Pour le développement, indiquez un autre dossier avec `RAMP_BASEDIR` :

```powershell
$env:RAMP_BASEDIR = "C:\ramp-dev"; cargo run
```

`release.ps1` compile et produit le paquet `dist\RAMP-<version>-win64.zip` et son `.sha256`. Avec `-InstallDir`, il copie aussi `ramp.exe` dans un dossier d'installation, sans toucher à l'installation existante :

```powershell
.\release.ps1                      # paquet seul
.\release.ps1 -InstallDir C:\RAMP  # paquet + installation ou mise à jour de ramp.exe
```

## Publier une version

Chaque tag `v*` poussé sur GitHub déclenche le workflow [`release.yml`](.github/workflows/release.yml). Il compile sous Windows avec la même chaîne MSYS2 UCRT64, lance `release.ps1` et publie le zip et son SHA256 dans une release GitHub. Le message du tag annoté sert de notes de version.

1. Mettez la version à jour dans `Cargo.toml` (par exemple `0.6.0`) et commitez.
2. Créez un tag annoté qui correspond à cette version (`v0.6` ou `v0.6.0`) et poussez-le seul :
   ```bash
   git tag -a v0.6 -m "RAMP v0.6: ..."
   git push origin v0.6
   ```

Le workflow s'arrête si le tag ne correspond pas à la version de `Cargo.toml`. Un tag avec tiret (`v0.6.0-rc1`) crée une pré-version.

## Structure du code

| Fichier | Rôle |
|---|---|
| `src/main.rs` | Interface, gestion des serveurs, fenêtres, ligne de commande |
| `src/install.rs` | Installation au premier lancement, génération des configurations |
| `src/update.rs` | Sources de versions (Apache Lounge, MariaDB, php.net, phpMyAdmin), vérification et application des mises à jour |
| `src/http.rs` | Client HTTPS minimal sur WinHTTP (TLS du système, proxy système) |
| `src/ports.rs`, `src/netstat.rs` | Ports configurés et processus qui les occupent |
| `src/procs.rs`, `src/pe.rs` | Processus des serveurs, détection des DLL manquantes |
| `src/config.rs` | Lecture et écriture de `ramp.ini` |
| `ui/main.slint` | Toutes les fenêtres |
| `templates/` | Modèles de configuration (`httpd.conf`, `php.ini`, `my.ini`, `config.inc.php`, page d'accueil) |
| `build.rs` | Compilation de l'interface Slint et intégration de l'icône |

## Licence

RAMP est distribué sous licence [GPL-3.0](LICENSE). Slint y est utilisé sous sa licence GPLv3. Apache, MariaDB, PHP et phpMyAdmin sont téléchargés depuis leurs sources officielles et restent soumis à leurs propres licences.
