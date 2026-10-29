# etaHEN-Plugins-Loader-v3.03 — Etat des mises a jour firmware (4.00 -> 14.10) WIP

Ce document resume ce qui a ete mis a jour dans l'arbre `etaHEN-Plugins` pour
supporter les firmwares recents, ce qui reste non verifie, et ce qui manque
completement. A lire avant de flasher/tester sur console.

> Fw 4.xx a 7.xx voir 8.xx ici tous a etait teste sur un vrai PS5.
> Fw 8.xx et superieur rien ici n'a ete teste sur un vrai PS5. Les valeurs ajoutees viennent de
> sources publiques (portage etaHEN "unified", firmware-profiles.json,
> ps5-payload-dev / ftpsrv self-prospero.c) et d'une table KERNEL_ADDRESS_*
> fournie par l'utilisateur (11.40 et 14.00/14.10). Si un firmware plante,
> regarde d'abord le log (`/data/gta5.log` ou equivalent) pour un message
> "firmware non supporte" avant de suspecter autre chose.

---

## 0. Comment l'utiliser (placement des fichiers par FTP)

Sur la PS5, via FTP :

- **Le `.plugin`** → `/data/etaHEN/plugins/` (c'est etaHEN lui-meme qui
  charge les `.plugin` depuis ce dossier au demarrage)
- **Le fichier config** → `/data/PluginLoader/PluginLoader.ini`
- **Les `.prx`** → `/data/PluginLoader/` (chemin ecrit dans le `.ini` est
  relatif a ce dossier, ex: `prx/Exemple.prx` devient
  `/data/PluginLoader/prx/Exemple.prx`)

#### Editer le `.ini` avec Notepad2

1. Connecte-toi en FTP sur la PS5, va dans `/data/PluginLoader/`.
2. Clic droit sur `PluginLoader.ini` -> "Edit" / "Open with" -> **Notepad2**
   (ou telecharge-le, edite en local, reuploade au meme endroit).
3. Syntaxe : une section `[TITLEID]` par jeu (`PPSAxxxxx` pour PS5,
   `CUSAxxxxx` pour PS4), puis une ligne par `.prx` a charger sous cette
   section : `chemin/du.prx:delai_en_frames` (`:delai` optionnel, 60 par
   defaut = 1 seconde a 60fps). `;` ou `#` en debut de ligne = commentaire.

Exemple avec un jeu PS5 (`PPSA`) et un jeu PS4 (`CUSA`) dans le meme `.ini` :

```ini
[PPSA04263]
fakelib=true
prx/BeachMenu.prx:60
or with LSO
[PPSA04263]
fakelib=true
prx/LSOExemple.prx:60
prx/BeachMenu.prx:600

[PPSA04264]
fakelib=true
prx/BeachMenu.prx:60
# Or with LSO
[PPSA04264]
fakelib=true
prx/LSOExemple.prx:60
prx/BeachMenu.prx:600

[CUSA00411]
prx/BeachMenu157.prx:60
# Or with LSO
[CUSA00411]
prx/LSOPlugin.prx:60
prx/BeachMenu157.prx:600

[CUSA00419]
prx/BeachMenu157.prx:60
# Or with LSO
[CUSA00419]
prx/LSOPlugin.prx:60
prx/BeachMenu157.prx:600

[CUSA03041]
prx/Sheriff.prx:60

[CUSA08519]
prx/Sheriff.prx:60
```

- `fakelib=true/false` : lu, mais **ignore automatiquement sur les `CUSA`**
  (PS4) -- actif par defaut (`true`) sur les `PPSA` (PS5) sans avoir besoin
  de l'ecrire, sauf pour le desactiver.
- Plusieurs lignes `.prx` sous le meme `[TITLEID]` = plusieurs plugins
  charges pour ce jeu (ex: un pour le LSO, un pour le menu).
- Pas de cle `inject` ici : tout `.prx` liste sous une section est injecte.

#### Section `[DEFAULT]` (valeur globale pour `fakelib`)

Ajoute dans `Plugin-Loader-v3.01-DEFAULT-fix.zip` -- **pas presente a
l'origine dans le code envoye**, c'est un ajout de ma part.

```ini
[DEFAULT]
fakelib=false

[PPSA04264]
prx/FullBeachMenu-1.011.001.prx:60

[PPSA04263]
fakelib=true
prx/LSO-1.010.prx:60
```

- `[DEFAULT]` n'est **pas** un Title ID : c'est juste la valeur de secours
  pour `fakelib` quand un `[PPSAxxxxx]` n'a pas sa propre ligne `fakelib=`.
- Dans l'exemple : `PPSA04264` (pas de `fakelib=` a lui) herite du
  `[DEFAULT]` -> `false`. `PPSA04263` a sa propre ligne `fakelib=true` ->
  elle gagne, `[DEFAULT]` est ignore pour ce jeu-la.
- Toujours **PPSA uniquement** : `[DEFAULT]` n'affecte jamais les `CUSA`.
- Sans `[DEFAULT]` dans le fichier : comportement identique a avant
  (`fakelib=true` par defaut pour tout `PPSA`).

⚠️ Teste sur l'hote avec le vrai fichier `.ini` fourni (logique de parsing
verifiee ligne par ligne), mais **pas compile avec le vrai SDK PS5** ici --
a tester sur console avant de considerer que c'est bon.
---

## 1. Fichiers mis a jour et ce qu'ils couvrent

### `libhijacker/source/offsets.cpp`
Offsets noyau (allproc, security_flags, qa_flags, utoken_flags, root_vnode).

| Firmware | Statut |
|---|---|
| 11.00 / 11.20 / 11.40 / 11.60 | ✅ ajoute |
| 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70 | ✅ ajoute |
| 13.00 / 13.20 | ✅ ajoute |
| 13.40 / 13.42 | ✅ ajoute |
| 13.60 | ✅ ajoute |
| **14.00 / 14.10** | ✅ ajoute |

Valeurs (allproc / security_flags / root_vnode) :
- 11.00-11.60 (11.40 inclus) : `42425712 (0x2875D70)` / `14205028 (0xD8C064)` / `51082512 (0x30B7510)`
- 12.xx : `42491392 (0x2885E00)` / `14168164 (0xD83064)` / `51213584 (0x30D7510)`
- 13.00/13.20 : `42753536 (0x28C5E00)` / `14258276 (0xD99064)` / `51590416 (0x3133510)`
- 13.40/13.42 : `42770048 (0x28C9E80)` / `14258276 (0xD99064)` / `51606800 (0x3137510)`
- 13.60 : `42770048 (0x28C9E80)` / `14270564 (0xD9C064)` / `51688720 (0x314B510)`
- **14.00/14.10** : `42991264 (0x28D9EA0)` / `14303332 (0xDA4064)` / `51705616 (0x315B510)`

11.40 et 14.00/14.10 viennent de la table `KERNEL_ADDRESS_*` fournie par
l'utilisateur ; testes sur l'hote (switch isole, build g++) : chaque version
renvoie la bonne valeur, et un firmware non liste tombe toujours dans le
`default` (`-1` + message), donc les garde-fous restent actifs.

`security_flags` pour tout le bloc 13.xx (13.00/13.20/13.40/13.42/13.60) est
confirme independamment par ps5debug-NG (projet "Fully Verified" sur
materiel reel) : son kpatch syscall-filter cible `kbase + 0xD99088` pour
13.00/13.20/13.40/13.42 et `kbase + 0xD9C088` pour 13.60 -- exactement
`security_flags() + 0x24` (= `qa_flags()`) dans les deux cas, donc
`0xD99064` et `0xD9C064` sont corrects, pas juste portes d'une table.

**4 fonctions supplementaires ajoutees** (table complete 1.00 -> 14.10,
fournie par l'utilisateur) :
- `text_base_delta()` -- `KERNEL_ADDRESS_TEXT_BASE`. **Signee** (negative) :
  l'adresse reelle est `kernel_data_base + text_base_delta()`.
- `bus_data_devices()` -- `KERNEL_ADDRESS_BUS_DATA_DEVICES`, addition classique.
- `vmspace_p_root()` / `vmspace_vm_pmap()` -- `KERNEL_OFFSET_VMSPACE_*`. Ce
  sont des offsets de champs **dans** la structure `vmspace`, pas relatifs a
  `KERNEL_ADDRESS_DATA_BASE`.

⚠️ **Dormantes** : aucun appelant existant (`hijacker.cpp`, `dbg.cpp`,
`elf.cpp`...) ne les utilise encore. Ajoutees pretes a l'emploi si un besoin
se presente. Testees sur l'hote pour plusieurs firmwares (1.00, 1.05, 2.00,
6.00, 11.00, 11.40, 13.60, 14.00, 14.10) sans regression sur les 5 fonctions
d'origine.

### `libhijacker/source/dbg.cpp` et `hijacker.cpp`
Garde-fous : si le firmware n'est pas dans `offsets.cpp` (renvoie `-1`),
le code **s'arrete proprement** au lieu de lire une adresse noyau invalide.
- `dbg.cpp::getCurrentProc()` -> renvoie `0` si `allproc() == -1`
- `hijacker.cpp::jailbreak()` -> abandonne si `root_vnode() == -1`

`hijacker2.cpp` a disparu de l'arbre (un seul hijacker reste, pas de doublon
a maintenir).

### `libSelfDecryptor/source/selfpager.c`
Table `pagertab_addr` par firmware (necessaire pour le dechiffrement des SELF).

| Plage | Statut |
|---|---|
| 1.00 -> 10.01 | deja presente avant mes ajouts |
| 10.20 / 10.60 | ✅ `0xDE04F0` |
| 11.00 / 11.20 | ✅ `0xDF1940` |
| 11.40 / 11.60 | ✅ `0xDF1960` |
| 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70 | ✅ `0xDF2860` |
| 13.00 / 13.20 | ✅ `0xE038D0` |
| 13.40 / 13.42 / 13.60 | ✅ `0xE03910` |
| **14.00 / 14.10** | ❌ **absent** — aucune valeur trouvee -> `ENOSYS` |

### `include/hijacker/patch_shellcore.hpp`
Patch de SceShellCore (acces `/data` en sandbox etc.), par recherche de pattern
binaire + offset.

| Plage | Statut |
|---|---|
| 4.00 -> 13.60 | ✅ fonctionne (13.40/13.42/13.60 en table exacte verifiee sur dump ; 13.00/13.20 en mode secours, meme pattern -- voir note) |
| **14.00 / 14.10** | ⚠️ **mode secours seulement** (meme mecanisme, voir plus bas) |

13.40/13.42 et 13.60 sont passes en table exacte apres verification contre
de vrais dumps `SceShellCore.elf` des deux firmwares (`1340_SceShellCore.elf`
et `1360_SceShellCore.elf`) : les patterns 12.70 non modifies (`/data`
sandbox pat1 + pat2, le pattern `onNewProcess`, le pattern `GetAppInfoSfo`)
matchent chacun **exactement une fois** dans les deux binaires, sans besoin
de les relacher. Ces deux firmwares ne sont plus non-verifies.

**13.00/13.20** restent sur le mode secours (pas de dump dedie pour ces
deux-la), mais il n'y a aucune raison de douter que ca marche aussi : le
mode secours reutilise ce meme pattern 12.70, et ce pattern est confirme
unique (1 seule occurrence) sur 13.40 ET 13.60 -- rien n'indique que Sony
l'aurait change specifiquement sur 13.00/13.20 au milieu de ce cycle. Le
mode secours n'est pas fragile : il verifie lui-meme l'unicite du match
avant d'ecrire quoi que ce soit (`sc_pattern_count`), donc meme si le
pattern avait change, le pire cas est "aucun patch applique", jamais un
crash. 13.00/13.20 fonctionne donc tres probablement, juste non confirme
par un dump reel dedie -- a la difference de 14.00/14.10 ci-dessous, pour
qui on n'a aucune donnee du tout.

Pour les FW encore hors de la table exacte (13.00/13.20, et 14.00/14.10), le
mode secours (`sc_lookup_patch_set` + `sc_pattern_count`) prend le relai :
1. reutilise le pattern de l'entree exacte connue la plus proche en dessous,
2. scanne le binaire SceShellCore de ce firmware avec ce pattern,
3. **applique le patch seulement si le pattern est trouve exactement une
   fois**,
4. sinon (0 ou plusieurs matches) : abandonne, pas de patch, pas de crash.

`sc_lookup_patch_set()` n'a pas de plafond fixe : pour tout firmware
au-dessus de la derniere entree exacte connue (maintenant 13.60), il
reutilise automatiquement les patterns de cette entree via ce mode secours.
Donc 14.00/14.10 n'est pas litteralement "non gere" -- il passe par
exactement le meme mecanisme de secours que 13.00/13.20, avec la meme
securite ("n'ecrit que si chaque pattern matche exactement une fois"). Pour
une vraie entree dediee, il faut dumper `SceShellCore.elf` de ce firmware et
en extraire le pattern reel.

---

## 2. Ce qui n'a PAS besoin de mise a jour FW

Verifie sur tout l'arbre (`libelfloader`, `libelfldr`, `libNineS`,
`libNidResolver`, `stubber`, `Plugin_samples`, `lib/`) : aucune autre table
dependante du firmware n'existe. Les seuls fichiers concernes par le
firmware sont les 4 listes ci-dessus.

- `libelfloader` / `libelfldr` : loader ELF autonome (ps5-payload-dev), pas
  de table FW, syscalls generiques stables entre firmwares. Pas utilise par
  l'injection de PRX (c'est `libhijacker/source/elf/elf.cpp` qui fait ca).
- `stubber` : outil Go qui tourne sur PC, genere des stubs de lib depuis des
  `.so`/`.sprx`, ne connait pas la notion de firmware PS5.

---

## 3. Recapitulatif rapide

| Composant | 11.xx | 12.xx | 13.xx | 14.xx |
|---|---|---|---|---|
| Offsets noyau (`offsets.cpp`) | ✅ | ✅ | ✅ | ✅ |
| Garde-fous (`dbg.cpp`/`hijacker.cpp`) | ✅ | ✅ | ✅ | ✅ |
| Pagertab (`selfpager.c`) | ✅ | ✅ | ✅ | ❌ |
| Patch SceShellCore | ✅ | ✅ | ✅ (13.40/13.60 verifies sur dump ; 13.00/13.20 secours, tres probablement OK) | ⚠️ secours |

⚠️ = fonctionne via le mode secours, mais sans dump dedie pour confirmer (voir section 1).
❌ = non supporte, erreur propre (`ENOSYS` ou abandon), pas de crash.

---

## 4. Pour completer ce qui manque

Pour chaque trou, il faut une donnee precise que je n'ai pas :

- **Pagertab 14.00-14.10** : la valeur `pagertab_addr`
  (offset depuis `KERNEL_ADDRESS_DATA_BASE`) pour ce firmware precis.
- **Pattern SceShellCore pour 13.00/13.20 et 14.00/14.10** (les seules
  plages encore en mode secours non verifie ; 13.40/13.42 et 13.60 sont deja
  verifies) : un dump de `SceShellCore.elf` pour ce firmware, ou directement
  les octets autour de la fonction patchee.
- **Offsets de structures noyau** (ex. attribut `ucred`, suspecte different
  depuis FW 8.00) : non verifies, a confirmer sur console reelle.

Envoie le fichier ou le resultat d'un scan et je complete la table
correspondante.
