# etaHEN-Plugins — Etat des mises a jour firmware (11.00 -> 13.60)

Ce document resume ce qui a ete mis a jour dans l'arbre `etaHEN-Plugins` pour
supporter les firmwares recents, ce qui reste non verifie, et ce qui manque
completement. A lire avant de flasher/tester sur console.

> Rien ici n'a ete teste sur un vrai PS5. Les valeurs ajoutees viennent de
> sources publiques (portage etaHEN "unified", firmware-profiles.json,
> ps5-payload-dev / ftpsrv self-prospero.c). Si un firmware plante, regarde
> d'abord le log (`/data/gta5.log` ou equivalent) pour un message
> "firmware non supporte" avant de suspecter autre chose.

---

## 1. Fichiers mis a jour et ce qu'ils couvrent

### `libhijacker/source/offsets.cpp`
Offsets noyau (allproc, security_flags, qa_flags, utoken_flags, root_vnode).

| Firmware | Statut |
|---|---|
| 11.00 / 11.20 / 11.60 | ✅ ajoute |
| 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70 | ✅ ajoute |
| 13.00 / 13.20 | ✅ ajoute |
| 13.40 / 13.42 | ✅ ajoute |
| 13.60 | ✅ ajoute |

Valeurs (allproc / security_flags / root_vnode) :
- 11.00-11.60 : `42425712 (0x2875D70)` / `14205028` / `51082512`
- 12.xx : `42491392` / `14168164` / `51213584`
- 13.00/13.20 : `42753536` / `14258276` / `51590416`
- 13.40/13.42 : `42770048` / `14258276` / `51606800`
- 13.60 : `42770048` / `14270564` / `51688720`

### `libhijacker/source/dbg.cpp` et `hijacker.cpp`
Garde-fous ajoutes : si le firmware n'est pas dans `offsets.cpp` (renvoie `-1`),
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
| **10.20 -> 10.60** | ❌ **absent** — aucune valeur publique trouvee -> `ENOSYS` |
| 11.00 / 11.20 | ✅ `0xDF1940` |
| **11.40** | ❌ **absent** — aucune valeur publique trouvee -> `ENOSYS` |
| 11.60 | ✅ `0xDF1960` |
| 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70 | ✅ `0xDF2860` |
| 13.00 / 13.20 | ✅ `0xE038D0` |
| 13.40 / 13.42 / 13.60 | ✅ `0xE03910` |

### `include/hijacker/patch_shellcore.hpp`
Patch de SceShellCore (acces `/data` en sandbox etc.), par recherche de pattern
binaire + offset.

| Plage | Statut |
|---|---|
| 4.00 -> 12.70 | ✅ table exacte, patterns verifies |
| **13.00 -> 13.60** | ⚠️ **mode secours seulement** |

Le mode secours (`sc_lookup_patch_set` + `sc_pattern_count`) :
1. reutilise le pattern connu du 12.70 (dernier firmware avec un vrai pattern),
2. scanne le binaire SceShellCore du firmware 13.xx avec ce pattern,
3. **applique le patch seulement si le pattern est trouve exactement une
   fois**,
4. sinon (0 ou plusieurs matches) : abandonne, pas de patch, pas de crash.

Consequence : sur 13.xx le patch peut simplement ne rien faire (silencieux)
si le pattern a change entre 12.70 et ce firmware. Pour une vraie entree
13.xx il faut dumper `SceShellCore.elf` de ce firmware et en extraire le
pattern reel.

---

## 2. Ce qui n'a PAS besoin de mise a jour FW

Verifie sur tout l'arbre (`libelfloader`, `libNineS`, `libNidResolver`,
`stubber`, `Plugin_samples`, `lib/`) : aucune autre table dependante du
firmware n'existe. Les seuls fichiers concernes par le firmware sont les 4
listes ci-dessus.

---

## 3. Recapitulatif rapide

| Composant | 11.xx | 12.xx | 13.xx |
|---|---|---|---|
| Offsets noyau (`offsets.cpp`) | ✅ | ✅ | ✅ |
| Garde-fous (`dbg.cpp`/`hijacker.cpp`) | ✅ | ✅ | ✅ |
| Pagertab (`selfpager.c`) | ⚠️ (sauf 11.40) | ✅ | ✅ |
| Patch SceShellCore | ✅ | ✅ | ⚠️ secours uniquement |

⚠️ = fonctionne mais avec une limite connue (voir sections 1).
❌ = non supporte, erreur propre (`ENOSYS` ou abandon), pas de crash.

---

## 4. Pour completer ce qui manque

Pour chaque trou, il faut une donnee precise que je n'ai pas :

- **Pagertab 10.20-10.60 / 11.40** : la valeur `pagertab_addr` (offset depuis
  `KERNEL_ADDRESS_DATA_BASE`) pour ce firmware precis.
- **Pattern SceShellCore 13.xx** : un dump de `SceShellCore.elf` pour ce
  firmware, ou directement les octets autour de la fonction patchee.
- **Offsets de structures noyau** (ex. attribut `ucred`, suspecte different
  depuis FW 8.00) : non verifies, a confirmer sur console reelle.

Envoie le fichier ou le resultat d'un scan et je complete la table
correspondante.
