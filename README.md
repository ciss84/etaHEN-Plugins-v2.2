# etaHEN-Plugins-Loader-v3.01 — Firmware update status (4.00 -> 14.10)

This document summarizes what has been updated in the `etaHEN-Plugins` tree
to support recent firmwares, what is still unverified, and what is
completely missing. Read this before flashing/testing on a console.

> FW 4.xx to 7.xx, maybe up to 8.xx: everything here has been tested on a
> real PS5. FW 8.xx and above: nothing here has been tested on a real PS5.
> The added values come from public sources (etaHEN "unified" port,
> firmware-profiles.json, ps5-payload-dev / ftpsrv self-prospero.c) and a
> KERNEL_ADDRESS_* table provided by the user (11.40 and 14.00/14.10). If a
> firmware crashes, check the log (`/data/gta5.log` or equivalent) first for
> an "unsupported firmware" message before suspecting anything else.

---

## 0. How to use it (placing the files via FTP)

On the PS5, via FTP:

- **The config file** → `/data/PluginLoader/PluginLoader.ini`
- **The `.prx` files** → `/data/PluginLoader/` (the path written in the
  `.ini` is relative to this folder, e.g. `prx/Example.prx` becomes
  `/data/PluginLoader/prx/Example.prx`)

#### Editing the `.ini` with Notepad2

1. Connect via FTP to the PS5, go to `/data/PluginLoader/`.
2. Right-click `PluginLoader.ini` -> "Edit" / "Open with" -> **Notepad2**
   (or download it, edit it locally, then re-upload it to the same place).
3. Syntax: one `[TITLEID]` section per game (`PPSAxxxxx` for PS5,
   `CUSAxxxxx` for PS4), then one line per `.prx` to load under that
   section: `path/to.prx:delay_in_frames` (`:delay` optional, defaults to
   60 = 1 second at 60fps). `;` or `#` at the start of a line = comment.

Example with a PS5 game (`PPSA`) and a PS4 game (`CUSA`) in the same `.ini`:

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

- `fakelib=true/false`: read, but **automatically ignored on `CUSA`** (PS4)
  -- enabled by default (`true`) on `PPSA` (PS5) with no need to write it,
  except to disable it.
- Multiple `.prx` lines under the same `[TITLEID]` = multiple plugins
  loaded for that game (e.g. one for the LSO, one for the menu).
- No `inject` key here: every `.prx` listed under a section is injected.
---

## 1. Updated files and what they cover

### `libhijacker/source/offsets.cpp`
Kernel offsets (allproc, security_flags, qa_flags, utoken_flags, root_vnode).

| Firmware | Status |
|---|---|
| 11.00 / 11.20 / **11.40** / 11.60 | ✅ added |
| 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70 | ✅ added |
| 13.00 / 13.20 | ✅ added |
| 13.40 / 13.42 | ✅ added |
| 13.60 | ✅ added |
| **14.00 / 14.10** | ✅ added |

Values (allproc / security_flags / root_vnode):
- 11.00-11.60 (11.40 included): `42425712 (0x2875D70)` / `14205028 (0xD8C064)` / `51082512 (0x30B7510)`
- 12.xx: `42491392 (0x2885E00)` / `14168164 (0xD83064)` / `51213584 (0x30D7510)`
- 13.00/13.20: `42753536 (0x28C5E00)` / `14258276 (0xD99064)` / `51590416 (0x3133510)`
- 13.40/13.42: `42770048 (0x28C9E80)` / `14258276 (0xD99064)` / `51606800 (0x3137510)`
- 13.60: `42770048 (0x28C9E80)` / `14270564 (0xD9C064)` / `51688720 (0x314B510)`
- **14.00/14.10**: `42991264 (0x28D9EA0)` / `14303332 (0xDA4064)` / `51705616 (0x315B510)`

11.40 and 14.00/14.10 come from the `KERNEL_ADDRESS_*` table provided by the
user; tested on the host (isolated switch, g++ build): every version
returns the correct value, and an unlisted firmware always falls through to
the `default` case (`-1` + message), so the safety guards stay active.

**4 additional functions added** (full table 1.00 -> 14.10, provided by the
user):
- `text_base_delta()` -- `KERNEL_ADDRESS_TEXT_BASE`. **Signed** (negative):
  the real address is `kernel_data_base + text_base_delta()`.
- `bus_data_devices()` -- `KERNEL_ADDRESS_BUS_DATA_DEVICES`, plain addition.
- `vmspace_p_root()` / `vmspace_vm_pmap()` -- `KERNEL_OFFSET_VMSPACE_*`.
  These are field offsets **inside** the `vmspace` structure, not relative
  to `KERNEL_ADDRESS_DATA_BASE`.

⚠️ **Dormant**: no existing caller (`hijacker.cpp`, `dbg.cpp`, `elf.cpp`...)
uses them yet. Added ready to use whenever a need comes up. Tested on the
host for several firmwares (1.00, 1.05, 2.00, 6.00, 11.00, 11.40, 13.60,
14.00, 14.10) with no regression on the 5 original functions.

### `libhijacker/source/dbg.cpp` and `hijacker.cpp`
Safety guards: if the firmware isn't in `offsets.cpp` (returns `-1`), the
code **stops cleanly** instead of reading an invalid kernel address.
- `dbg.cpp::getCurrentProc()` -> returns `0` if `allproc() == -1`
- `hijacker.cpp::jailbreak()` -> bails out if `root_vnode() == -1`

`hijacker2.cpp` is gone from the tree (only one hijacker remains, no
duplicate to maintain).

### `libSelfDecryptor/source/selfpager.c`
`pagertab_addr` table per firmware (needed for SELF file decryption).

| Range | Status |
|---|---|
| 1.00 -> 10.01 | already present before my additions |
| **10.20 -> 10.60** | ❌ **missing** — no public value found -> `ENOSYS` |
| 11.00 / 11.20 | ✅ `0xDF1940` |
| **11.40** | ❌ **missing** — the provided table doesn't cover this structure, and the pagertab already splits 11.00/11.20 from 11.60 -> no reliable value can be inferred -> `ENOSYS` |
| 11.60 | ✅ `0xDF1960` |
| 12.00 / 12.02 / 12.20 / 12.40 / 12.60 / 12.70 | ✅ `0xDF2860` |
| 13.00 / 13.20 | ✅ `0xE038D0` |
| 13.40 / 13.42 / 13.60 | ✅ `0xE03910` |
| **14.00 / 14.10** | ❌ **missing** — no value found -> `ENOSYS` |

### `include/hijacker/patch_shellcore.hpp`
SceShellCore patch (`/data` sandbox access, etc.), via binary pattern + offset.

| Range | Status |
|---|---|
| 4.00 -> 12.70 | ✅ exact table, patterns verified |
| **13.00 -> 13.60** | ⚠️ **fallback mode only** |
| **14.00 / 14.10** | ❌ no constant or pattern -> not handled |

The fallback mode (`sc_lookup_patch_set` + `sc_pattern_count`):
1. reuses the known 12.70 pattern (the last firmware with a real pattern),
2. scans the firmware 13.xx SceShellCore binary with that pattern,
3. **only applies the patch if the pattern is found exactly once**,
4. otherwise (0 or multiple matches): gives up, no patch, no crash.

Consequence: on 13.xx the patch can simply do nothing (silently) if the
pattern changed between 12.70 and that firmware. For a real 13.xx or 14.xx
entry, `SceShellCore.elf` for that firmware needs to be dumped to extract
the real pattern.

---

## 2. What does NOT need a FW update

Checked across the whole tree (`libelfloader`, `libelfldr`, `libNineS`,
`libNidResolver`, `stubber`, `Plugin_samples`, `lib/`): no other
firmware-dependent table exists. The only files affected by firmware are
the 4 listed above.

- `libelfloader` / `libelfldr`: standalone ELF loader (ps5-payload-dev), no
  FW table, generic syscalls stable across firmwares. Not used by PRX
  injection (that's `libhijacker/source/elf/elf.cpp`'s job).
- `stubber`: a Go tool that runs on the PC, generates lib stubs from
  `.so`/`.sprx` files, has no notion of PS5 firmware.

---

## 3. Quick summary

| Component | 11.xx | 12.xx | 13.xx | 14.xx |
|---|---|---|---|---|
| Kernel offsets (`offsets.cpp`) | ✅ (11.40 included) | ✅ | ✅ | ✅ |
| Safety guards (`dbg.cpp`/`hijacker.cpp`) | ✅ | ✅ | ✅ | ✅ |
| Pagertab (`selfpager.c`) | ⚠️ (except 11.40 ❌) | ✅ | ✅ | ❌ |
| SceShellCore patch | ✅ | ✅ | ⚠️ fallback only | ❌ |

⚠️ = works but with a known limitation (see section 1).
❌ = unsupported, clean error (`ENOSYS` or bail-out), no crash.

---

## 4. To finish what's missing

For each gap, a precise piece of data is needed that I don't have:

- **Pagertab 10.20-10.60 / 11.40 / 14.00-14.10**: the `pagertab_addr` value
  (offset from `KERNEL_ADDRESS_DATA_BASE`) for that specific firmware.
- **SceShellCore pattern 13.xx / 14.xx**: a dump of `SceShellCore.elf` for
  that firmware, or directly the bytes around the patched function.
- **Kernel structure offsets** (e.g. the `ucred` attribute, suspected to
  differ since FW 8.00): unverified, needs confirming on real hardware.

Send the file or the result of a scan and I'll fill in the corresponding
table.
