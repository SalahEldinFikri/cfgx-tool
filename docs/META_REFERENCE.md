# cfgx rule-meta reference

cfgx reads its instructions from the `meta:` section of your YARA rule. Nothing is needed for a rule to *detect* a sample;
meta only tells cfgx **where the data/keys are, how long they are, and what to do with them**.

## 1. How a rule becomes a decryption

* Every YARA string (`$config`, `$key`, `$data2` ...) is a **target**: the place its match points at (or the data a code
  reference in it points at).
* Targets are handed to your plugin's `decrypt(...)` **by name**:

| rule string | goes to the plugin as |
|---|---|
| `$config`, `$data`, `$cfg`, `$payload`, `$blob` | `data` |
| any other, e.g. `$key`, `$iv`, `$nonce`, `$salt` | the parameter with the same name |
| `$config2`, `$data_v2`, `$key_32`, `$key1` | a **variant**: same role (`config`/`key`), suffix `2`/`v2`/`32`/`1` |

* Several data targets = several entries (one result each). Several keys for one blob = alternatives (the readable one wins).
* A variant inherits the meta of its role: `$config2` uses `config_*`, `$key_32` uses `key_*`, unless it has its own line.
* A detection-only string (`$m1`, `$s1` ...) is ignored when a plugin is used. With **no plugin** every string is read;
  limit that with `extract = "..."` (below).

In a meta key, `config` stands for the string's name without `$`: for `$tbl` write `tbl_size`, `tbl_ref_index`, ...

## 2. Rule-level meta

| key | value | meaning |
|---|---|---|
| `family` | `"Stealc"` | name of the family. Put the **same** value in every rule of a family: one output folder, one family file. (A plugin's `FAMILY = "..."` wins over it.) |
| `extract` | `"c2"` / `"key_*, data_*"` / `"none"` | which strings to read when **no plugin** is used (comma list, `*` wildcards). `"none"` = detection-only rule (listed as `detected`, nothing extracted). |
| `mips_gp` | `0x4a0ff0` | MIPS only: value of `_gp`, when the ELF has no `.reginfo`/`.got` to take it from. |
| anything else | any | free for your plugin: `ctx.meta.get("algo")` ... (the AISURU plugin uses `algo = "rc4"`). |

## 3. Per-string meta  (`<name>_<key>`)

### Where is the data?

| key | values | default | meaning |
|---|---|---|---|
| `_ref` | `"auto"` `"code"` `"none"` | `auto` | `auto`: if the match is in an executable section, follow the address the instructions load (`lea`, `push offset`, `mov esi,imm`, `ldr r,=x`, `lw $gp`...); otherwise the match itself is the data. `code`: always follow. `none`: never (the matched bytes ARE the data, e.g. a key literal inside `.text`). |
| `_ref_index` | `0`, `1`, `-1`, `"all"` | `0` | which address-loading instruction of the match: 0 = the first. `"all"` = every one is a separate entry. References into `.bss` count (they have no bytes in the file, so they are skipped when reading). |
| `_deref` | `true` | `false` | the address is a **pointer variable** (`mov edx, ds:off_805BD48`): read the pointer (native width) and follow it. |
| `_adjust` | `4`, `-8` | `0` | add N bytes to the final start offset (skip a header). |
| `_resource` | `"RCDATA/101"` | - | the data is a **PE resource** (section 4). |
| `_section` | `".rdata"` | - | the data is a **named section** (PE or ELF). |

### How long is it?  (first one that applies wins)

| order | key | values | meaning |
|---|---|---|---|
| 1 | `_size` | `16`, `0x200` | fixed number of bytes. |
| 2 | `_size_at` | `25` | the length is an **immediate in the matched instructions**: byte offset *inside the match* (count your hex string: 7+5+6+3 ...). Go strings, `push 0Ah`, `mov [esp+4], 13h`. |
|   | `_size_bytes` | `1`, `2`, `4` | width of that immediate (default 4). |
|   | `_size_endian` | `"little"` `"big"` | byte order of it (default: the file's, big-endian MIPS works automatically). |
|   | `_size_mul` | `4` | multiply it (a DWORD count from `mov ecx, 0Ch` / `rep movsd`). |
|   | `_size_tail` | `"F3A5 66A5=2 A4=1"` | after the anchor (`rep movsd`) add 2 for a following `movsw`, 1 for `movsb`. |
| 3 | `_size_reg` | `"r2"` ARM, `"a2"` MIPS | the length is the value of an **argument register at the next call** (`MOV R2,#n` / `li $a2,N`, delay slot included). |
|   | `_size_window` | `64` | how many bytes after the reference to look for that call. |
| 4 | `_until` | `"00"`, `"0000"` | read up to this hex terminator. |
| 5 | (match mode) | | if the match itself is the data (`_ref = none`, or text in a data section): the length of the match. |
| 6 | (default) | | up to the first NUL byte (cap: `_max`). Fine for strings; **binary blobs need a size**. |
|   | `_max` | `65536` | cap for NUL/terminator reads (and for lengths taken from the code). |

## 4. Resources and sections

```yara
meta:
    config_resource = "RCDATA/101"        // TYPE/NAME[/LANG]
    config_adjust   = 4                   // skip a 4-byte header
    key_resource    = "RCDATA/KEYRES"
    blob_section    = ".cfg"              // whole content of a named section
```
* **TYPE**: a standard name (`RCDATA`, `RT_RCDATA`, `ICON`, `MANIFEST`, `VERSION`, `HTML`, `STRING`, `BITMAP` ...), a number
  (`10`, `0xA`) or a custom type name (`"BIN"`). Case-insensitive.
* **NAME**: a number (`101`), a string (`"CONFIG"`), `*` (every resource of that type: one entry each) or `#N` (the N-th name, from 0).
* **LANG**: optional, `1033` / `0x409` / `*` (default any).
* `_adjust`, `_size`, `_until` apply to the resource bytes. A resource/section target needs **no YARA string**; the rule just has to
  match through some other string. `-v` puts the file's resource list in the JSON (`sample.resources`); when nothing matches, the
  warning lists the resources the file does have.
* Resources exist only in PE files (ELF: use `_section`).

## 5. Copy-paste blocks

```yara
// C2 string in a Go binary: pointer from `lea`, length from `mov [esp+4], 0Dh`        (no plugin)
extract = "c2"        c2_size_at = 25

// XOR/RC4 config behind two `lea`s, key is a literal in .rdata
config_size = 512     key_size = 16

// one entry per call site, length from the code, key through a pointer variable
config_size_at = 1    config_size_bytes = 1    key_deref = true    key_size = 16

// ARM: key = 2nd literal load, entries = every LDR R1,=x, length = R2 at the BL
key_ref_index = 1     key_size = 16     config_ref_index = "all"     config_size_reg = "r2"

// MIPS PIC (GOT via $gp): first reference is the entry, length = $a2
key_size = 16         config_ref_index = 0     config_size_reg = "a2"     // mips_gp = 0x4a0ff0

// rep movsd blobs: DWORD count * 4 (+ movsw/movsb tail)
config_size_at = 6    config_size_bytes = 1    config_size_mul = 4    config_size_tail = "F3A5 66A5=2 A4=1"

// detection-only rule of a family that has per-architecture config rules
family = "Vulcan"     extract = "none"
```

## 6. YARA meta syntax

* Integers: `16`, `0x10`. Strings need quotes: `"all"`, `"r2"`, `"F3A5 66A5=2"`. Booleans: `true`/`false`.
* Names are case-sensitive and use `_`: `Config_size_at` belongs to `$Config`.
* `//` comments are fine inside `meta:`.
* A wrong value is reported, not guessed: unknown register (`"li"` is an instruction, the register is `"a2"`), a size offset outside
  the match, a bad resource spec - each prints a warning that names the key.

## 7. What the warnings mean

| warning | set |
|---|---|
| `no 'x_size' / 'x_until' ... read up to the first NUL` | `x_until = "00"` to confirm text, or `x_size` for binary |
| `x_ref_index=1 but only 1 reference(s) found` | the match loads fewer addresses than you think: lower the index, or look at the instructions |
| `no code reference found ... set x_ref = "none"` | the match is data (not code): `x_ref = "none"` |
| `reference to 0x... is skipped: .bss` | the address has no bytes in the file (state buffer); normal for `"all"` |
| `could not recover the size from r2` | `x_size_window` bigger, or the length is not an immediate |
| `$gp value is unknown` | `mips_gp = 0x...` |
| `none of the N entries decrypted to readable text` | wrong key or cipher (ignore for binary families) |
