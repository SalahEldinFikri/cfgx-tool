# 0.3.0
* **x86 v2 cipher identified and implemented exactly**: key schedule `sub_804D070` (S[i] = 13 - 89*i, key-word pass, five LCG
  scrambling passes) + the routine-three PRGA. Verified against the keystream recovered from real samples (24/24 bytes) and
  against real ciphertext; table entries stored unencrypted (flag byte 0) are left alone.
* **PE resources and named sections as sources**: `<name>_resource = "TYPE/NAME[/LANG]"` (standard/custom type, number or name,
  `*`, `#N`) and `<name>_section = ".cfg"`, with `_adjust`/`_size`/`_until`; no YARA string needed. `-v` lists the file's resources
  in the JSON; a missing resource names the ones that exist.
* **`docs/META_REFERENCE.md`**: every rule-meta key, defaults, precedence of the length rules, copy-paste blocks, warning cheat-sheet.

# 0.2.11
* When a plugin returns three or more entries and none decodes to readable text, a warning says so and the entries are marked
  `confidence: low` (on a real sample a wrong cipher printed 16 confident-looking hex rows).
* AISURU example: documents what real v2 data showed (shared keystream, first 24 bytes recovered; the v2 cipher is not identified yet).

# 0.2.10
Fixes from the first run on real AISURU samples:
* **ELF `.bss` was dropped** when the file had a section table, so `LDR R0,=ctx` (state buffer in .bss) left no placeholder and
  `key_ref_index = 1` failed with "only 1 reference(s) found". NOBITS sections are now mapped (no file bytes, but in memory).
* **`<name>_size_tail`**: `rep movsd` copies are followed by `movsw`/`movsb` for the last 1-3 bytes; sizes are now exact.
* **Console**: every non-printable character (including C1 codes like 0x9B and U+2028, which terminals treat as escapes) is
  escaped; a string containing one could make a table row disappear.
* **AISURU example**: in real samples each `$config` match is one blob (not a table); `algo = "auto"` tries each cipher per entry
  and keeps the readable one; `ctx.notes` lets a plugin report the choice (`-v`).

# 0.2.9
* **`<name>_deref`**: follow a pointer variable (`mov edx, ds:off_...` -> key string).
* **`<name>_size_mul`**: scale a length taken from the code (DWORD counts).
* **x86**: `mov r,[abs32]` and `mov eax,[moffs32]` are reported as references (kind `mov-mem`).
* **Stable `ref_index`**: references into `.bss` / zero-initialised memory are kept as placeholders (no file offset) instead of
  disappearing, so indexes count instructions, not "targets that happen to be in the file".
* Plugin context: `ctx.variant`, `ctx.names` (which rule string is being decrypted).
* `examples/aisuru`: x86 v1, x86 v2 (custom cipher, pointer-variable key, table), ARM; the cipher of routine three is verified
  against a line-by-line transcription of the decompiled C.

# 0.2.8
* **MIPS PIC / GOT support**: `lw rt,imm($gp)` loads, `addiu $a1,$v0,off` with the base loaded before the match, `$gp` discovery
  (`.reginfo`, `PT_MIPS_REGINFO`, `.got`, `DT_PLTGOT`) with the `mips_gp` rule-meta override and a precise hint when it is unknown;
  `config_size_reg = "a2"` for MIPS (delay slot included); register names are validated.
* **Meta inheritance**: `$config2` / `$config_v2` inherit `config_*`, `$key_32` inherits `key_*` (so one set of lines covers a
  pattern and its variants).
* **Fixed: garbage reported as success.** A match in code with no resolvable reference fell back to reading the *instruction bytes*
  as data. That fallback now only happens for text-like matches.
* Size-recovery failures are verbose-only notes when following every reference (`ref_index = "all"`).
* `examples/kittysocks5`: the three rules (ARM v1, ARM v2, MIPS) in one file, one plugin, one family.

# 0.2.7
* **`-o` writes one directory per family** with one file per sample plus a merged family file (`<Family>.family.json`:
  overview, keys seen, all results); unmatched samples go to `_unmatched/`; `summary.json` lists everything. Results now carry `families`.
* **Fixed: entries were silently cut off.** The number of data/key combinations tried was capped at 256, so samples with more than
  256 strings lost the rest. The default is now 100000 (the warning still appears if it is ever hit).
* **Fixed: warning flood.** References that point at empty buffers (normal with `ref_index = "all"`) are now notes shown only with
  `-v`; similar warnings are collapsed to one line `(+N similar)`.
* **A sample that falls back to a raw blob now says why** (no valid PE signature / headers could not be parsed), since code
  references cannot be resolved there.

# 0.2.6
* **MIPS32** (big and little endian): `lui`+`addiu`/`ori` references; ELF byte order is detected and used for `<name>_size_at`
  (override with `<name>_size_endian`).
* Detection-only rules: `extract = "none"`; new `detected` status, `detections` in the JSON, shown in the console and summary.
* `examples/vulcan` (six architectures, one rule file, no plugin).

# 0.2.5
* **New console output**: banner, one block per matching sample, tables (offset / section / size / value), keys shown once,
  binary values previewed, summary line with counts and timing, unmatched files hidden unless `-v`,
  ASCII fallback, `--color`, `--full`, progress on stderr.
* **ARM (A32) support**: `ldr rd,=label` literal-pool references; `<name>_size_reg` / `_size_window` recover the length from
  `MOV/ADD/SUB/ORR/MOVW/MOVT` on an argument register before the next `BL` (decoded properly: register-offset loads are no
  longer mistaken for `MOV`/`ADD`).
* Several data blobs are now separate entries; only several keys/IVs for *one* blob are treated as alternatives. (Before, without
  `validate()`, binary entries could be dropped.)
* `examples/kittysocks5`.

# 0.2.4
* Numbered strings (`$data`, `$data2`, `$key1`) are variants too; a plain `$data` also runs on its own.
* A plugin that defines `extract()` always uses it (old contract), with a warning if it also has `decrypt()`.
* One-line, actionable warning when a data string has no size (was repeated per string).
* `examples/ffdroider`.

# 0.2.3
* `<name>_size_at` / `<name>_size_bytes`: read a target's length from an immediate inside the matched code (Go strings, `push len`).
* Rule-only extraction is first-class: without a plugin, values are reported under `config`; rule meta `extract` picks the strings.
* `examples/easystealer` (rule only, no plugin).

# 0.2.2
* Unreadable samples now explain themselves (Windows Errno 22 / WinError 225 hint); `-v` prints the traceback.
* `Reader` falls back to plain reads if memory-mapping fails.

# 0.2.1
* Variant groups, Stealc example.

# 0.2.0

**New plugin model** - a plugin is `decrypt(data, key, ...)`; the rule `meta` says how much to read. Old
`extract(matches, reader)` plugins still work.

Fixed
* `algorithms/3des.py` could not be imported (module names cannot start with a digit) -> `triple_des.py`.
* RIP-relative resolver only understood `lea rcx/rdx/r15`; now any register / REX combination, plus mov/movzx/movabs.
* ELF samples never had references resolved.
* `push`/`mov imm32` detection matched any `0x68` byte; now architecture-aware and validated against the image.
* `rva_to_offset` used `max(VirtualSize, RawSize)` and returned bogus offsets for memory with no file data (.bss tails).
* CLI always exited 0; failures were swallowed. Now exit codes 0/1/2, `-v` for details, errors recorded in JSON.
* JSON output decoded bytes with `errors="replace"` (corrupted binary keys); now lossless (`{"hex": ...}`).
* A crashing plugin produced no output file; now the error is recorded in the result.
* Output files from different folders could overwrite each other.
* YARA was recompiled and the plugin reloaded for every sample; now once per run. Samples are memory-mapped.
* `formats/` and `yara_handler/` were installed as top-level packages; everything now lives under `cfgx/`.

Added
* Variant groups: `$key_32`/`$data_32` and `$key_64`/`$data_64` are paired by suffix (`"variant"` in the output).
* `examples/stealc` (rule + plugin + synthetic sample generator `tests/stealc_demo.py`), `is_text()` helper.
* Raw-blob support (memory dumps, unpacked payloads), `--format`, `--arch`.
* Locate-only mode (no plugin) for debugging rules.
* Rule `meta` pass-through, multi-candidate key/data trial, `validate`/`parse` hooks, `ctx`.
* Richer `Reader` (cstrings, wide strings, ints, find, sections, address translation).
* `cfgx.crypto` one-line imports; rule directories; `-r`, `--glob`, `-o`, `--json`, `-q`.
* pytest suite with synthetic PE32/PE64/ELF64 builders.
