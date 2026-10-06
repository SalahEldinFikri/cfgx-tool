# cfgx

Malware configuration extraction without the boilerplate.

You write **a YARA rule** (where is the data / key?) and **a plugin that is just the
decryption function**. cfgx does everything in between: parses the sample (PE, ELF or
raw dump), follows the code references the rule matched, reads the bytes, tries the
candidates, calls your function, and writes structured JSON.

```
rule.yar ──► cfgx finds + reads data and keys ──► decrypt(data, key) ──► JSON
```

## The whole workflow

**rule.yar**
```yara
rule MyFamily {
  meta:
    config_size = 512                     // how many bytes of $config to read
    key_size    = 16
  strings:
    $config = { 48 8D 0D ?? ?? ?? ?? }    // lea rcx,[rip+config]   -> followed automatically
    $key    = "S3cr3tK3y0123456"          // literal in .rdata      -> used as is
  condition: all of them
}
```

**plugin.py** (the entire file)
```python
from cfgx.crypto import rc4

def decrypt(data, key):
    return rc4(data, key)
```

```
cfgx rule.yar sample.exe plugin.py
cfgx rule.yar samples/ plugin.py -r -o results/
cfgx rule.yar sample.exe                 # no plugin: just show what the rule located
```

**Full list of every rule-meta key: [docs/META_REFERENCE.md](docs/META_REFERENCE.md).**

## How the rule talks to cfgx

Every YARA string is a **target**. Its name decides where it goes:

| String | Passed to `decrypt` as |
|---|---|
| `$config` (or `$data`, `$cfg`, `$payload`, `$blob`) | `data` |
| any other, e.g. `$key`, `$iv`, `$nonce`, `$salt` | the parameter with the same name |

Your function only declares the parameters it needs: `decrypt(data)`, `decrypt(data, key)`,
`decrypt(data, key, iv)`, ... Extra optional parameters: `ctx`, `reader`, `meta`, `image`, `rule`.

Rule `meta` fine-tunes a target (replace `config` with the string name). A variant inherits the settings of its role: `$config2` and `$config_v2` use `config_*`, `$key_32` uses `key_*`, unless they have lines of their own.

| meta | meaning | default |
|---|---|---|
| `config_size` | bytes to read | up to first NUL; for non-code matches, the match length |
| `config_until` | hex terminator, e.g. `"0000"` | – |
| `config_ref` | `"auto"`, `"code"` (follow instruction), `"none"` (use the match) | `auto`: follow only if the match is in an executable section |
| `config_ref_index` | which reference if the bytes contain several (`0`, `1`, `-1`, `"all"`) | `0` |
| `config_adjust` | add N bytes to the final offset (skip a header) | `0` |
| `config_max` | cap for NUL/terminator reads | `65536` |
| `config_size_at` | take the length from the code: byte offset *inside the matched bytes* of an immediate (`mov [esp+4], 0Dh`, `push 12h` ...) | - |
| `config_size_bytes` | width of that immediate (little-endian) | `4` |
| `config_size_endian` | byte order of that immediate | taken from the ELF header (`little` for PE) |
| `config_size_mul` | multiply a length taken from the code (`size_at`/`size_reg`), e.g. `4` when the code holds a DWORD count (`mov ecx,0Ch` / `rep movsd`) | `1` |
| `config_size_tail` | after a `rep movsd` count, add the bytes of the instructions that follow: `"F3A5 66A5=2 A4=1"` = anchor, then `movsw` +2, `movsb` +1 (a DWORD count alone loses the last 1-3 bytes) | - |
| `config_resource` | the data is a **PE resource**: `"TYPE/NAME[/LANG]"`, e.g. `"RCDATA/101"`, `"10/101"`, `"BIN/*"`, `"RCDATA/#0"` | - |
| `config_section` | the data is the content of a **named section** (PE or ELF), e.g. `".cfg"` | - |
| `config_deref` | the reference points at a **pointer variable** (`mov edx, ds:off_805BD48`): read the pointer (native width and byte order) and follow it to the real data | `false` |
| `config_size_reg` | the length is the value of this argument register at the next call: **ARM** `"r2"` (`MOV/ADD R2,#n`, `MOVW`...), **MIPS** `"a2"` (`li $a2,N`, delay slot included); evaluated per reference | - |
| `config_size_window` | how many bytes after the reference to scan for that `BL` | `64` |

If a target has several candidates (e.g. three possible keys in `.rdata`), cfgx tries the
combinations and keeps the plausible result. Add `validate()` to decide exactly.

### No encryption? No plugin needed

If the data is plain (a C2 string, a mutex name ...), run cfgx with the rule only. Every string the rule
points at is read and reported under `config` (status `located`). Use rule meta `extract = "c2, key_*"` to
choose which strings count; the rest (detection-only strings) are ignored.

A rule that only *detects* the family (many marker strings, nothing to read) takes `extract = "none"`. It is listed as
`detected` and its strings are never dumped. Add `family = "Vulcan"` to every rule of one family so the per-version
rules (x86, amd64, arm, mips ...) are reported under one name. A sample that only matches detection rules gets status
`detected` (exit status 1: nothing was extracted).

```yara
rule EasyStealer {
  meta:
    extract    = "c2"
    c2_size_at = 25      // Go strings have no NUL: the length is the immediate of `mov [esp+4], 0Dh`
  strings:
    $c2 = { C7 04 24 ?? 00 00 00  E8 ?? ?? ?? ??  8D 05 ?? ?? ?? ??  89 ?? ??  C7 44 24 04 0? 00 00 00  E8 ?? ?? ?? ?? }
  ...
```
Count the bytes of your hex string to find the offset (see `examples/easystealer/rule.yar`).

### Several builds in one rule (x86 / x64, v1 / v2 ...)

Name strings `<role>_<suffix>` and cfgx pairs them by suffix, running your function once per complete pair:

```yara
$key_32  = { 6A 12 68 ?? ?? ?? ?? ... }     $key_64  = { 4C 8D 3D ?? ?? ?? ?? ... }
$data_32 = { 68 ?? ?? ?? ?? ... }           $data_64 = { 48 8D 0D ?? ?? ?? ?? ... }
```
Numbered names work too (`$data` and `$data2`, `$key1` and `$key2`). Plain names (`$key`, `$data`) run as their own variant and are shared by the others. Entries in the output carry `"variant": "32"`.
See `examples/stealc/` for a complete rule + plugin.

### Optional plugin hooks

```python
FAMILY = "MyFamily"                  # shown in the output

def validate(plaintext):             # reject wrong key/data combinations
    return plaintext.startswith(b"{")

def parse(plaintext, ctx):           # custom structure (ctx.meta, ctx.reader, ctx.rule ...)
    ...
```
Without `parse`, output is auto-detected: JSON → object, text (UTF-8/UTF-16) → string, else bytes (hex in JSON).

### Helpers for plugins

`from cfgx.crypto import is_text, rc4, xor, xor_rolling, aes_decrypt, des_decrypt, des3_decrypt, blowfish_decrypt,
chacha20_decrypt, b64decode, b32decode, b58decode, b85decode, md5, sha1, sha256, unpad_pkcs7`

`ctx.reader` (also the old `extract(matches, reader)` argument) offers `read`, `read_cstring`, `read_until`,
`read_wstring`, `u8/u16/u32/u64`, `unpack`, `find`, `find_all`, `section(".rdata")`, `va_to_offset`,
`rva_to_offset`, `offset_to_va`, `read_va`.

Old plugins that define `extract(matches, reader)` still run unchanged. If a file defines both `extract` and `decrypt`, `extract` wins (with a warning); delete it to use the short flow.

### Reference index and `.bss`

`<name>_ref_index` counts the address-loading instructions of the match in order (`lea`, `push imm32`, `mov r32,imm32`,
`mov r,[abs32]`, `ldr rd,=label`, ...). A reference whose target lives in `.bss` (state buffers, zero-initialised data) is
kept as a placeholder, so the index does **not** depend on whether a target happens to be stored in the file; the placeholder
itself is skipped when reading (verbose-only note). Example: ARM `LDR R0,=ctx` (.bss) + `LDR R1,=key` -> the key is always index 1.

### One plugin for several algorithms

A plugin can take `ctx` and pick the algorithm from the rule meta, so one file serves every rule of a family:
`ctx.notes` (append a short remark; shown with `-v`, e.g. which algorithm was picked), `ctx.meta` (all rule meta), `ctx.rule`, `ctx.variant` (e.g. `"2"` for `$config2`) and `ctx.names["data"]` (the string being
decrypted, e.g. `"config"` or `"config2"`). `decrypt` may return a dict or list (e.g. a decrypted table) instead of bytes.
See `examples/aisuru` (RC4 + a custom cipher chosen per rule or tried automatically with `algo = "auto"`, a pointer-variable key, `rep movsd` blobs with a tail).

### MIPS (PIC / GOT)

Position-independent MIPS code loads addresses through `$gp`. cfgx takes `$gp` from `.reginfo`, `PT_MIPS_REGINFO`, `.got`+0x7ff0
or `DT_PLTGOT`+0x7ff0 (in that order). If none exists (stripped ELF) the warning says so; give it in the rule meta:
`mips_gp = 0x4a0ff0` (the value of `_gp`, e.g. from IDA). Name the register that carries the length (`"a2"`), not the instruction (`"li"`).

A match in code is never read as data: when no code reference can be found and the matched bytes are not text, the
string is skipped with a warning (set `<name>_ref = "none"` if the matched bytes really are the data).

## Console output

```
cfgx 0.3.0 · rule stealc/rule.yar · plugin plugin.py · 8 files

✔ stealc_demo_x86.exe
  pe/x86 · 1.5 KB · sha256 610c1f8e…b458ec

  Stealc (StealcStealer)  3 entries
  ──────────────────────────────────────────────────────────
    key   A1b2C3d4E5f6G7h8I9  (18 B) @0x444 .rdata

    #  var  offset  section  size  value
    1  32   0x46c   .rdata     24  http://203.0.113.7
    ...
────────────────────────────────────────────────────────────
8 scanned · 2 extracted · 6 no match · 0 failed · 0 errors    0.02 s
```

Only samples that matched are shown; the summary counts the rest. `-v` also lists non-matching files, shows
informational notes and full tracebacks. `--full` stops long values being truncated, `--color auto|always|never`
(colour is off when piped or `NO_COLOR` is set), `-q` prints nothing, `--json` prints only machine-readable JSON.
The console view is a summary; `-o` / `--json` always contain everything.

## Saving results (`-o`)

`-o results\` creates one directory per **family** (the plugin's `FAMILY`, else the rule's `family` meta, else the rule name):

```
results/
  summary.json                  every sample of this run: status, families, file
  Stealc/
    Stealc.family.json          the whole family: overview of every sample, keys seen across the family, full results
    <sample>.cfgx.json          one file per sample
  _unmatched/
    <sample>.cfgx.json          samples no rule matched, or that could not be read
```

The family file is **merged** with what is already on disk (by sha256): running cfgx on new samples later extends the same
family file, and re-running a sample replaces its entry. A sample whose rule matched but produced nothing (status `failed`)
is still filed under its family. Put the same `family` in every rule (or `FAMILY` in the plugin) of one family so that
several rules (v1, v2, per-architecture ...) end up in one directory. `-o something.json` still writes one combined file.

## Output (JSON)

```json
{
  "schema": "cfgx/1",
  "sample": { "name": "...", "sha256": "...", "format": "pe", "arch": "x64" },
  "status": "success",            // success | located | no_match | failed | error
  "rules": ["MyFamily"],
  "config": [ { "rule": "...", "family": "...", "config": { ... },
                "inputs": { "data": { "offset":..,"rva":..,"va":..,"section":".rdata","via":"ref:lea" },
                            "key":  { "...": "...", "value": "...", "hex": "..." } } } ],
  "warnings": [], "errors": []
}
```
Binary values are written as `{"hex": "..."}`; nothing is lossy.

Exit status: `0` extracted something, `1` nothing extracted, `2` bad usage / bad rule / bad plugin.

## Supported inputs

* PE32 / PE32+ (via pefile), ELF 32/64 (pyelftools), **any other file as a raw blob** (memory dumps,
  unpacked payloads; use `--arch x64|x86` to enable code-reference following).
* Code references: `lea reg,[rip+x]`, `mov/movzx reg,[rip+x]`, `movabs reg,imm64` (x64);
  `push imm32`, `mov reg,imm32`, `lea reg,[abs32]` (x86); `mov r,[abs32]` / `mov eax,[moffs32]` (a variable's address, use with `_deref`); `ldr rd,=label` literal-pool loads (ARM A32); MIPS32 big/little endian: `lui`+`addiu`/`ori`, and PIC code - `lw rt,imm($gp)` GOT loads and `addiu $a1,$v0,off` where `$v0` was loaded *before* the match.
  Thumb and AArch64 are not supported yet. More architectures plug into `cfgx/refs.py`
  (`RESOLVERS`).

## Development

```
pip install -e .[dev]
pytest
```
Tests build PE/ELF files from scratch (`tests/builders.py`), no binary fixtures.

## Analyst tip: entries that share one keystream

If every entry is decrypted with a fresh stream cipher (fresh key schedule per entry, as in several IoT families), **all
entries are XORed with the same keystream**. XOR two ciphertexts and the key cancels (`C1 ^ C2 = P1 ^ P2`); with a handful of
entries and one guessed plaintext (an HTTP request line, a charset string like `ABCDEFGHIJ...`, `/proc/`, `wget,curl`) the
keystream - and so every entry - can be read without knowing the cipher. Export the raw blobs with
`cfgx rule.yar sample -o probe.json` (no plugin). It also gives an exact test for a cipher you are reimplementing:
the first bytes of your keystream must equal the recovered one.

## Troubleshooting (Windows)

* `OSError: [Errno 22] Invalid argument: '...sample...'` - Windows refused to open the file; on a malware
  folder this is normally antivirus real-time protection (WinError 225). Check with
  `python -c "open(r'C:\\path\\sample','rb').read(4)"`; if that fails too, add the folder to the Defender exclusions
  or work inside your analysis VM.
* `Failed to import ...libyara.dll` - the wrong `yara` package is installed. Run
  `pip uninstall -y yara yara-python` then `pip install yara-python`.
* Use `-v` to get full tracebacks.
