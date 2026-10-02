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

## How the rule talks to cfgx

Every YARA string is a **target**. Its name decides where it goes:

| String | Passed to `decrypt` as |
|---|---|
| `$config` (or `$data`, `$cfg`, `$payload`, `$blob`) | `data` |
| any other, e.g. `$key`, `$iv`, `$nonce`, `$salt` | the parameter with the same name |

Your function only declares the parameters it needs: `decrypt(data)`, `decrypt(data, key)`,
`decrypt(data, key, iv)`, ... Extra optional parameters: `ctx`, `reader`, `meta`, `image`, `rule`.

Rule `meta` fine-tunes a target (replace `config` with the string name):

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
| `config_size_reg` | **ARM**: the length is the value of this register at the next `BL` (`MOV R2,#n` / `ADD R2,R2,#n` / `MOVW`...), e.g. `"r2"`; evaluated per reference | - |
| `config_size_window` | how many bytes after the reference to scan for that `BL` | `64` |

If a target has several candidates (e.g. three possible keys in `.rdata`), cfgx tries the
combinations and keeps the plausible result. Add `validate()` to decide exactly.

### No encryption? No plugin needed

If the data is plain (a C2 string, a mutex name ...), run cfgx with the rule only. Every string the rule
points at is read and reported under `config` (status `located`). Use rule meta `extract = "c2, key_*"` to
choose which strings count; the rest (detection-only strings) are ignored.

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

## Console output

```
cfgx 0.2.5 · rule stealc/rule.yar · plugin plugin.py · 8 files

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
  `push imm32`, `mov reg,imm32`, `lea reg,[abs32]` (x86); `ldr rd,=label` literal-pool loads (ARM A32).
  Thumb and AArch64 are not supported yet. More architectures plug into `cfgx/refs.py`
  (`RESOLVERS`).

## Development

```
pip install -e .[dev]
pytest
```
Tests build PE/ELF files from scratch (`tests/builders.py`), no binary fixtures.

## Troubleshooting (Windows)

* `OSError: [Errno 22] Invalid argument: '...sample...'` - Windows refused to open the file; on a malware
  folder this is normally antivirus real-time protection (WinError 225). Check with
  `python -c "open(r'C:\\path\\sample','rb').read(4)"`; if that fails too, add the folder to the Defender exclusions
  or work inside your analysis VM.
* `Failed to import ...libyara.dll` - the wrong `yara` package is installed. Run
  `pip uninstall -y yara yara-python` then `pip install yara-python`.
* Use `-v` to get full tracebacks.
