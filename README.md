# cfgx

**cfgx** is a Python-based malware configuration extraction framework designed to separate **generic malware-analysis infrastructure** from **malware-family-specific extraction logic**.

The framework handles:

* YARA scanning
* YARA match normalization
* PE parsing and metadata resolution
* Controlled access to sample bytes
* External analyst plugins
* Plugin validation
* Single-sample analysis
* Batch analysis of sample directories
* Terminal output
* JSON extraction reports

The actual malware-specific extraction logic is implemented by an external analyst-supplied Python plugin.

---

## Table of Contents

* [Overview](#overview)
* [Design Philosophy](#design-philosophy)
* [Architecture](#architecture)
* [Project Structure](#project-structure)
* [Requirements](#requirements)
* [Installation](#installation)
* [Command Usage](#command-usage)
* [Single Sample Analysis](#single-sample-analysis)
* [Folder / Batch Analysis](#folder--batch-analysis)
* [Output Directory](#output-directory)
* [How cfgx Works](#how-cfgx-works)
* [YARA Processing](#yara-processing)
* [PE Processing](#pe-processing)
* [SampleReader](#samplereader)
* [Algorithms](#algorithms)
* [Analyst Plugin](#analyst-plugin)
* [Plugin Result Contract](#plugin-result-contract)
* [Terminal Output](#terminal-output)
* [JSON Output](#json-output)
* [Error Handling](#error-handling)
* [File-by-File Explanation](#file-by-file-explanation)
* [Testing](#testing)
* [Current MVP Capabilities](#current-mvp-capabilities)
* [Design Boundaries](#design-boundaries)
* [Future Improvements](#future-improvements)
* [License](#license)

---

# Overview

Malware configuration extraction often requires several different stages:

1. Scan the malware with YARA.
2. Identify interesting matches.
3. Locate those matches inside the executable.
4. Detect and load the PE or ELF executable format.
5. Resolve executable metadata such as sections, RVAs, and virtual addresses.
6. Read additional bytes from the sample.
7. Decode, decrypt, transform, or otherwise process the data.
8. Build a configuration object.
9. Save the extracted configuration.

`cfgx` provides the common infrastructure required for these operations.

The malware-specific logic is delegated to an analyst plugin.

The framework also provides a reusable algorithm library. The plugin can use
Base16, Base32, Base45, Base58, Base64, Base85, XOR, Rolling XOR, RC4, AES,
DES, 3DES, Blowfish, ChaCha20, ChaCha20-Poly1305, MD5, SHA1, and SHA256.

The important distinction is that cfgx provides the algorithm mechanics while
the analyst plugin decides which algorithm the malware uses, which parameters
are required, and in what order multiple algorithms must be applied.

For example, a plugin can decide that:

```text
$steamid
```

is interesting and then read 16 bytes from the corresponding location:

```python
data = reader.read(match["offset"], 16)
```

The plugin can then interpret those bytes as ASCII:

```python
value = data.decode("ascii")
```

The core framework does not need to know that the value is a Steam ID.

---

# Design Philosophy

The central design principle of cfgx is:

> **The framework provides evidence and controlled access to the sample. The analyst plugin decides what that evidence means.**

The core framework is therefore malware-family agnostic.

For example, cfgx knows:

```python
{
    "rule": "VoidStealer",
    "identifier": "$steamid",
    "offset": 450664
}
```

but it does not know:

```text
$steamid = Steam ID
```

That interpretation belongs to the analyst plugin.

This makes it possible to use the same framework for different malware families.

---

# Architecture

The overall pipeline is:

```text
                    cfgx CLI
                       │
                       ▼
                Validate arguments
                       │
                       ▼
                 Load plugin
                       │
                       ▼
                  Load PE, ELF
                       │
                       ▼
                 Run YARA
                       │
                       ▼
              Normalize YARA matches
                       │
                       ▼
               Resolve PE metadata
                       │
                       ▼
                 Create Reader
                       │
                       ▼
            Analyst Plugin.extract()
                       │
                       ▼
              Validate plugin result
                       │
              ┌────────┴────────┐
              ▼                 ▼
          Terminal             JSON
           output             report
```

For a directory:

```text
                 Sample directory
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
         sample1    sample2    sample3
            │          │          │
            ▼          ▼          ▼
          YARA       YARA       YARA
            │          │          │
            ▼          ▼          ▼
         Plugin      Plugin      Plugin
            │          │          │
            └──────────┼──────────┘
                       ▼
               Combined result
                       │
                       ▼
              rule-name.json
```

---

# Project Structure

The current project structure is:

```text
cfgx commandline tool/
│
├── .vscode/
│   └── settings.json
│
├── cfgx/
│   ├── __init__.py
│   ├── cli.py
│   ├── main.py
│   ├── plugin.py
│   ├── reader.py
│   ├── models.py
│   └── algorithms/
│       ├── __init__.py
│       ├── base16.py
│       ├── base32.py
│       ├── base45.py
│       ├── base58.py
│       ├── base64.py
│       ├── base85.py
│       ├── xor.py
│       ├── xor_rolling.py
│       ├── rc4.py
│       ├── aes.py
│       ├── des.py
│       ├── 3des.py
│       ├── blowfish.py
│       ├── chacha20.py
│       └── chacha20_poly1305.py
│
├── formats/
│   ├── __init__.py
│   ├── pe.py
|   ├── elf.py
│   ├── detect.py
|
├── yara_handler/
│   ├── __init__.py
│   └── runner.py
│
├── decryptor.py
├── test_decryptor.py
├── bad_decryptor.py
├── pyproject.toml
└── README.md
```

The project also uses external sample/rule directories during testing.

---

# Requirements

cfgx currently targets:

```text
Python >= 3.12
```

Main dependencies:

```text
yara-python >= 4.5.0
pefile >= 2024.8.26
pyelftools >= 0.32
pycryptodome >= 3.20.0
```

The project was tested with:

```text
Python 3.12
yara-python 4.5.4
pefile 2024.8.26
pyelftools 0.32
pycryptodome 3.23.0
```

`pycryptodome` provides the implementations used by the AES, DES, 3DES,
Blowfish, ChaCha20, and ChaCha20-Poly1305 helpers.

---

# Installation

Clone or copy the project and install it in editable mode:

```powershell
py -3.12 -m pip install -e .
```

The editable installation registers the `cfgx` command in the Python
environment while keeping the package linked to the source tree. This is
useful during development because changes to the source are immediately
available to the installed command.

Verify the installation:

```powershell
cfgx --help
```

---

# Command Usage

The basic syntax is:

```text
cfgx <rule> <sample-or-directory> <decryptor> [--output <directory>]
```

Arguments:

| Argument    | Description                                          |
| ----------- | ---------------------------------------------------- |
| `rule`      | Path to the YARA rule                                |
| `sample`    | Path to one sample or a directory containing samples |
| `decryptor` | Path to the analyst plugin                           |
| `--output`  | Directory where extraction results are saved         |

The output directory defaults to:

```text
output/
```

---

# Single Sample Analysis

Example:

```powershell
cfgx D:\rules\voidstealer.yar D:\samples\sample D:\plugins\voidstealer.py
```

With a custom output directory:

```powershell
cfgx D:\rules\voidstealer.yar D:\samples\sample D:\plugins\voidstealer.py --output results
```

The framework processes the sample and sends the YARA/PE information to the analyst plugin.

---

# Folder / Batch Analysis

cfgx can also process a directory containing multiple samples.

Example:

```text
test_samples/
├── sample
└── sample2
```

Run:

```powershell
cfgx D:\rules\voidstealer.yar D:\samples\test_samples D:\plugins\voidstealer.py --output results
```

cfgx processes each file independently:

```text
sample
    ↓
YARA
    ↓
PE
    ↓
plugin
    ↓
result

sample2
    ↓
YARA
    ↓
PE
    ↓
plugin
    ↓
result
```

The results are then combined into a single JSON file based on the YARA rule name.

For:

```text
voidstealer.yar
```

the output becomes:

```text
results/
└── voidstealer.json
```

This means multiple samples belonging to the same malware/rule can be represented in one extraction report.

---

# Output Directory

The output directory can be specified using:

```text
--output
```

Example:

```powershell
cfgx rule.yar samples decryptor.py --output D:\analysis\results
```

If the directory does not exist, cfgx creates it.

Default:

```text
output/
```

Custom:

```text
results/
```

---

# How cfgx Works

The framework consists of several stages. Every sample passes through the
same pipeline. The framework handles the generic stages, while the analyst
plugin owns the malware-family-specific extraction step.

## 1. CLI validation

The CLI verifies that:

* the YARA rule exists
* the YARA rule is a file
* the sample path exists
* the sample path is either a file or directory
* the analyst plugin exists
* the analyst plugin is a Python file

---

## 2. Analyst plugin loading

The external plugin is dynamically loaded by cfgx.

The plugin is not hard-coded into the framework. This allows an analyst to
create a malware-family-specific extractor without modifying cfgx itself.

The framework verifies that the plugin exposes a callable:

```python
extract(matches, reader)
```

function before extraction begins.

---

## 3. PE / ELF loading

cfgx detects the executable format and loads the appropriate parser.

For PE samples, cfgx uses `pefile` to resolve:

```text
file offset
    ↓
PE section
    ↓
RVA
    ↓
VA
```

For ELF samples, cfgx uses `pyelftools` to resolve:

```text
file offset
    ↓
ELF section
    ↓
VA
```

This allows the same plugin architecture to work with both Windows PE and
Linux/IoT ELF samples.

---

## 4. YARA scanning

The YARA rule is compiled and executed against the sample.

Every individual YARA string occurrence becomes a separate normalized match.
If `$steamid` occurs three times, cfgx produces three independent match
objects.

---

## 5. Match normalization

Raw YARA results are converted into a stable generic structure:

```python
{
    "rule": "...",
    "identifier": "$config",
    "offset": 450664
}
```

This gives the analyst plugin a predictable interface.

---

## 6. Executable metadata resolution

For PE files, cfgx enriches matches with:

```text
section
rva
va
```

For ELF files, cfgx can provide:

```text
section
va
```

The metadata is useful when cross-referencing a YARA match with IDA,
Ghidra, a debugger, or reverse-engineering notes.

---

## 7. SampleReader

The framework creates a `SampleReader`.

The plugin accesses sample bytes only through:

```python
reader.read(offset, size)
```

The plugin does not receive the sample path or raw file handle.

This keeps file access under the framework's reader abstraction.

---

## 8. Analyst extraction

The framework calls:

```python
extract(matches, reader)
```

This is the malware-family-specific step.

The plugin decides:

* which matches are interesting
* which offsets should be read
* how many bytes should be read
* whether the data is encoded, encrypted, or transformed
* which cfgx algorithm is required
* which key, IV, nonce, or other parameters are required
* the order of multiple algorithms
* how the resulting bytes should be interpreted
* what configuration structure should be returned

For example:

```text
YARA match
    ↓
reader.read()
    ↓
Base64 decode
    ↓
RC4
    ↓
plaintext
    ↓
configuration
```

The framework does not automatically choose this sequence. The analyst
determines it from reverse engineering of the malware.

---

## 9. Result validation

cfgx validates the result returned by the plugin.

The result must be a dictionary containing:

```text
status
config
```

`status` must be a string.

`config` is intentionally unrestricted so each malware family can expose the
configuration structure that makes sense for that family.

---

## 10. Output

The result is shown in the terminal and saved as JSON.

For directory analysis, cfgx waits for the samples to be processed and then
writes the combined rule-level report.

---

# YARA Processing

YARA processing is implemented in:

```text
yara_handler/runner.py
```

The runner converts native YARA results into a generic match structure.

The generic match contains:

```python
{
    "rule": str,
    "identifier": str,
    "offset": int
}
```

For example:

```python
{
    "rule": "VoidStealer",
    "identifier": "$steamid",
    "offset": 450664
}
```

If a YARA string occurs multiple times, every occurrence becomes a separate match.

For example:

```text
$steamid → offset 450664
$steamid → offset 450688
$steamid → offset 450712
```

becomes three independent match objects.

This is intentional.

The framework treats YARA matches as **evidence/anchors**, not automatically as configuration data.

---

# PE Processing

PE functionality is implemented in:

```text
formats/pe.py
```

The module provides several operations.

## `load_pe()`

Loads the sample as a PE:

```python
pe = load_pe(sample_path)
```

---

## `offset_to_rva()`

Converts a raw file offset into an RVA.

Conceptually:

```text
file offset
     ↓
PE section
     ↓
RVA
```

---

## `rva_to_va()`

Converts an RVA to a virtual address using the PE image base.

Conceptually:

```text
RVA + ImageBase = VA
```

---

## `get_section_for_offset()`

Determines which PE section contains a file offset.

For example:

```text
452384
   ↓
.rdata
```

---

## `resolve_offset()`

Combines the PE information and returns:

```python
{
    "section": ".rdata",
    "rva": 456992,
    "va": 5369166112
}
```

This metadata is added to the YARA match when available.

---

# SampleReader

The sample reader is implemented in:

```text
cfgx/reader.py
```

Its primary API is:

```python
reader.read(offset, size)
```

Example:

```python
data = reader.read(450664, 16)
```

The result is raw bytes:

```python
b"7656119987836894"
```

The plugin can then interpret those bytes.

For example:

```python
value = data.decode("ascii")
```

produces:

```text
7656119987836894
```

---

## Reader Validation

The reader validates offsets and sizes.

Negative offsets are rejected:

```python
reader.read(-1, 16)
```

results in:

```text
ValueError: Offset cannot be negative
```

Negative sizes are also rejected.

Reading past the end of the file is handled safely by Python's file reading behavior.

For example, if fewer bytes remain than requested, the reader returns the available bytes.

If the requested offset is already beyond EOF:

```python
b""
```

is returned.

---

# Algorithms

cfgx includes a reusable algorithm library for configuration extraction.

The library is intentionally separate from malware-family-specific plugins.
The framework provides the mechanics; the analyst plugin decides how those
mechanics reproduce the malware's implementation.

## Algorithm Categories

```text
Encodings
    Base16
    Base32
    Base45
    Base58
    Base64
    Base85

Transforms
    XOR
    Single-byte XOR
    Rolling XOR

Ciphers
    RC4
    AES
    DES
    3DES
    Blowfish
    ChaCha20
    ChaCha20-Poly1305

Hashes
    MD5
    SHA1
    SHA256
```

## Encodings

### Base16

Base16 represents bytes as hexadecimal characters.

```text
48 65 6c 6c 6f
      ↓
48656c6c6f
```

The plugin can decode the value back into raw bytes before passing those bytes
to another processing stage.

### Base32

Base32 represents binary data using a restricted text alphabet.

```text
Base32 text
    ↓
Base32 decode
    ↓
raw bytes
```

### Base45

Base45 is a byte-to-text encoding. cfgx provides encoding and decoding with
validation of malformed input.

### Base58

Base58 uses a reduced alphabet and can be useful when malware stores binary
data or identifiers in a printable representation.

### Base64

Base64 is commonly encountered during malware configuration extraction.

Example:

```python
from cfgx.algorithms.base64 import decode as base64_decode

decoded = base64_decode(encoded)
```

The result is raw bytes and can be passed to another algorithm.

### Base85

Base85 provides another binary-to-text encoding. cfgx also provides ASCII85
helpers.

---

## Transforms

### XOR

The repeating-key XOR helper applies a key repeatedly across the input.

```python
from cfgx.algorithms.xor import xor

plaintext = xor(data, key)
```

XOR is reversible using the same key:

```text
ciphertext XOR key = plaintext
plaintext  XOR key = ciphertext
```

### Single-byte XOR

Single-byte XOR uses one byte as the key.

```python
from cfgx.algorithms.xor import xor_single_byte

plaintext = xor_single_byte(data, 0x5A)
```

### Rolling XOR

Rolling XOR changes the key as processing continues.

```text
initial key
    ↓
XOR byte
    ↓
increment key
    ↓
XOR next byte
    ↓
...
```

Example:

```python
from cfgx.algorithms.xor_rolling import rolling_xor

plaintext = rolling_xor(data, key, increment)
```

The analyst must determine the initial key and increment from the malware.

---

## Ciphers

### RC4

RC4 is a stream cipher frequently encountered in malware.

Example:

```python
from cfgx.algorithms.rc4 import rc4

plaintext = rc4(ciphertext, key)
```

A malware may use multiple processing stages:

```python
from cfgx.algorithms.base64 import decode as base64_decode
from cfgx.algorithms.rc4 import rc4

decoded = base64_decode(encoded)
plaintext = rc4(decoded, "74934157919546113795")
```

The important part is that the plugin knows the malware's actual sequence and
key. cfgx only provides the reusable implementations.

### AES

cfgx supports:

```text
ECB
CBC
CTR
```

with AES key sizes of:

```text
16 bytes
24 bytes
32 bytes
```

CBC uses a 16-byte IV.

The analyst must identify the correct mode, key, and IV/parameters from the
malware.

### DES

DES is a block cipher with an 8-byte block size.

cfgx supports:

```text
ECB
CBC
```

with an 8-byte key. CBC requires an 8-byte IV.

### 3DES

3DES supports:

```text
ECB
CBC
```

with supported 16-byte or 24-byte keys. CBC uses an 8-byte IV.

### Blowfish

Blowfish is a symmetric block cipher with a variable-length key.

cfgx supports:

```text
ECB
CBC
```

with supported key sizes from 4 through 56 bytes. CBC uses an 8-byte IV.

### ChaCha20

ChaCha20 is a stream cipher. The plugin supplies the key and nonce required
by the malware's implementation.

```text
ciphertext
    +
key
    +
nonce
    ↓
ChaCha20
    ↓
plaintext
```

### ChaCha20-Poly1305

ChaCha20-Poly1305 combines encryption with authentication.

Depending on the malware's data format, the plugin may need:

```text
key
nonce
ciphertext
authentication tag
associated data
```

Authenticated decryption requires the authentication information to validate.

---

## Hashes

Hashes are different from encryption. They produce digests and are not
normally reversible.

cfgx provides:

```text
MD5
SHA1
SHA256
```

They can be used by plugins to reproduce or verify malware-derived values.

### MD5

```python
from cfgx.algorithms.md5 import hexdigest

value = hexdigest(data)
```

### SHA1

```python
from cfgx.algorithms.sha1 import hexdigest

value = hexdigest(data)
```

### SHA256

```python
from cfgx.algorithms.sha256 import hexdigest

value = hexdigest(data)
```

For example, SHA256 of `Hello World` is:

```text
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
```

---

## Using Algorithms in the Analyst Plugin

The plugin imports only the algorithms it needs.

For example:

```python
from cfgx.algorithms.base64 import decode as base64_decode
from cfgx.algorithms.rc4 import rc4
```

Then the plugin can build the malware-specific processing chain:

```python
def extract(matches, reader):
    results = []

    for match in matches:
        if match["identifier"] != "$config":
            continue

        encoded = reader.read(match["offset"], 128)

        decoded = base64_decode(encoded)
        plaintext = rc4(decoded, "key")

        results.append({
            "value": plaintext
        })

    return {
        "status": "success",
        "config": results
    }
```

The framework knows how to perform Base64 decoding and RC4, but only the
plugin knows:

```text
which match matters
which bytes contain the data
which key is correct
which algorithm is correct
which order to use
how to interpret the result
```

## Multi-Stage Algorithms

Malware configurations can contain several processing stages.

For example:

```text
YARA match
    ↓
SampleReader
    ↓
Base64 decode
    ↓
XOR
    ↓
RC4
    ↓
plaintext
    ↓
configuration parser
```

The plugin can represent that sequence directly:

```python
encoded = reader.read(match["offset"], size)

stage1 = base64_decode(encoded)
stage2 = xor(stage1, xor_key)
stage3 = rc4(stage2, rc4_key)
```

The order matters. If reverse engineering shows:

```text
Base64 → RC4
```

the extractor must perform:

```text
Base64 decode → RC4
```

The framework does not automatically try every available algorithm.

That would mix malware-family-specific reasoning into the generic framework and
could produce false positives.

---

# Analyst Plugin

The analyst plugin is the most important extension point in cfgx.

The plugin is an external Python file.

The framework calls:

```python
extract(matches, reader)
```

The plugin receives:

### `matches`

A list of normalized YARA/PE matches.

Example:

```python
[
    {
        "rule": "VoidStealer",
        "identifier": "$steamid",
        "offset": 450664,
        "section": ".rdata",
        "rva": 456992,
        "va": 5369166112
    }
]
```

### `reader`

A controlled reader object.

Example:

```python
data = reader.read(450664, 16)
```

The plugin does not receive:

```text
sample_path
```

or:

```text
file handle
```

This keeps sample access under the framework's reader abstraction.

---

# Example Analyst Plugin

A minimal plugin looks like:

```python
def extract(matches, reader):
    results = []

    for match in matches:
        if match["identifier"] != "$steamid":
            continue

        data = reader.read(match["offset"], 16)

        results.append({
            "identifier": match["identifier"],
            "offset": match["offset"],
            "value": data.decode("ascii"),
            "data_length": len(data)
        })

    return {
        "status": "success",
        "config": results
    }
```

This example demonstrates several important properties.

The plugin:

1. receives all matches
2. selects only `$steamid`
3. requests bytes through the reader
4. interprets those bytes as ASCII
5. creates its own configuration structure
6. returns the generic result contract

The cfgx core does not know what `$steamid` means.

---

# Plugin Result Contract

Every successful plugin execution must return a dictionary containing:

```python
{
    "status": "...",
    "config": ...
}
```

For example:

```python
{
    "status": "success",
    "config": {
        "c2": "example.com",
        "port": 443
    }
}
```

Or:

```python
{
    "status": "not_found",
    "config": []
}
```

Or:

```python
{
    "status": "decryption_failed",
    "config": {}
}
```

## Status

`status` must be a string.

cfgx does **not** restrict the value to a fixed list.

Therefore the analyst may use:

```text
success
not_found
partial
decryption_failed
invalid_config
anything_else
```

as appropriate.

The framework does not interpret the meaning of the string.

## Config

`config` is intentionally analyst-defined.

It can be:

```python
[]
```

or:

```python
{}
```

or:

```python
{
    "c2": "example.com"
}
```

or:

```python
[
    {"host": "example.com"},
    {"port": 443}
]
```

The core does not impose a malware-specific configuration schema.

---

# Terminal Output

cfgx displays the extraction status:

```text
Extraction status: success
```

and the extracted configuration:

```text
Extraction result:
[
    {
        "identifier": "$steamid",
        "offset": 450664,
        "value": "7656119987836894"
    }
]
```

For multiple samples, each sample is displayed separately during processing.

---

# JSON Output

cfgx saves the complete analyst result rather than only the configuration.

Example:

```json
{
    "status": "success",
    "config": [
        {
            "identifier": "$steamid",
            "offset": 450664,
            "value": "7656119987836894",
            "data_length": 16
        }
    ]
}
```

When processing a directory, results from multiple samples are combined into one file named after the YARA rule.

For example:

```text
voidstealer.yar
```

produces:

```text
voidstealer.json
```

A combined result can contain sample-specific context such as:

```json
[
    {
        "sample": "sample",
        "result": {
            "status": "success",
            "config": []
        }
    },
    {
        "sample": "sample2",
        "result": {
            "status": "success",
            "config": []
        }
    }
]
```

This allows one malware rule to produce one consolidated extraction report.

---

# Error Handling

cfgx validates several parts of the extraction pipeline.

## Missing plugin

If the plugin doesn't define:

```python
extract()
```

cfgx reports:

```text
[ERROR] Analyst plugin must define extract(matches, reader)
```

---

## Non-callable extract

If:

```python
extract = "not a function"
```

cfgx reports:

```text
[ERROR] Analyst plugin 'extract' must be callable
```

---

## Plugin exception

If the analyst plugin raises:

```python
RuntimeError("Analyst extraction failed")
```

the CLI reports:

```text
[ERROR] Analyst extraction failed
```

---

## Missing config

If the plugin returns:

```python
{
    "status": "success"
}
```

cfgx rejects it:

```text
[ERROR] Result must contain 'config'
```

---

## Invalid status

If the plugin returns:

```python
{
    "status": 123,
    "config": []
}
```

cfgx rejects it:

```text
[ERROR] Result 'status' must be a string
```

---

# File-by-File Explanation

## `cfgx/__init__.py`

Package initialization file for the main `cfgx` Python package.

It allows the directory to function as the framework's Python package.

---

## `cfgx/cli.py`

The command-line interface.

Responsibilities include:

* parsing command-line arguments
* validating paths
* accepting either a sample file or directory
* loading the analyst plugin through the framework
* processing individual samples
* processing directories
* displaying extraction results
* creating the output directory
* saving JSON results

The CLI is the user-facing layer of cfgx.

It does not perform malware-specific extraction itself.

---

## `cfgx/main.py`

The main orchestration layer.

This module coordinates the extraction pipeline.

Its `process_sample()` function performs the sequence:

```text
load analyst plugin
       ↓
load PE
       ↓
run YARA
       ↓
resolve PE metadata
       ↓
create SampleReader
       ↓
call plugin
       ↓
validate result
       ↓
return result
```

The important design decision is that `main.py` does not contain malware-family-specific extraction logic.

It simply connects the framework components together.

---

## `cfgx/plugin.py`

Responsible for external analyst plugin handling.

It performs two main jobs:

### Plugin loading

The plugin is dynamically loaded from a Python file.

### Result validation

The plugin's result is checked to ensure it contains:

```text
status
config
```

and that:

```text
status
```

is a string.

This module therefore defines the boundary between cfgx and analyst-developed plugins.

---

## `cfgx/reader.py`

Provides controlled access to sample bytes.

The main abstraction is:

```python
SampleReader
```

with:

```python
reader.read(offset, size)
```

The reader validates offsets and sizes before accessing the sample.

This prevents the analyst plugin from needing direct file-handling logic.

---

## `cfgx/models.py`

Contains the generic type definitions used by the framework.

The main models are:

### `Match`

Represents a normalized YARA match:

```python
class Match(TypedDict):
    rule: str
    identifier: str
    offset: int
```

### `PEMetadata`

Represents optional PE information:

```python
class PEMetadata(TypedDict):
    section: str
    rva: int
    va: int
```

### `PEMatch`

Represents a YARA match enriched with PE information.

It combines:

```text
Match
+
PEMetadata
```

### `ExtractionResult`

Represents the generic plugin result:

```python
class ExtractionResult(TypedDict):
    status: str
    config: object
```

The `config` field intentionally uses a generic object type because the analyst controls its structure.

---

## `formats/__init__.py`

Initializes the `formats` package.

The package contains executable-format-specific parsing functionality for PE
and ELF samples.

---

## `formats/pe.py`

PE-specific functionality.

It handles:

* loading PE files
* file-offset to RVA conversion
* RVA to virtual-address conversion
* locating PE sections
* enriching YARA matches with PE metadata

This keeps PE parsing out of the core orchestration code.

---

## `formats/elf.py`

ELF-specific functionality.

It handles:

* loading ELF files
* identifying ELF sections
* file-offset to virtual-address conversion
* resolving ELF virtual addresses

This provides the equivalent format support for Linux and other ELF-based
samples.

---

## `yara_handler/__init__.py`

Initializes the YARA handler package.

---

## `yara_handler/runner.py`

Runs YARA rules against samples.

Its responsibilities are:

* compiling the YARA rule
* scanning the sample
* iterating through YARA matches
* iterating through string instances
* producing normalized `Match` objects

The result is a flat list of match instances.

---

## `test_decryptor.py`

This is the current analyst/test plugin used to demonstrate the plugin API.

It has been used to verify:

* match selection
* reader access
* variable-size reads
* multiple reads
* byte decoding
* result generation
* status handling

It is not part of the generic cfgx core.

It represents the kind of external plugin an analyst can provide.

---

## `bad_decryptor.py`

A negative-testing plugin used to test framework validation and error handling.

It has been used to test conditions such as:

* missing `extract()`
* non-callable `extract`
* extraction exceptions
* invalid result structures

It is a development/testing artifact rather than part of the framework's normal runtime.

---

## `cfgx/algorithms/`

The reusable algorithm library.

It contains independent implementations for:

```text
Base16, Base32, Base45, Base58, Base64, Base85
XOR, single-byte XOR, Rolling XOR
RC4
AES, DES, 3DES, Blowfish
ChaCha20, ChaCha20-Poly1305
MD5, SHA1, SHA256
```

Each module is intended to be imported only when the analyst plugin needs it.
The algorithm library contains generic mechanics; malware-family-specific
selection and parameter recovery remain in the analyst plugin.

---

## `decryptor.py`

A development/experimental extraction-related file used during the earlier stages of the project.

The current plugin architecture uses the external plugin interface:

```python
extract(matches, reader)
```

rather than the earlier experimental plugin design.

---

## `pyproject.toml`

Defines the Python package and build configuration.

The project currently specifies:

```toml
[project]
name = "cfgx"
version = "0.1.0"
description = "A malware configuration extraction framework"
requires-python = ">=3.12"
```

Dependencies include:

```text
yara-python
pefile
pyelftools
pycryptodome
```

`pycryptodome` supplies the cryptographic primitives used by the supported
cipher helpers.

The CLI entry point is:

```toml
[project.scripts]
cfgx = "cfgx.cli:main"
```

This is what makes the following command possible:

```powershell
cfgx ...
```

The package discovery configuration includes:

```text
cfgx
formats
yara_handler
```

---

# Testing

The framework has been tested incrementally during development.

## YARA testing

A VoidStealer YARA rule successfully produced 10 individual match instances.

Examples included:

```text
$m2
$m3
$m4
$s1
$s9
$s16
$steamid
```

with multiple occurrences represented separately.

---

## PE testing

The PE processing successfully resolved file offsets into:

```text
section
RVA
VA
```

For example:

```text
offset: 452384
section: .rdata
```

---

## Reader testing

The reader has been tested with:

* normal reads
* different read sizes
* multiple independent reads
* negative offsets
* negative sizes
* reads beyond EOF

---

## Plugin testing

The plugin system has been tested with:

* valid plugins
* missing `extract()`
* non-callable `extract`
* plugin exceptions
* missing `config`
* invalid `status`
* custom status strings
* empty extraction results

---

## Algorithm testing

The reusable algorithm library has been tested independently from the malware
extraction pipeline.

The test suite covers:

```text
Base16
Base32
Base45
Base58
Base64
Base85
RC4
XOR repeating key
XOR single byte
Rolling XOR
MD5
SHA1
SHA256
AES
DES
3DES
Blowfish
ChaCha20
ChaCha20-Poly1305
```

This separates algorithm correctness from malware-family-specific extraction
logic.

---

## Batch testing

Multiple samples have been processed from a directory.

Example:

```text
sample
    10 YARA matches
    3 extracted values

sample2
    5 YARA matches
    1 extracted value
```

The results were successfully combined into a rule-level JSON output.

---

# Current MVP Capabilities

The current MVP provides:

### CLI

* command-line interface
* argument parsing
* path validation
* single-file analysis
* directory analysis
* configurable output directory

### YARA

* YARA rule compilation
* sample scanning
* individual string-instance extraction
* normalized match representation

### PE / ELF

* PE loading
* ELF loading
* section identification
* RVA resolution
* virtual address resolution
* file-offset address resolution

### Reader

* controlled byte reads
* arbitrary read sizes
* multiple reads
* offset validation
* size validation
* safe EOF behavior

### Plugins

* external plugin loading
* analyst-controlled match selection
* analyst-controlled byte interpretation
* analyst-controlled extraction logic
* analyst-controlled algorithm selection and chaining
* generic result contract

### Algorithms

* Base16 / Base32 / Base45 / Base58 / Base64 / Base85
* XOR / single-byte XOR / Rolling XOR
* RC4
* AES ECB / CBC / CTR
* DES / 3DES
* Blowfish
* ChaCha20 / ChaCha20-Poly1305
* MD5 / SHA1 / SHA256

### Output

* extraction status
* terminal configuration output
* JSON output
* combined batch results

---

# Design Boundaries

The following responsibilities intentionally belong to the **core framework**:

```text
CLI
YARA
PE / ELF parsing
match normalization
sample reading
algorithm implementations
plugin loading
result validation
output
```

The following responsibilities intentionally belong to the **analyst plugin**:

```text
malware-family logic
match selection
byte interpretation
algorithm selection
algorithm order / chaining
key / IV / nonce selection
decryption
decoding
configuration identification
configuration schema
status meaning
```

For example, cfgx does not know that:

```text
$steamid
```

represents a Steam ID.

The plugin decides that.

Similarly, cfgx does not know whether a configuration is:

```python
{
    "c2": "...",
    "port": 443
}
```

or:

```python
[
    {"host": "..."},
    {"key": "..."}
]
```

That is intentionally left to the analyst.

---

# Future Improvements

The current MVP is complete enough to serve as the foundation for additional features.

Possible future improvements include:

* richer CLI formatting
* structured logging
* verbose/debug mode
* multiple YARA rule support
* plugin metadata
* plugin discovery
* plugin versioning
* standardized extraction timestamps
* improved JSON schema/versioning
* additional executable format support
* additional algorithm implementations
* improved batch-processing controls
* configuration deduplication
* extraction statistics
* unit-test suite
* integration-test suite
* packaging and release automation

These are enhancements rather than requirements for the current MVP.

---

# Core Philosophy

The most important property of cfgx is the separation between **framework functionality** and **analyst knowledge**.

The framework provides:

```text
             cfgx
              │
       ┌──────┴──────┐
       │             │
    Evidence       Access
       │             │
     YARA           Reader
       │             │
       └──────┬──────┘
              │
              ▼
       Analyst Plugin
              │
              ▼
       Interpretation
              │
              ▼
        Configuration
```

This allows the same cfgx installation to support different malware families without modifying the framework itself.

An analyst can simply provide a different plugin:

```text
voidstealer.py
redline.py
lumma.py
stealc.py
custom_family.py
```

while the core extraction pipeline remains the same.

---

# Example

A complete invocation might look like:

```powershell
cfgx D:\rules\voidstealer.yar D:\samples\voidstealer D:\plugins\voidstealer.py --output D:\results
```

The framework then:

```text
1. Validates the rule
2. Validates the sample directory
3. Loads the analyst plugin
4. Processes every sample
5. Runs YARA
6. Normalizes matches
7. Resolves PE metadata
8. Creates a SampleReader
9. Calls extract(matches, reader)
10. Validates the result
11. Displays the extraction
12. Combines results from all samples
13. Writes the final JSON report
```

Result:

```text
D:\results\
└── voidstealer.json
```

---

# Version

Current MVP:

```text
cfgx 0.1.0
```

Python requirement:

```text
Python >= 3.12
```

---

# License

## License

**cfgx** is released under the **MaTriX Non-Commercial License (MNCL) v1.0**.

Copyright (c) 2026 SalahEldin Kamil
All Rights Reserved.

The license permits use, copying, study, modification, and redistribution of the software for **non-commercial purposes**, subject to the terms of the license. Commercial use requires a separate written commercial license from the copyright holder.
Attribution and the original copyright notice must be retained in copies and derivative works.

For the complete terms and conditions, see the [`LICENSE`](LICENSE) file included in this repository.

For commercial licensing inquiries, contact the copyright holder.

