"""The engine: rule hits -> located data/keys -> plugin -> structured result.

How a rule describes what to extract (all optional, see README):

    rule MyFamily {
      meta:
        config_size = 512          // bytes to read for $config   (default: up to NUL)
        key_size    = 16           // bytes to read for $key
        key_ref     = "none"       // "auto" (default) | "code" | "none"
      strings:
        $config = { 48 8D 0D ?? ?? ?? ?? }     // lea rcx,[rip+config]
        $key    = "S3cretKey"                   // literal in .rdata
      condition: all of them
    }

Every YARA string becomes a *target*.  ``$config`` (or ``$data``) is passed to
``decrypt`` as ``data``; every other string is passed by its own name.
"""
from __future__ import annotations

import fnmatch
import hashlib
import itertools
import re
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .errors import CfgxError, os_hint
from .formats import load_image
from .formats.base import Image
from .output import auto_parse, decode_text, score_plaintext
from .plugin import Plugin, load_plugin, param_names
from .reader import Reader
from .consts import recover_register
from .refs import find_references
from .resources import describe as describe_resources, select as select_resources
from .yara_scan import RuleHit, Scanner

SCHEMA = "cfgx/1"
DATA_NAMES = ("config", "data", "cfg", "payload", "blob")
MAX_VALUE_IN_OUTPUT = 1024
_NOTE = "[note]"
SPECIALS = ("ctx", "reader", "meta", "image", "rule")


@dataclass
class Target:
    name: str
    offset: int
    size: int
    data: bytes
    via: str                      # "match" or "ref:<instruction>"
    match_offset: int
    rva: Optional[int]
    va: Optional[int]
    section: Optional[str]

    def describe(self, include_value: bool) -> dict:
        d = {
            "offset": self.offset,
            "rva": self.rva,
            "va": self.va,
            "section": self.section,
            "size": self.size,
            "via": self.via,
            "match_offset": self.match_offset,
        }
        if len(self.data) > MAX_VALUE_IN_OUTPUT:
            d["truncated"] = True
        if include_value:
            d["value"] = self.data[:MAX_VALUE_IN_OUTPUT]
            d["hex"] = self.data[:MAX_VALUE_IN_OUTPUT].hex()
        return d


@dataclass
class Context:
    """Optional second argument for plugins: ``def decrypt(data, key, ctx)``."""

    rule: str
    meta: Dict[str, Any]
    tags: List[str]
    sample: Path
    reader: Reader
    image: Image
    targets: Dict[str, List[Target]]
    warnings: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)    # a plugin may append short remarks (shown with -v)
    variant: Optional[str] = None                     # variant label of the entry being decrypted
    names: Dict[str, str] = field(default_factory=dict)   # decrypt parameter -> rule string (e.g. data -> "config2")


def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Engine:
    def __init__(self, rules, plugin=None, force_format=None, arch=None,
                 max_combinations=100_000, debug=False):
        self.debug = debug
        self.scanner = Scanner(rules)                      # compiled once
        self.plugin: Optional[Plugin] = load_plugin(plugin) if plugin else None  # loaded once
        self.force_format = force_format if force_format not in (None, "auto") else None
        self.arch = arch
        self.max_combinations = max_combinations

    # ------------------------------------------------------------------ public
    def run(self, sample) -> dict:
        sample = Path(sample)
        result: Dict[str, Any] = {
            "schema": SCHEMA,
            "tool": f"cfgx {__version__}",
            "sample": {"path": str(sample), "name": sample.name},
            "status": "error",
            "rules": [],
            "families": [],
            "detections": [],
            "config": [],
            "warnings": [],
            "errors": [],
        }
        reader = None
        image = None
        try:
            image = load_image(sample, self.force_format, self.arch)
            if self.arch and image.arch is None:
                image.arch = self.arch
            result["warnings"].extend(image.notes)
            if self.debug and image.resources:
                result["sample"]["resources"] = [
                    {k: r[k] for k in ("type", "name", "lang", "size")} for r in image.resources[:200]]
            reader = Reader(sample, image)
            result["sample"].update(
                size=reader.size, sha256=_sha256(sample), **image.describe()
            )

            if self.plugin is not None and self.plugin.ambiguous:
                result["warnings"].append(
                    f"plugin {self.plugin.path.name} defines both extract() and decrypt(): extract() is used "
                    f"(old contract). Remove extract() to use the short decrypt-only flow."
                )
            hits = self.scanner.scan(sample)
            result["rules"] = [h.rule for h in hits]
            if not hits:
                result["status"] = "no_match"
                return result

            for hit in hits:
                try:
                    self._process_hit(hit, sample, reader, image, result)
                except Exception as e:                      # one bad rule must not kill the rest
                    result["errors"].append(f"{hit.rule}: {type(e).__name__}: {e}")

            if result["config"]:
                result["status"] = "success" if self.plugin else "located"
            elif result["detections"] and not result["errors"]:
                result["status"] = "detected"
            else:
                result["status"] = "failed"
        except CfgxError as e:
            result["errors"].append(str(e))
        except Exception as e:
            result["errors"].append(f"{type(e).__name__}: {e}")
            hint = os_hint(e)
            if hint:
                result["errors"].append(hint)
            if self.debug:
                result["traceback"] = traceback.format_exc()
        finally:
            if reader is not None:
                reader.close()
            if image is not None:                           # releases PE/ELF file handles
                image.close()
        return result

    # --------------------------------------------------------------- targets
    def _read_target(self, name, inst, via, start, hit, reader, warnings, ref=None,
                     quiet_empty=False) -> Optional[Target]:
        meta = hit.meta
        size = self._m(hit, name, "size")
        until = self._m(hit, name, "until")
        cap = int(self._m(hit, name, "max", 65536))

        size_at = self._m(hit, name, "size_at")
        if size is None and size_at is not None:
            # length is an immediate operand inside the matched instructions
            # (Go strings, `push len`, `mov r8d, len` ...): little-endian, N bytes at byte
            # offset `size_at` counted from the start of the match
            at = int(size_at)
            width = int(self._m(hit, name, "size_bytes", 4))
            raw = inst.data[at:at + width] if at >= 0 else b""
            if len(raw) != width:
                warnings.append(
                    f"${name}: {name}_size_at={at} (+{width} bytes) is outside the "
                    f"{len(inst.data)} matched bytes"
                )
                return None
            endian = str(self._m(hit, name, "size_endian", reader.image.endian)).lower()
            if endian not in ("little", "big"):
                warnings.append(f"${name}: {name}_size_endian must be 'little' or 'big'")
                return None
            size = int.from_bytes(raw, endian) * int(self._m(hit, name, "size_mul", 1))
            size += self._tail_bytes(str(self._m(hit, name, "size_tail", "")), inst.data, at + width)
            if not 0 < size <= cap:
                warnings.append(f"${name}: the length read from the code ({size}) looks wrong; skipped")
                return None

        size_reg = self._m(hit, name, "size_reg")
        if size is None and size_reg and ref is not None:
            # length passed in an argument register before the next call (ARM: MOV R2,#n ; BL ...)
            try:
                size = recover_register(reader.image, reader.read, ref["at"], str(size_reg),
                                        int(self._m(hit, name, "size_window", 64)))
            except ValueError as e:
                warnings.append(f"${name}: {e}")
                return None
            size = size * int(self._m(hit, name, "size_mul", 1)) if size else size
            if not size or not 0 < size <= cap:
                warnings.append((f"{_NOTE} " if quiet_empty else "")
                                + f"${name}: could not recover the size from {size_reg} near {ref['at']:#x}; skipped")
                return None

        if size is not None:
            size = int(size)
            data = reader.read(start, size)
            if len(data) < size:
                warnings.append(f"${name}: wanted {size} bytes at {start:#x}, only {len(data)} available")
        elif until is not None:
            data = reader.read_until(start, bytes.fromhex(str(until)), cap)
        elif via == "match":
            data = reader.read(start, inst.length)
        else:
            data = reader.read_cstring(start, cap)
            if name in DATA_NAMES:
                msg = (f"{_NOTE} ${name}: read up to the first NUL (no '{name}_size' / '{name}_until' in the rule "
                       f"meta) - fine for strings; binary blobs need '{name}_size'. "
                       f"Set {name}_until = \"00\" to confirm and silence this")
                if msg not in warnings:
                    warnings.append(msg)
        if not data:
            # following *every* reference (ref_index = "all") legitimately hits zeroed buffers
            warnings.append(f"{_NOTE} " if quiet_empty else "")
            warnings[-1] += f"${name}: nothing readable at {start:#x}"
            return None
        image = reader.image
        return Target(
            name=name, offset=start, size=len(data), data=data, via=via,
            match_offset=inst.offset,
            rva=image.offset_to_rva(start), va=image.offset_to_va(start),
            section=image.section_name(start),
        )

    def _build_targets(self, hit: RuleHit, reader: Reader, warnings: List[str],
                       only=None) -> Dict[str, List[Target]]:
        image = reader.image
        targets: Dict[str, List[Target]] = {}
        for name, sh in hit.strings.items():
            if only is not None and name not in only:
                continue
            mode = str(self._m(hit, name, "ref", "auto")).lower()
            if mode not in ("auto", "code", "none"):
                raise CfgxError(f"rule {hit.rule}: {name}_ref must be auto, code or none")
            index = self._m(hit, name, "ref_index", 0)
            adjust = int(self._m(hit, name, "adjust", 0))
            seen = set()
            for inst in sh.instances:
                follow = mode == "code" or (mode == "auto" and image.is_executable(inst.offset))
                starts = []                                  # (start offset, via)
                if follow:
                    refs = find_references(image, inst.offset, inst.data, reader.read)
                    if refs:
                        if index == "all":
                            chosen = refs
                        else:
                            try:
                                chosen = [refs[int(index)]]
                            except IndexError:
                                warnings.append(f"${name}: {name}_ref_index={index} but only {len(refs)} reference(s) found")
                                chosen = []
                        deref = str(self._m(hit, name, "deref", False)).lower() in ("true", "1", "yes")
                        starts = []
                        for r in chosen:
                            resolved = self._deref(reader, r) if (deref and r["offset"] is not None) else r
                            if resolved is None or resolved["offset"] is None:
                                what = ("the pointer at it does not lead into the image" if resolved is None
                                        else "memory that is not stored in the file (.bss)")
                                warnings.append((f"{_NOTE} " if index == "all" else "")
                                                + f"${name}: reference to {r['va']:#x} is skipped: {what}")
                                continue
                            starts.append((resolved["offset"], f"ref:{resolved['kind']}", resolved))
                    elif (mode == "code" or self._m(hit, name, "size_reg") is not None
                          or self._m(hit, name, "ref_index") is not None or not decode_text(inst.data)):
                        # The rule says "follow the code" (or the match is plainly instructions, not text):
                        # reading the instruction bytes as if they were the data would only produce garbage.
                        extra = "" if mode == "code" else (
                            f"; if the matched bytes ARE the data, set {name}_ref = \"none\"")
                        warnings.append(f"${name}: no code reference found in the matched bytes at "
                                        f"{inst.offset:#x}" + self._gp_hint(image) + extra)
                    else:
                        warnings.append(f"${name}: matched in code but no data reference found; using the match location"
                                        + self._gp_hint(image))
                        starts = [(inst.offset, "match", None)]
                else:
                    starts = [(inst.offset, "match", None)]

                for start, via, ref in starts:
                    start += adjust
                    if start < 0 or start in seen:
                        continue
                    seen.add(start)
                    t = self._read_target(name, inst, via, start, hit, reader, warnings, ref,
                                      quiet_empty=(index == "all"))
                    if t:
                        targets.setdefault(name, []).append(t)
        for name in self._source_names(hit):                 # resource / section targets (no code reference)
            if only is None or name in only:
                for t in self._source_targets(hit, name, reader, warnings):
                    targets.setdefault(name, []).append(t)
        return targets

    @staticmethod
    def _source_names(hit) -> List[str]:
        """Targets declared in the rule meta: ``<name>_resource`` (PE resource) and ``<name>_section`` (named section)."""
        names: List[str] = []
        for key in hit.meta:
            for suffix in ("_resource", "_section"):
                if key.endswith(suffix) and key[: -len(suffix)] and key[: -len(suffix)] not in names:
                    names.append(key[: -len(suffix)])
        return names

    def _source_targets(self, hit, name, reader, warnings) -> List["Target"]:
        """Data and keys that live in a PE resource or a named section instead of behind a code reference."""
        image, pieces = reader.image, []                     # (offset, size, via)
        spec = hit.meta.get(f"{name}_resource")
        if spec is not None:
            if image.format != "pe":
                warnings.append(f"${name}: {name}_resource needs a PE file (this one is {image.format})")
            else:
                try:
                    found = select_resources(image.resources, spec)
                except ValueError as e:
                    warnings.append(f"${name}: {e}")
                    found = []
                if not found:
                    warnings.append(f"${name}: no resource matches {str(spec)!r} "
                                    f"(this file has: {describe_resources(image.resources)})")
                pieces += [(r["offset"], r["size"], f"resource:{r['type']}/{r['name']}/{r['lang']}")
                           for r in found if r["offset"] is not None]
        sec = hit.meta.get(f"{name}_section")
        if sec is not None:
            maps = [m for m in image.mappings if m.name == str(sec) and m.file_size]
            if not maps:
                warnings.append(f"${name}: no section named {str(sec)!r} (sections: "
                                f"{', '.join(m.name for m in image.mappings) or 'none'})")
            pieces += [(m.file_offset, m.file_size, f"section:{m.name}") for m in maps]

        out = []
        for offset, size, via in pieces:
            adjust = int(self._m(hit, name, "adjust", 0))
            start, avail = offset + adjust, size - adjust
            if avail <= 0:
                warnings.append(f"${name}: {name}_adjust={adjust} leaves nothing of {via}")
                continue
            fixed, until = self._m(hit, name, "size"), self._m(hit, name, "until")
            data = reader.read(start, min(int(fixed), avail) if fixed is not None else avail)
            if fixed is None and until is not None:
                data = data.split(bytes.fromhex(str(until)), 1)[0]
            if data:
                out.append(Target(name=name, offset=start, size=len(data), data=data, via=via, match_offset=offset,
                                  rva=image.offset_to_rva(start), va=image.offset_to_va(start),
                                  section=image.section_name(start)))
        return out

    @staticmethod
    def _tail_bytes(spec: str, data: bytes, start: int) -> int:
        """``size_tail = "F3A5 66A5=2 A4=1"``: find the anchor (``rep movsd``) in the matched bytes, then add the
        listed amount for each instruction that follows it, in order (``movsw`` = 2, ``movsb`` = 1).
        A DWORD count alone loses the last 1-3 bytes of a string that is not a multiple of four."""
        tokens = spec.split()
        if len(tokens) < 2:
            return 0
        idx = data.find(bytes.fromhex(tokens[0]), start)
        if idx < 0:
            return 0
        pos, extra = idx + len(bytes.fromhex(tokens[0])), 0
        for tok in tokens[1:]:
            pattern, _, amount = tok.partition("=")
            pattern = bytes.fromhex(pattern)
            if data.startswith(pattern, pos):
                extra += int(amount)
                pos += len(pattern)
        return extra

    @staticmethod
    def _deref(reader, ref):
        """The reference points at a *pointer variable* (``mov edx, ds:off_805BD48``): read the pointer
        (native width and byte order) and follow it."""
        image = reader.image
        width = (image.bits or 32) // 8
        raw = reader.read(ref["offset"], width)
        if len(raw) != width:
            return None
        va = int.from_bytes(raw, image.endian)
        if image.mapping_at_va(va) is None:
            return None
        return {"offset": image.va_to_offset(va), "rva": va - image.image_base, "va": va,
                "kind": ref["kind"] + "->ptr", "at": ref["at"]}

    @staticmethod
    def _gp_hint(image) -> str:
        if image.arch == "mips" and image.gp is None:
            return (" (MIPS: the $gp value is unknown - this ELF has no .reginfo, .got or DT_PLTGOT to take it from; "
                    "give it in the rule meta, e.g. mips_gp = 0x4a0ff0, the value of _gp)")
        return ""

    @staticmethod
    def _m(hit, name, key, default=None):
        """Rule meta for a string: ``<name>_<key>``, else inherited from its role
        (``config2`` and ``config_v2`` use ``config_<key>``; ``key_32`` uses ``key_<key>``)."""
        meta = hit.meta
        if f"{name}_{key}" in meta:
            return meta[f"{name}_{key}"]
        roles = []
        m = re.match(r"^(.+)_([^_]+)$", name)
        if m:
            roles.append(m.group(1))
        m = re.match(r"^(.*?[A-Za-z])(\d+)$", name)
        if m:
            roles.append(m.group(1))
        for role in roles:
            if f"{role}_{key}" in meta:
                return meta[f"{role}_{key}"]
        return default

    @staticmethod
    def _primary(targets: Dict[str, List[Target]]) -> Optional[str]:
        for n in DATA_NAMES:
            if n in targets:
                return n
        return next(iter(targets)) if len(targets) == 1 else None

    # ----------------------------------------------------------------- hits
    def _family(self, hit) -> str:
        return str((self.plugin.family if self.plugin else None) or hit.meta.get("family") or hit.rule)

    def _process_hit(self, hit, sample, reader, image, result):
        warnings: List[str] = []
        family = self._family(hit)
        if family not in result["families"]:
            result["families"].append(family)
        if hit.meta.get("mips_gp") is not None:               # MIPS: _gp given by the analyst
            image.gp, image.gp_source = int(hit.meta["mips_gp"]), "rule meta mips_gp"

        if str(hit.meta.get("extract", "")).strip().lower() == "none":
            # detection-only rule (family markers): recorded, nothing is extracted
            result["detections"].append(hit.rule)
            return

        if self.plugin is None:                              # no plugin: values are read as-is
            targets = self._build_targets(hit, reader, warnings, only=self._extract_names(hit))
            result["warnings"] += [f"{hit.rule}: {w}" for w in warnings]
            if not targets:
                result["errors"].append(f"{hit.rule}: rule matched but no data could be located")
                return
            values = {
                n: (ts[0].data[:MAX_VALUE_IN_OUTPUT] if len(ts) == 1
                    else [t.data[:MAX_VALUE_IN_OUTPUT] for t in ts])
                for n, ts in targets.items()
            }
            result["config"].append({
                "rule": hit.rule,
                "family": family,
                "config": values,
                "located": {n: [t.describe(include_value=False) for t in ts]
                            for n, ts in targets.items()},
            })
            return
        if self.plugin.legacy:
            self._run_legacy(hit, reader, image, result)
            return

        variants = self._plan(hit)
        needed = {name for _, mapping in variants for name in mapping.values()}
        targets = self._build_targets(hit, reader, warnings, only=needed)
        result["warnings"] += [f"{hit.rule}: {w}" for w in warnings]
        ctx = Context(hit.rule, hit.meta, hit.tags, sample, reader, image, targets)
        for label, mapping in variants:
            self._run_variant(hit, ctx, label, mapping, result)

    @staticmethod
    def _extract_names(hit: RuleHit):
        """Rule meta ``extract = "c2, key_*"`` limits which strings are read when no plugin is used."""
        spec = hit.meta.get("extract")
        if not spec:
            return None
        pats = [p.strip().lstrip("$") for p in str(spec).split(",") if p.strip()]
        names = {n for n in [*hit.strings, *Engine._source_names(hit)] if any(fnmatch.fnmatchcase(n, p) for p in pats)}
        if not names:
            raise CfgxError(f"rule {hit.rule}: meta extract={spec!r} matches none of its strings")
        return names

    # ------------------------------------------------------------- planning
    def _plan(self, hit: RuleHit):
        """Decide which rule strings feed which decrypt() parameter.

        * ``$config``/``$data`` -> ``data``; any string named like a parameter -> that parameter.
        * Strings named ``<role>_<suffix>`` or ``<role><number>`` (``key_32`` + ``data_32``,
          ``data2``) form a *variant*: strings with the same suffix are used together, and the
          plugin runs once per complete variant.  Plain strings (``$data``, ``$key``) run as
          their own variant and are shared by the others.
        Returns a list of ``(variant_label_or_None, {param: string_name})``.
        """
        names, var_kw, required = param_names(self.plugin.decrypt)
        params = [p for p in names if p not in SPECIALS]
        required_params = [p for p in required if p not in SPECIALS]
        strings = list(hit.strings) + [n for n in self._source_names(hit) if n not in hit.strings]

        exact: Dict[str, str] = {}
        for n in DATA_NAMES:
            if n in strings:
                exact["data"] = n
                break
        for p in params:
            if p != "data" and p in strings:
                exact[p] = p
        if "data" in params and "data" not in exact and len(strings) == 1:
            exact["data"] = strings[0]

        def split_name(n):
            """('data', '32') for data_32 / data32 / data2 ; roles must be a parameter or a data name."""
            candidates = []
            m = re.match(r"^(.+)_([^_]+)$", n)                  # key_32, config_v2
            if m:
                candidates.append(m.groups())
            m = re.match(r"^(.*?[A-Za-z])(\d+)$", n)             # data2, key1
            if m:
                candidates.append(m.groups())
            for role, suffix in candidates:
                if role in DATA_NAMES and "data" in params:
                    return "data", suffix
                if role in params and role != "data":
                    return role, suffix
            return None

        groups: Dict[str, Dict[str, str]] = {}
        for n in strings:
            if n in exact.values():
                continue
            parts = split_name(n)
            if parts:
                param, suffix = parts
                groups.setdefault(suffix, {})[param] = n

        if var_kw:                                           # **kwargs takes everything left over
            used = set(exact.values()) | {n for g in groups.values() for n in g.values()}
            for n in strings:
                if n not in used:
                    exact[n] = n

        def order(item):
            k = item[0]
            return (not k.isdigit(), int(k) if k.isdigit() else 0, k)

        exact_complete = bool(exact) and all(p in exact for p in required_params)
        variants = [(None, exact)] if exact_complete else []

        if not groups:
            if not exact_complete:
                missing = [p for p in required_params if p not in exact]
                avail = ", ".join(f"${n}" for n in strings) or "none"
                raise CfgxError(
                    f"decrypt() needs '{missing[0]}' but rule {hit.rule} has no ${missing[0]} string "
                    f"(strings in rule: {avail})"
                )
            return variants

        problems = []
        for suffix, g in sorted(groups.items(), key=order):
            mapping = {**exact, **g}
            missing = [p for p in required_params if p not in mapping]
            if missing:
                problems.append(f"variant '{suffix}' has no string for {', '.join(missing)}")
            else:
                variants.append((suffix, mapping))
        if not variants:
            raise CfgxError(f"decrypt() cannot be fed from rule {hit.rule}: " + "; ".join(problems))
        return variants

    # --------------------------------------------------------- decrypt flow
    def _run_variant(self, hit, ctx: Context, label, mapping, result):
        plugin = self.plugin
        names, var_kw, required = param_names(plugin.decrypt)
        tag = hit.rule if label is None else f"{hit.rule}[{label}]"
        ctx.variant, ctx.names = label, dict(mapping)
        specials = {"ctx": ctx, "reader": ctx.reader, "meta": ctx.meta, "image": ctx.image,
                    "rule": ctx.rule}

        wanted: Dict[str, str] = {}                          # parameter -> string name
        for p, sname in mapping.items():
            if ctx.targets.get(sname):
                wanted[p] = sname
            elif p in required:
                result["warnings"].append(f"{tag}: nothing could be located for ${sname}")
                return

        lists = [ctx.targets[sname] for sname in wanted.values()]
        combos = list(itertools.islice(itertools.product(*lists), self.max_combinations + 1))
        if len(combos) > self.max_combinations:
            combos = combos[: self.max_combinations]
            result["warnings"].append(
                f"{tag}: more than {self.max_combinations} data/key combinations; only the first "
                f"{self.max_combinations} were tried")

        attempts, failures = [], []
        for combo in combos:
            chosen = dict(zip(wanted.keys(), combo))
            kwargs = {p: t.data for p, t in chosen.items()}
            kwargs.update({k: v for k, v in specials.items() if k in names})
            try:
                out = plugin.decrypt(**kwargs)
            except Exception as e:
                failures.append(f"{type(e).__name__}: {e}")
                continue
            if out is None:
                failures.append("decrypt() returned None")
                continue
            plaintext = bytes(out) if isinstance(out, (bytes, bytearray)) else None

            if plugin.validate is not None:
                try:
                    ok = bool(plugin.validate(plaintext if plaintext is not None else out))
                except Exception as e:
                    failures.append(f"validate(): {type(e).__name__}: {e}")
                    continue
                if not ok:
                    failures.append("validate() rejected the result")
                    continue
            score = score_plaintext(plaintext) if plaintext is not None else 1.0
            attempts.append((score, chosen, out, plaintext))

        for note in dict.fromkeys(ctx.notes):               # remarks the plugin made while decrypting
            result["warnings"].append(f"{_NOTE} {tag}: {note}")
        ctx.notes.clear()

        if not attempts:
            detail = "; ".join(sorted(set(failures))[:3]) or "no combinations"
            result["errors"].append(f"{tag}: decryption failed ({detail})")
            return

        # Several data blobs are separate entries; several keys/IVs for ONE blob are alternatives.
        by_blob: Dict[int, list] = {}
        for a in attempts:
            by_blob.setdefault(id(a[1].get("data")), []).append(a)
        selected = []                                       # (attempt, low_confidence)
        for group in by_blob.values():
            if plugin.validate is None and len(group) > 1:
                group.sort(key=lambda a: -a[0])
                good = [a for a in group if a[0] >= 0.85]
                selected += [(a, False) for a in good] if good else [(group[0], True)]
            else:
                selected += [(a, False) for a in group]
        selected.sort(key=lambda sa: sa[0][1]["data"].offset if "data" in sa[0][1] else 0)

        texts = [pt for (_, _, _, pt), _ in selected if pt is not None]
        noise = len(texts) >= 3 and not any(score_plaintext(t) >= 0.85 for t in texts)
        if noise:                                            # say so instead of printing confident-looking hex
            result["warnings"].append(
                f"{tag}: none of the {len(texts)} entries decrypted to readable text - wrong key or cipher? "
                f"(ignore this if the family stores binary data)")

        for (score, chosen, out, plaintext), confidence_low in selected:
            try:
                parsed = self._parse(out, plaintext, ctx)
            except Exception as e:
                result["errors"].append(f"{tag}: parse() failed: {type(e).__name__}: {e}")
                continue
            entry = {
                "rule": hit.rule,
                "family": self._family(hit),
                "config": parsed,
                "inputs": {p: t.describe(include_value=(p != "data")) for p, t in chosen.items()},
            }
            if label is not None:
                entry["variant"] = label
            if confidence_low or noise:
                entry["confidence"] = "low"
            result["config"].append(entry)

    def _parse(self, out, plaintext, ctx):
        value = plaintext if plaintext is not None else out
        if self.plugin.parse is not None:
            names, _, _ = param_names(self.plugin.parse)
            extra = {"ctx": ctx, "reader": ctx.reader, "meta": ctx.meta}
            first = names[0] if names else None
            kwargs = {k: v for k, v in extra.items() if k in names and k != first}
            return self.plugin.parse(value, **kwargs)
        return auto_parse(value)

    # ---------------------------------------------------------- legacy flow
    def _run_legacy(self, hit, reader, image, result):
        """Old plugin contract: extract(matches, reader) -> {"status","config"}."""
        matches = []
        for name, sh in hit.strings.items():
            for inst in sh.instances:
                refs = find_references(image, inst.offset, inst.data, reader.read)
                for r in refs:
                    r["data"] = reader.read(r["offset"], 4096) if r["offset"] is not None else b""
                m = {
                    "rule": hit.rule, "identifier": sh.identifier, "meta": hit.meta,
                    "tags": hit.tags, "offset": inst.offset, "match_data": inst.data,
                    "section": image.section_name(inst.offset),
                    "rva": image.offset_to_rva(inst.offset),
                    "va": image.offset_to_va(inst.offset),
                    "references": refs,
                }
                if refs:
                    m.update(data=refs[0]["data"], data_offset=refs[0]["offset"],
                             data_rva=refs[0]["rva"], data_va=refs[0]["va"])
                matches.append(m)
        out = self.plugin.extract(matches, reader)
        if isinstance(out, dict) and "status" in out and "config" in out:
            if out["status"] != "success":
                result["errors"].append(f"{hit.rule}: plugin reported status {out['status']!r}")
                return
            out = out["config"]
        result["config"].append({"rule": hit.rule, "family": self._family(hit),
                                 "config": out})
