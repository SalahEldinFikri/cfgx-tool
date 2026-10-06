"""Command line interface.

    cfgx RULE SAMPLE [PLUGIN] [options]

RULE    a .yar file or a directory of rules
SAMPLE  a file, or a directory of samples
PLUGIN  python file with decrypt(data, key, ...) ; omit it to only *locate*
        the data/keys your rule points at (great for debugging rules)

Exit status: 0 = at least one sample produced output, 1 = nothing extracted, 2 = usage/fatal error.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List

from . import __version__
from .engine import Engine
from .errors import CfgxError
from .export import save_directory
from .output import dumps
from .render import Console


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cfgx",
        description="Extract malware configuration: YARA finds the data, your plugin decrypts it.",
    )
    p.add_argument("rule", help="YARA rule file (or directory of .yar/.yara files)")
    p.add_argument("sample", help="sample file or directory of samples")
    p.add_argument("plugin", nargs="?", help="plugin .py file (omit to only locate data/keys)")
    p.add_argument("-o", "--output", help="save JSON: a *.json path = one combined file; otherwise a directory with one sub-directory per family (one file per sample + a family file)")
    p.add_argument("--json", action="store_true", help="print the full JSON result instead of the short summary")
    p.add_argument("-r", "--recursive", action="store_true", help="descend into sub-directories")
    p.add_argument("--glob", default="*", help="only process files matching this pattern (default: *)")
    p.add_argument("--format", choices=["auto", "pe", "elf", "raw"], default="auto",
                   help="force the container format (default: detect; unknown files are scanned as raw blobs)")
    p.add_argument("--arch", choices=["x86", "x64"], help="architecture for raw blobs (enables code-reference following)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="also list files that did not match, show notes and full tracebacks")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colour output (default: auto)")
    p.add_argument("--full", action="store_true", help="do not truncate long values in the console output")
    p.add_argument("-q", "--quiet", action="store_true", help="no console output (use with -o and the exit status)")
    p.add_argument("--version", action="version", version=f"cfgx {__version__}")
    return p


def _collect(sample: Path, recursive: bool, pattern: str) -> List[Path]:
    if sample.is_file():
        return [sample]
    if not sample.is_dir():
        raise CfgxError(f"sample path not found: {sample}")
    it = sample.rglob(pattern) if recursive else sample.glob(pattern)
    return sorted(p for p in it if p.is_file())


def _main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        engine = Engine(args.rule, args.plugin, force_format=args.format, arch=args.arch,
                        debug=args.verbose)
        samples = _collect(Path(args.sample), args.recursive, args.glob)
    except CfgxError as e:
        print(f"cfgx: error: {e}", file=sys.stderr)
        return 2
    if not samples:
        print("cfgx: error: no samples found", file=sys.stderr)
        return 2

    console = Console(color=args.color, full=args.full)
    show = not args.quiet and not args.json
    if show:
        console.banner(args.rule, args.plugin, len(samples))
    progress = show and len(samples) > 1 and console.color and sys.stderr.isatty()

    results = []
    started = time.perf_counter()
    for i, sample in enumerate(samples, 1):
        if progress:
            sys.stderr.write(f"\r\x1b[2K  scanning {i}/{len(samples)}  {sample.name[:48]}")
            sys.stderr.flush()
        res = engine.run(sample)
        results.append(res)
        if progress:
            sys.stderr.write("\r\x1b[2K")
        if args.quiet:
            continue
        if args.json and len(samples) == 1:
            print(dumps(res))
        elif show:
            console.sample(res, args.verbose)
    elapsed = time.perf_counter() - started

    if not args.quiet and args.json and len(samples) > 1:
        print(dumps(results))
    if show:
        console.summary(results, elapsed, args.verbose)

    if args.output:
        out = Path(args.output)
        if out.suffix.lower() == ".json":
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(dumps(results[0] if len(results) == 1 else results), encoding="utf-8")
            info = {"total": 1, "layout": []}
        else:
            info = save_directory(results, out)
        if show:
            console.saved(args.output, info["total"], info["layout"])

    ok = any(r["status"] in ("success", "located") for r in results)
    return 0 if ok else 1


def main(argv=None) -> int:
    try:
        return _main(argv)
    except BrokenPipeError:             # e.g. `cfgx ... | head`
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
