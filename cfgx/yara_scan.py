"""Compile YARA rules once and turn matches into plain, easy-to-use objects."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

import yara

from .errors import CfgxError


@dataclass
class Instance:
    offset: int
    length: int
    data: bytes


@dataclass
class StringHit:
    identifier: str            # as written in the rule, e.g. "$key"
    name: str                  # without "$" ("key"); anonymous strings -> "anon"
    instances: List[Instance] = field(default_factory=list)


@dataclass
class RuleHit:
    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, object]
    strings: Dict[str, StringHit]      # keyed by name


class Scanner:
    def __init__(self, rules_path):
        self.rules_path = Path(rules_path)
        self.rules = self._compile(self.rules_path)

    @staticmethod
    def _compile(path: Path):
        if not path.exists():
            raise CfgxError(f"YARA rule path not found: {path}")
        if path.is_dir():
            files = sorted(p for p in path.rglob("*") if p.suffix.lower() in (".yar", ".yara"))
            if not files:
                raise CfgxError(f"no .yar/.yara files in {path}")
            filepaths = {f"r{i}_{f.stem}": str(f) for i, f in enumerate(files)}
        else:
            filepaths = {"default": str(path)}
        try:
            return yara.compile(filepaths=filepaths)
        except yara.SyntaxError as e:
            raise CfgxError(f"YARA syntax error: {e}") from e
        except yara.Error as e:
            raise CfgxError(f"YARA error: {e}") from e

    def scan(self, sample) -> List[RuleHit]:
        try:
            matches = self.rules.match(str(sample))
        except yara.Error as e:
            raise CfgxError(f"YARA scan failed: {e}") from e

        hits: List[RuleHit] = []
        for m in matches:
            strings: Dict[str, StringHit] = {}
            for s in m.strings:
                name = s.identifier.lstrip("$") or "anon"
                sh = strings.setdefault(name, StringHit(s.identifier, name))
                for inst in s.instances:
                    sh.instances.append(
                        Instance(inst.offset, inst.matched_length, bytes(inst.matched_data))
                    )
            for sh in strings.values():
                sh.instances.sort(key=lambda i: i.offset)
            hits.append(RuleHit(m.rule, m.namespace, list(m.tags), dict(m.meta), strings))
        return hits
