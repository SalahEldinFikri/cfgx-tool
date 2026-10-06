"""Plugin loading.

The smallest possible plugin is one function::

    from cfgx.crypto import rc4

    def decrypt(data, key):
        return rc4(data, key)

Optional extras: ``parse(plaintext)``, ``validate(plaintext)``, ``FAMILY = "..."``.
Old-style plugins that define ``extract(matches, reader)`` keep working.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import sys
from pathlib import Path

from .errors import CfgxError


class Plugin:
    def __init__(self, path: Path, module):
        self.path = path
        self.module = module
        self.name = path.stem
        self.family = getattr(module, "FAMILY", None)
        self.decrypt = getattr(module, "decrypt", None)
        self.parse = getattr(module, "parse", None)
        self.validate = getattr(module, "validate", None)
        self.extract = getattr(module, "extract", None)

        for fn in ("decrypt", "parse", "validate", "extract"):
            attr = getattr(self, fn)
            if attr is not None and not callable(attr):
                raise CfgxError(f"plugin {path.name}: '{fn}' must be a function")
        if self.decrypt is None and self.extract is None:
            raise CfgxError(
                f"plugin {path.name} must define decrypt(data, ...) "
                f"(or the legacy extract(matches, reader))"
            )

    @property
    def legacy(self) -> bool:
        """Old contract: an explicit ``extract(matches, reader)`` always takes over."""
        return self.extract is not None

    @property
    def ambiguous(self) -> bool:
        return self.extract is not None and self.decrypt is not None


def load_plugin(path) -> Plugin:
    path = Path(path)
    if not path.is_file():
        raise CfgxError(f"plugin not found: {path}")
    mod_name = "cfgx_plugin_" + hashlib.sha1(str(path.resolve()).encode()).hexdigest()[:10]
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise CfgxError(f"cannot load plugin: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent.resolve()))     # let plugins import siblings
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise CfgxError(f"plugin {path.name} failed to import: {type(e).__name__}: {e}") from e
    finally:
        sys.path.pop(0)
    return Plugin(path, module)


def param_names(func):
    """(names, accepts_var_kwargs, required_names) for ``func``."""
    sig = inspect.signature(func)
    names, required, var_kw = [], [], False
    for p in sig.parameters.values():
        if p.kind is p.VAR_KEYWORD:
            var_kw = True
        elif p.kind is p.VAR_POSITIONAL:
            continue
        else:
            names.append(p.name)
            if p.default is p.empty:
                required.append(p.name)
    return names, var_kw, required
