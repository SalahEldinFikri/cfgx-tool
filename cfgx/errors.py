import os


class CfgxError(Exception):
    """Fatal, user-facing error (bad rule, bad plugin, unreadable sample ...)."""


def os_hint(exc, nt=None):
    """Extra explanation for OS errors that are confusing on Windows."""
    nt = (os.name == "nt") if nt is None else nt
    if isinstance(exc, OSError) and nt and (getattr(exc, "winerror", None) == 225 or exc.errno == 22):
        return (
            "hint: Windows refused to open this file (Errno 22 / WinError 225). For a malware sample this "
            "usually means antivirus real-time protection is blocking it - add the sample folder to the "
            "Defender exclusions, or run cfgx inside your analysis VM."
        )
    return None
