from __future__ import annotations

import os

from .base import Image, Mapping


def load_raw(path, arch=None) -> Image:
    """Treat the file as one flat blob (memory dumps, shellcode, unpacked payloads).

    File offset == virtual address, image base is 0.
    """
    size = os.path.getsize(path)
    mapping = Mapping(
        name="raw",
        file_offset=0,
        file_size=size,
        va=0,
        mem_size=size,
        executable=False,
        writable=True,
    )
    return Image(format="raw", arch=arch, image_base=0, file_size=size, mappings=[mapping])
