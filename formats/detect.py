def detect_format(sample_path):
    with open(sample_path, "rb") as f:
        magic = f.read(4)

    if magic.startswith(b"MZ"):
        return "pe"

    if magic == b"\x7fELF":
        return "elf"

    return None