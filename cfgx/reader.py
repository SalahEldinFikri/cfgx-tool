def read_bytes(sample_path, start, end=None):
    if start < 0:
        raise ValueError("Start offset cannot be negative")

    if end is not None and end < start:
        raise ValueError(
            "End offset cannot be smaller than start offset"
        )

    with open(sample_path, "rb") as f:
        f.seek(start)

        if end is None:
            return f.read()

        return f.read(end - start)


class SampleReader:
    def __init__(self, sample_path, rva_to_offset=None):
        self._sample_path = sample_path
        self._rva_to_offset = rva_to_offset

    def read(self, offset, size):
        if not isinstance(offset, int):
            raise TypeError("Offset must be an integer")

        if not isinstance(size, int):
            raise TypeError("Size must be an integer")

        if offset < 0:
            raise ValueError("Offset cannot be negative")

        if size < 0:
            raise ValueError("Size cannot be negative")

        return read_bytes(
            self._sample_path,
            offset,
            offset + size
        )

    def rva_to_offset(self, rva):
        if not isinstance(rva, int):
            raise TypeError("RVA must be an integer")

        if rva < 0:
            raise ValueError("RVA cannot be negative")

        if self._rva_to_offset is None:
            raise ValueError(
                "RVA to file offset conversion is not available"
            )

        return self._rva_to_offset(rva)