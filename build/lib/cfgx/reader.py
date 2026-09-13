def read_bytes(sample_path, start, end=None):
    if start < 0:
        raise ValueError("Start offset cannot be negative")

    if end is not None and end < start:
        raise ValueError("End offset cannot be smaller than start offset")

    with open(sample_path, "rb") as f:
        f.seek(start)

        if end is None:
            return f.read()

        return f.read(end - start)


class SampleReader:
    def __init__(self, sample_path):
        self._sample_path = sample_path

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