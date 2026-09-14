from typing import TypedDict


class Match(TypedDict):
    rule: str
    identifier: str
    offset: int


class PEMetadata(TypedDict):
    section: str
    rva: int
    va: int


class DataMetadata(TypedDict, total=False):
    data: bytes
    data_offset: int
    data_rva: int
    data_va: int
    data_section: str


class PEMatch(
    Match,
    PEMetadata,
    DataMetadata
):
    pass


class ExtractionResult(TypedDict):
    status: str
    config: object