from typing import TypedDict


class Match(TypedDict):
    rule: str
    identifier: str
    offset: int


class PEMetadata(TypedDict):
    section: str
    rva: int
    va: int


class PEMatch(Match, PEMetadata):
    pass


class ExtractionResult(TypedDict):
    status: str
    config: object