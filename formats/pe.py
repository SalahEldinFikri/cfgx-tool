import pefile
from typing import Optional
from cfgx.models import PEMetadata


def load_pe(sample_path):
    pe = pefile.PE(sample_path)

    return pe


def offset_to_rva(pe, offset):
    for section in pe.sections:
        if section.PointerToRawData <= offset < (
            section.PointerToRawData + section.SizeOfRawData
        ):
            rva = (
                offset
                - section.PointerToRawData
                + section.VirtualAddress
            )

            return rva

    return None


def rva_to_offset(pe, rva):
    for section in pe.sections:
        if (
            section.VirtualAddress
            <= rva
            < section.VirtualAddress + max(
                section.Misc_VirtualSize,
                section.SizeOfRawData
            )
        ):
            offset = (
                rva
                - section.VirtualAddress
                + section.PointerToRawData
            )

            return offset

    return None


def rva_to_va(pe, rva):
    va = pe.OPTIONAL_HEADER.ImageBase + rva

    return va


def resolve_offset(pe, offset) -> Optional[PEMetadata]:
    rva = offset_to_rva(pe, offset)

    if rva is None:
        return None

    va = rva_to_va(pe, rva)
    section_name = get_section_for_offset(pe, offset)

    if section_name is None:
        return None

    return {
        "section": section_name,
        "rva": rva,
        "va": va
    }


def get_section_for_offset(pe, offset):
    for section in pe.sections:
        if section.PointerToRawData <= offset < (
            section.PointerToRawData + section.SizeOfRawData
        ):
            return section.Name.rstrip(
                b"\x00"
            ).decode(errors="replace")

    return None