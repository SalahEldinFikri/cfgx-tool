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
            return (
                offset
                - section.PointerToRawData
                + section.VirtualAddress
            )

    return None


def rva_to_offset(pe, rva):
    for section in pe.sections:
        if (
            section.VirtualAddress
            <= rva
            < section.VirtualAddress
            + max(
                section.Misc_VirtualSize,
                section.SizeOfRawData
            )
        ):
            return (
                rva
                - section.VirtualAddress
                + section.PointerToRawData
            )

    return None


def va_to_rva(pe, va):
    image_base = pe.OPTIONAL_HEADER.ImageBase

    if va < image_base:
        return None

    rva = va - image_base

    if rva < 0:
        return None

    return rva


def rva_to_va(pe, rva):
    return pe.OPTIONAL_HEADER.ImageBase + rva


def get_section_for_offset(pe, offset):
    for section in pe.sections:
        if section.PointerToRawData <= offset < (
            section.PointerToRawData + section.SizeOfRawData
        ):
            return section.Name.rstrip(
                b"\x00"
            ).decode(
                errors="replace"
            )

    return None


def resolve_rip_relative(
    pe,
    match_offset,
    match_data
):
    patterns = (
        b"\x48\x8D\x0D",
        b"\x48\x8D\x15",
        b"\x4C\x8D\x3D",
    )

    for pattern in patterns:
        position = match_data.find(pattern)

        if position == -1:
            continue

        if position + 7 > len(match_data):
            continue

        instruction_offset = (
            match_offset
            + position
        )

        source_rva = offset_to_rva(
            pe,
            instruction_offset
        )

        if source_rva is None:
            continue

        displacement = int.from_bytes(
            match_data[
                position + 3:
                position + 7
            ],
            byteorder="little",
            signed=True
        )

        target_rva = (
            source_rva
            + 7
            + displacement
        )

        target_offset = rva_to_offset(
            pe,
            target_rva
        )

        if target_offset is None:
            continue

        return {
            "offset": target_offset,
            "rva": target_rva,
            "va": rva_to_va(
                pe,
                target_rva
            )
        }

    return None


def resolve_rip_references(
    pe,
    match_offset,
    match_data
):
    patterns = (
        b"\x48\x8D\x0D",
        b"\x48\x8D\x15",
        b"\x4C\x8D\x3D",
    )

    references = []

    for position in range(
        len(match_data) - 6
    ):
        pattern = match_data[
            position:
            position + 3
        ]

        if pattern not in patterns:
            continue

        instruction_offset = (
            match_offset
            + position
        )

        source_rva = offset_to_rva(
            pe,
            instruction_offset
        )

        if source_rva is None:
            continue

        displacement = int.from_bytes(
            match_data[
                position + 3:
                position + 7
            ],
            byteorder="little",
            signed=True
        )

        target_rva = (
            source_rva
            + 7
            + displacement
        )

        target_offset = rva_to_offset(
            pe,
            target_rva
        )

        if target_offset is None:
            continue

        reference = {
            "offset": target_offset,
            "rva": target_rva,
            "va": rva_to_va(
                pe,
                target_rva
            )
        }

        if reference not in references:
            references.append(reference)

    return references


def resolve_push_offset(
    pe,
    match_offset,
    match_data
):
    for position in range(
        len(match_data) - 4
    ):
        if match_data[position] != 0x68:
            continue

        target_value = int.from_bytes(
            match_data[
                position + 1:
                position + 5
            ],
            byteorder="little",
            signed=False
        )

        target_rva = va_to_rva(
            pe,
            target_value
        )

        if target_rva is not None:
            target_offset = rva_to_offset(
                pe,
                target_rva
            )

            if target_offset is not None:
                return {
                    "offset": target_offset,
                    "rva": target_rva,
                    "va": target_value
                }

        target_rva = target_value

        target_offset = rva_to_offset(
            pe,
            target_rva
        )

        if target_offset is not None:
            return {
                "offset": target_offset,
                "rva": target_rva,
                "va": rva_to_va(
                    pe,
                    target_rva
                )
            }

    return None


def resolve_push_references(
    pe,
    match_offset,
    match_data
):
    references = []

    for position in range(
        len(match_data) - 4
    ):
        if match_data[position] != 0x68:
            continue

        target_value = int.from_bytes(
            match_data[
                position + 1:
                position + 5
            ],
            byteorder="little",
            signed=False
        )

        target_rva = va_to_rva(
            pe,
            target_value
        )

        if target_rva is not None:
            target_offset = rva_to_offset(
                pe,
                target_rva
            )

            if target_offset is not None:
                reference = {
                    "offset": target_offset,
                    "rva": target_rva,
                    "va": target_value
                }

                if reference not in references:
                    references.append(reference)

                continue

        target_rva = target_value
        target_offset = rva_to_offset(
            pe,
            target_rva
        )

        if target_offset is not None:
            reference = {
                "offset": target_offset,
                "rva": target_rva,
                "va": rva_to_va(
                    pe,
                    target_rva
                )
            }

            if reference not in references:
                references.append(reference)

    return references


def resolve_reference(
    pe,
    match_offset,
    match_data
):
    references = resolve_references(
        pe,
        match_offset,
        match_data
    )

    if not references:
        return None

    return references[0]


def resolve_references(
    pe,
    match_offset,
    match_data
):
    if not isinstance(
        match_offset,
        int
    ):
        raise TypeError(
            "Match offset must be an integer"
        )

    if match_offset < 0:
        raise ValueError(
            "Match offset cannot be negative"
        )

    if not isinstance(
        match_data,
        bytes
    ):
        raise TypeError(
            "Match data must be bytes"
        )

    references = []

    rip_references = resolve_rip_references(
        pe,
        match_offset,
        match_data
    )

    for reference in rip_references:
        if reference not in references:
            references.append(
                reference
            )

    push_references = resolve_push_references(
        pe,
        match_offset,
        match_data
    )

    for reference in push_references:
        if reference not in references:
            references.append(
                reference
            )

    return references


def resolve_offset(
    pe,
    offset
) -> Optional[PEMetadata]:
    rva = offset_to_rva(
        pe,
        offset
    )

    if rva is None:
        return None

    va = rva_to_va(
        pe,
        rva
    )

    section_name = get_section_for_offset(
        pe,
        offset
    )

    if section_name is None:
        return None

    return {
        "section": section_name,
        "rva": rva,
        "va": va
    }
