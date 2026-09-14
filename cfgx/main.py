from pathlib import Path

from cfgx.plugin import load_decryptor, validate_result
from cfgx.reader import SampleReader
from yara_handler.runner import run_yara

from formats.detect import detect_format

from formats.pe import (
    load_pe,
    resolve_offset,
    resolve_references,
    rva_to_offset,
)

from formats.elf import (
    load_elf,
    offset_to_elf_address,
)


def process_sample(
    rule_path,
    sample_path,
    decryptor_path
):
    rule_path = Path(rule_path)
    sample_path = Path(sample_path)
    decryptor_path = Path(decryptor_path)

    sample_format = detect_format(
        sample_path
    )

    if sample_format is None:
        return {
            "status": "unsupported_format",
            "config": []
        }

    pe = None
    elf = None
    elf_file = None

    if sample_format == "pe":

        pe = load_pe(
            sample_path
        )

        reader = SampleReader(
            sample_path,
            rva_to_offset=lambda rva: rva_to_offset(
                pe,
                rva
            )
        )

    elif sample_format == "elf":

        elf, elf_file = load_elf(
            sample_path
        )

        reader = SampleReader(
            sample_path
        )

    else:

        return {
            "status": "unsupported_format",
            "config": []
        }

    try:

        matches = run_yara(
            rule_path,
            sample_path
        )

        processed_matches = []

        for match in matches:

            processed = dict(
                match
            )

            offset = match[
                "offset"
            ]

            if sample_format == "pe":

                metadata = resolve_offset(
                    pe,
                    offset
                )

                if metadata is not None:

                    processed.update(
                        metadata
                    )

                match_data = match.get(
                    "match_data"
                )

                if match_data is not None:

                    try:

                        references = resolve_references(
                            pe,
                            offset,
                            match_data
                        )

                    except Exception:

                        references = []

                    resolved_references = []

                    for reference in references:

                        reference_data = None

                        try:

                            reference_data = reader.read(
                                reference["offset"],
                                4096
                            )

                        except Exception:

                            reference_data = None

                        if reference_data:

                            reference_data = reference_data.split(
                                b"\x00",
                                1
                            )[0]

                        if reference_data:

                            reference = {
                                **reference,
                                "data": reference_data
                            }

                        resolved_references.append(
                            reference
                        )

                    if resolved_references:

                        processed[
                            "references"
                        ] = resolved_references

                        first_reference = (
                            resolved_references[0]
                        )

                        if "data" in first_reference:

                            processed[
                                "data"
                            ] = first_reference[
                                "data"
                            ]

                        processed[
                            "data_offset"
                        ] = first_reference[
                            "offset"
                        ]

                        processed[
                            "data_rva"
                        ] = first_reference[
                            "rva"
                        ]

                        processed[
                            "data_va"
                        ] = first_reference[
                            "va"
                        ]

            elif sample_format == "elf":

                metadata = offset_to_elf_address(
                    elf,
                    offset
                )

                if metadata is not None:

                    processed.update(
                        metadata
                    )

            processed_matches.append(
                processed
            )

        decryptor = load_decryptor(
            decryptor_path
        )

        if not hasattr(
            decryptor,
            "extract"
        ):

            return {
                "status": "extractor_missing",
                "config": []
            }

        result = decryptor.extract(
            processed_matches,
            reader
        )

        result = validate_result(
            result
        )

        return result

    finally:

        if elf_file is not None:

            elf_file.close()