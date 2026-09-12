from elftools import elf

from .reader import SampleReader
from .plugin import load_decryptor, validate_result

from formats.pe import load_pe, resolve_offset
from yara_handler.runner import run_yara

from typing import List, cast
from .models import Match, PEMatch

from formats.detect import detect_format
from formats.elf import load_elf
from formats.elf import offset_to_elf_address

def process_sample(rule_path, sample_path, decryptor_path):
    decryptor = load_decryptor(decryptor_path)

    sample_format = detect_format(sample_path)

    if sample_format == "pe":
        pe = load_pe(sample_path)
        elf = None

    elif sample_format == "elf":
        elf, elf_file = load_elf(sample_path)
        pe = None

    else:
        raise ValueError("Unsupported sample format")

    yara_results = run_yara(rule_path, sample_path)

    processed_results: List[Match | PEMatch] = []

    for result in yara_results:
        offset = result["offset"]
        
        if sample_format == "pe":
            resolved = resolve_offset(pe, offset)

        elif sample_format == "elf":
            resolved = offset_to_elf_address(elf, offset)

        processed_result = result.copy()

        if resolved is not None:
            processed_result = cast(
                PEMatch,
                {**result, **resolved}
            )
        
        processed_results.append(processed_result)
        
    reader = SampleReader(sample_path)

    print("Processed results:", len(processed_results))
    print("Calling analyst decryptor")
    
    if not hasattr(decryptor, "extract"):
        raise AttributeError(
            "Analyst plugin must define extract(matches, reader)"
        )

    if not callable(decryptor.extract):
        raise TypeError(
            "Analyst plugin 'extract' must be callable"
        )
    
    try:
        result = decryptor.extract(processed_results, reader)
        return validate_result(result)

    finally:
        if sample_format == "elf":
            elf_file.close()

    return validate_result(result)




#if __name__ == "__main__":
#        reader = SampleReader(
#            "D:/Data/blog/secblog/projects/malware/sample"
#        )
#
#        data = reader.read(457576, 16)
#
#        print(data)