from .reader import SampleReader
from .plugin import load_decryptor, validate_result

from formats.pe import load_pe, resolve_offset
from yara_handler.runner import run_yara

from typing import List, cast
from .models import Match, PEMatch

def process_sample(rule_path, sample_path, decryptor_path):
    decryptor = load_decryptor(decryptor_path)

    pe = load_pe(sample_path)
    yara_results = run_yara(rule_path, sample_path)

    processed_results: List[Match | PEMatch] = []

    for result in yara_results:
        offset = result["offset"]
        resolved = resolve_offset(pe, offset)

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
    
    result = decryptor.extract(processed_results, reader)

    return validate_result(result)




#if __name__ == "__main__":
#        reader = SampleReader(
#            "D:/Data/blog/secblog/projects/malware/sample"
#        )
#
#        data = reader.read(457576, 16)
#
#        print(data)