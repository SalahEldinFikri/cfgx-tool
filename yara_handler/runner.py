import yara
from typing import List
from cfgx.models import Match


def run_yara(rule_path, sample_path) -> List[Match]:
    rules = yara.compile(filepath=str(rule_path))
    matches = rules.match(filepath=str(sample_path))
    results: List[Match] = []
    for match in matches:
        for string in match.strings:
            for instance in string.instances:
                results.append({
                "rule": match.rule,   
                "identifier": string.identifier,
                "offset": instance.offset
            })
    return results


#if __name__ == "__main__":
#    results = run_yara(
#    "D:/Data/blog/secblog/projects/cfgx commandline tool/yararule/voidstealer.yar",
#    "D:/Data/blog/secblog/projects/cfgx commandline tool/malware/sample"
#)
#    print(results)
    
    
