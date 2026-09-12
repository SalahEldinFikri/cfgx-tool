from elftools.elf.elffile import ELFFile


def load_elf(sample_path):
    f = open(sample_path, "rb")
    elf = ELFFile(f)

    return elf, f


def get_elf_metadata(elf):
    return {
        "class": elf.elfclass,
        "machine": elf["e_machine"],
        "entry_point": elf["e_entry"],
    }


def offset_to_elf_address(elf, offset):
    for section in elf.iter_sections():
        section_offset = section["sh_offset"]
        section_size = section["sh_size"]

        if section_offset <= offset < section_offset + section_size:
            address = section["sh_addr"] + (offset - section_offset)

            return {
                "section": section.name,
                "va": address
            }

    return None