import pefile


def analyze_pe(file_path):
    pe = pefile.PE(file_path)

    arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"

    sections = []
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        sections.append({
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": round(section.get_entropy(), 2)
        })

    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            for imp in entry.imports:
                if imp.name:
                    imports.append({
                        "dll": dll_name,
                        "api": imp.name.decode(errors="ignore")
                    })

    return {
        "arch": arch,
        "sections": sections,
        "imports": imports,
        "entrypoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase)
    }