def generate_report(file_path, pe_info, findings, score, priority):
    report = []

    report.append("# PE Analysis Report\n")
    report.append(f"File: `{file_path}`\n")
    report.append(f"Architecture: `{pe_info['arch']}`\n")
    report.append(f"Risk score: `{score}/100`\n")
    report.append(f"Priority: `{priority}`\n")
    report.append(f"Image base: `{pe_info['image_base']}`\n")
    report.append(f"Entrypoint RVA: `{pe_info['entrypoint']}`\n")

    report.append("\n---\n")

    report.append("# Sections\n")
    if pe_info["sections"]:
        report.append("| Name | Virtual size | Raw size | Entropy |")
        report.append("|---|---:|---:|---:|")
        for section in pe_info["sections"]:
            report.append(
                f"| `{section['name']}` | {section['virtual_size']} | {section['raw_size']} | {section['entropy']} |"
            )
    else:
        report.append("No sections found.\n")

    report.append("\n---\n")

    report.append("# Imports\n")
    imports = pe_info["imports"]

    if imports:
        current_dll = None
        for imp in imports:
            if imp["dll"] != current_dll:
                current_dll = imp["dll"]
                report.append(f"\n## `{current_dll}`\n")
            report.append(f"- `{imp['api']}`")
    else:
        report.append(
            "No imports found. This may indicate a very small binary, static linking, packing, or custom resolving.\n"
        )

    report.append("\n---\n")

    report.append("# Findings\n")

    if not findings:
        report.append("No high-confidence suspicious API clusters detected.\n")
    else:
        for finding in findings:
            report.append(f"## {finding['category']}\n")
            report.append(f"Weight: `{finding.get('weight', 0)}`\n")
            for api in finding["matched"]:
                report.append(f"- `{api}`")
            report.append("")

    report.append("\n---\n")

    report.append("# Reverse Hints\n")
    report.extend(generate_reverse_hints(pe_info, findings))

    return "\n".join(report)


def generate_reverse_hints(pe_info, findings):
    hints = []

    imports = [imp["api"] for imp in pe_info["imports"]]
    sections = pe_info["sections"]

    if not imports:
        hints.append("- No imports detected. Check if the binary is packed, statically linked, or manually resolving APIs.")
        hints.append("- Start from the entrypoint and inspect early initialization code in Ghidra.")
        return hints

    gui_dialog_apis = [
        "DialogBoxParamA",
        "DialogBoxParamW",
        "GetDlgItemTextA",
        "GetDlgItemTextW",
        "SetDlgItemTextA",
        "SetDlgItemTextW",
        "EndDialog"
    ]

    if any(api in imports for api in gui_dialog_apis):
        hints.append("- Windows dialog APIs detected. This may be a GUI crackme or dialog-based validation program.")
        hints.append("- Focus on the dialog procedure, WM_COMMAND handler, and calls to GetDlgItemTextA/W.")
        hints.append("- Look for where user input is read, transformed, compared, and then passed to SetDlgItemTextA/W.")

    if any(api in imports for api in ["strcmp", "strncmp", "strlen", "sprintf", "scanf"]):
        hints.append("- String processing APIs detected. Good first targets: input validation, password checks, encoding loops.")

    if any(api in imports for api in ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]):
        hints.append("- Anti-debug related APIs detected. Inspect early checks near entrypoint or before validation logic.")

    if any(api in imports for api in ["CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW"]):
        hints.append("- Process execution APIs detected. Check whether the program launches external commands or helper binaries.")

    if any(api in imports for api in ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]):
        hints.append("- Memory manipulation / injection-like APIs detected. Inspect allocation and write/call chains carefully.")

    high_entropy = [s for s in sections if s["entropy"] >= 7.0]
    if high_entropy:
        names = ", ".join(s["name"] for s in high_entropy)
        hints.append(f"- High entropy section(s) detected: {names}. Possible compression, packing, or encrypted data.")

    if not hints:
        hints.append("- Low-noise binary. Start with strings, main function, and xrefs to user-visible messages.")
        hints.append("- If this is a crackme, look for comparison functions and encoded constants.")

    return hints