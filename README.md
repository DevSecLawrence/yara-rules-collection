# YARA Rules Collection
 
![YARA](https://img.shields.io/badge/YARA-4.5.5-green?style=flat)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=flat&logo=kalilinux&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat)
![Malware Detection](https://img.shields.io/badge/Malware-Detection-orange?style=flat)
 
Original YARA rules written and tested in Kali Linux as part of my 180-day SOC analyst roadmap (Day 22). Each rule includes the detection logic, what it targets, how I tested it, and known limitations.
 
YARA is a pattern-matching tool for files — where Sigma detects suspicious events in logs, YARA detects suspicious content in files. These rules were written from scratch, not copied from existing repos.
 
---
 
## Rules
 
### Rule 1 — Suspicious Strings
**File:** `suspicious_strings.yar`
**Detects:** Files containing references to cmd.exe or powershell.exe
**Use case:** Flagging scripts and droppers that reference Windows shells
**Tested against:** Plain text file containing "powershell.exe" (match) and clean text file (no match)
 
```yara
rule suspicious_strings {
    meta:
        description = "Detects files referencing cmd.exe or powershell.exe"
        author = "Lawrence"
        date = "2026-06-05"
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell.exe" nocase
    condition:
        any of them
}
```
 
**Known limitation:** High false positive rate — many legitimate installers and admin scripts reference these binaries. Works best combined with other conditions or used for initial triage, not definitive detection.
 
---
 
### Rule 2 — High Entropy
**File:** `high_entropy.yar`
**Detects:** Files with entropy above 7.0 — possible packing or encryption
**Use case:** Flagging packed malware, encrypted payloads, obfuscated scripts
**Tested against:** Zip file (match — compressed = high entropy) and plain text (no match)
 
```yara
import "math"
rule high_entropy_file {
    meta:
        description = "Flags files with entropy above 7.0 — possible packing or encryption"
        author = "Lawrence"
        date = "2026-06-05"
    condition:
        math.entropy(0, filesize) > 7.0
}
```
 
**Known limitation:** Legitimate compressed files (zip, jar, docx) also trigger this rule. The 7.0 threshold needs tuning against a baseline of known-clean binaries before deploying in production.
 
---
 
### Rule 3 — UPX PE Sections
**File:** `unusual_pe_sections.yar`
**Detects:** Binaries packed with UPX by looking for .upx0 and .upx1 section names
**Use case:** Identifying packed executables — packers are commonly used to evade AV
**Tested against:** UPX-packed copy of /usr/bin/whoami (match) and original binary (no match)
 
```yara
import "pe"
rule unusual_pe_sections {
    meta:
        description = "Detects binaries packed with UPX by PE section name"
        author = "Lawrence"
        date = "2026-06-05"
    condition:
        pe.is_pe and
        for any i in (0 .. pe.number_of_sections - 1) : (
            pe.sections[i].name == ".upx0" or
            pe.sections[i].name == ".upx1" or
            pe.sections[i].name == ".packed"
        )
}
```
 
**Known limitation:** PE module targets Windows PE format. On Linux ELF binaries the pe.is_pe condition will not match. For ELF packed binaries, verify with `readelf -S binary | grep -i upx` instead.
 
---
 
## Testing Environment
 
- **OS:** Kali Linux (VM)
- **YARA version:** 4.5.5
- **Install:** `sudo apt install yara -y`
---
 
## Part of
 
[SOC Analyst Journey — 180-day roadmap](https://github.com/DevSecLawrence/soc-analyst-journey)