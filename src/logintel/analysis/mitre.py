MITRE_BY_EVENT = {
    "authentication_failure": ["T1110 - Brute Force"],
    "web_access": ["T1190 - Exploit Public-Facing Application"],
}

MITRE_BY_KEYWORD = {
    "powershell": ["T1059.001 - PowerShell"],
    "mimikatz": ["T1003 - OS Credential Dumping"],
    "encoded": ["T1027 - Obfuscated Files or Information"],
}


def map_mitre(event_type: str, message: str) -> list[str]:
    techniques = set(MITRE_BY_EVENT.get(event_type, []))
    lower = message.lower()
    for keyword, mapped in MITRE_BY_KEYWORD.items():
        if keyword in lower:
            techniques.update(mapped)
    return sorted(techniques)
