import re
from typing import Dict, List
from src.utils.logger import get_logger

logger = get_logger(__name__)

class RuleParser:
    """Lightweight parser for SIEM rules (KQL/SPL/or generic)."""

    def parse(self, name: str, query: str, platform: str) -> Dict:
        indicators = self._extract_indicators(query)
        data_sources = self._guess_data_sources(query, platform)
        description = self._build_description(indicators)

        return {
            "name": name,
            "platform": platform.lower(),
            "query": query,
            "indicators": indicators,
            "data_sources": data_sources,
            "description": description,
        }

    def _extract_indicators(self, text: str) -> Dict[str, List[str]]:
        indicators: Dict[str, List[str]] = {
            "processes": [],
            "commands": [],
            "ips": [],
            "domains": [],
            "registry": [],
        }

        proc_pattern = r"\b[\w\-]+\.exe\b"
        indicators["processes"] = list(set(re.findall(proc_pattern, text, re.IGNORECASE)))

        cmd_keywords = [
            "encodedcommand",
            "-enc",
            "invoke-expression",
            "downloadstring",
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "wmic",
            "reg.exe",
        ]
        indicators["commands"] = [k for k in cmd_keywords if k.lower() in text.lower()]

        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        indicators["ips"] = list(set(re.findall(ip_pattern, text)))

        domain_pattern = r"\b[a-zA-Z0-9.-]+\.(com|net|org|io|ru|cn|xyz)\b"
        indicators["domains"] = list(set(re.findall(domain_pattern, text)))

        reg_pattern = r"HKLM\\[^\s\"]+|HKCU\\[^\s\"]+"
        indicators["registry"] = list(set(re.findall(reg_pattern, text, re.IGNORECASE)))

        return indicators

    def _guess_data_sources(self, text: str, platform: str) -> List[str]:
        sources: List[str] = []
        t = text.lower()

        if "deviceprocessevents" in t or "process_creation" in t or "process" in t:
            sources.append("Process Creation")
        if "devicenetworkevents" in t or "network" in t:
            sources.append("Network Traffic")
        if "devicefileevents" in t or "file" in t:
            sources.append("File Events")
        if "deviceregistryevents" in t or "registry" in t:
            sources.append("Registry")

        if platform.lower() == "splunk":
            if "index=wineventlog" in t:
                sources.append("Windows Event Logs")

        return list(set(sources))

    def _build_description(self, indicators: Dict[str, List[str]]) -> str:
        parts: List[str] = []
        if indicators["processes"]:
            parts.append(f"Monitors processes: {', '.join(indicators['processes'][:3])}")
        if indicators["commands"]:
            parts.append(f"Suspicious commands: {', '.join(indicators['commands'][:3])}")
        if indicators["ips"]:
            parts.append("Matches specific IP addresses")
        if indicators["domains"]:
            parts.append("Matches specific domains")
        if not parts:
            return "Detects potentially suspicious activity based on query logic."
        return " ".join(parts)
