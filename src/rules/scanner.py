"""
YARA rule scanner for explainable malware detection.
"""
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    yara = None


@dataclass
class YaraMatch:
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, str]
    strings: List[Dict[str, Any]] = field(default_factory=list)


class YaraScanner:
    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or Path(__file__).parent
        self.compiled_rules = None
        self._compile_rules()

    def _compile_rules(self):
        if not HAS_YARA:
            print("Warning: yara-python not installed, YARA scanning disabled")
            return

        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        if not rule_files:
            print(f"Warning: No YARA rules found in {self.rules_dir}")
            return

        try:
            filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
            self.compiled_rules = yara.compile(filepaths=filepaths)
            print(f"Compiled {len(rule_files)} YARA rule files")
        except Exception as e:
            print(f"Error compiling YARA rules: {e}")
            self.compiled_rules = None

    def scan_file(self, filepath: Path) -> List[YaraMatch]:
        if not self.compiled_rules or not filepath.exists():
            return []

        try:
            matches = self.compiled_rules.match(str(filepath), timeout=30)
            results = []
            for match in matches:
                strings_found = []
                for s in match.strings:
                    strings_found.append({
                        'identifier': s.identifier,
                        'offset': s.instances[0].offset if s.instances else 0,
                        'matched_data': s.instances[0].matched_data[:100] if s.instances else b''
                    })
                results.append(YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings=strings_found
                ))
            return results
        except yara.TimeoutError:
            print(f"YARA scan timeout: {filepath}")
            return []
        except Exception as e:
            print(f"YARA scan error: {e}")
            return []

    def scan_bytes(self, data: bytes) -> List[YaraMatch]:
        if not self.compiled_rules:
            return []

        try:
            matches = self.compiled_rules.match(data=data, timeout=30)
            results = []
            for match in matches:
                strings_found = []
                for s in match.strings:
                    strings_found.append({
                        'identifier': s.identifier,
                        'offset': s.instances[0].offset if s.instances else 0,
                        'matched_data': s.instances[0].matched_data[:100] if s.instances else b''
                    })
                results.append(YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings=strings_found
                ))
            return results
        except Exception as e:
            print(f"YARA scan error: {e}")
            return []


def format_yara_results(matches: List[YaraMatch]) -> str:
    if not matches:
        return "No YARA rule matches"

    lines = [f"YARA Matches ({len(matches)}):", "-" * 50]
    for m in matches:
        severity = m.meta.get('severity', 'unknown')
        desc = m.meta.get('description', 'No description')
        lines.append(f"  [{severity.upper()}] {m.rule_name}")
        lines.append(f"       Description: {desc}")
        if m.strings:
            lines.append(f"       Strings matched: {len(m.strings)}")
            for s in m.strings[:3]:
                identifier = s['identifier']
                offset = s['offset']
                data = s['matched_data']
                if isinstance(data, bytes):
                    data = data.decode('ascii', errors='replace')
                lines.append(f"         ${identifier} @ 0x{offset:x}: {data[:50]}")
            if len(m.strings) > 3:
                lines.append(f"         ... and {len(m.strings) - 3} more")
        lines.append("")
    return "\n".join(lines)