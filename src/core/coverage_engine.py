from typing import List, Dict, Any
from collections import defaultdict

class CoverageEngine:
    """Compute simple ATT&CK coverage metrics."""

    def build_coverage(self, mappings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Input: list of {rule_name, platform, techniques: [{id, name, confidence}]}
        Output: coverage summary.
        """
        technique_to_rules: Dict[str, List[str]] = defaultdict(list)
        technique_meta: Dict[str, Dict[str, Any]] = {}

        for m in mappings:
            rule_name = m.get("rule_name")
            for t in m.get("techniques", []):
                tid = t.get("id")
                if not tid:
                    continue
                technique_to_rules[tid].append(rule_name)
                technique_meta[tid] = {
                    "id": tid,
                    "name": t.get("name", ""),
                }

        coverage_list = []
        for tid, rules in technique_to_rules.items():
            coverage_list.append(
                {
                    "technique_id": tid,
                    "technique_name": technique_meta[tid]["name"],
                    "rule_count": len(rules),
                    "rules": rules,
                }
            )

        coverage_list.sort(key=lambda x: (-x["rule_count"], x["technique_id"]))

        return {
            "total_techniques_detected": len(coverage_list),
            "total_rules_mapped": len({r for v in technique_to_rules.values() for r in v}),
            "coverage": coverage_list,
        }
