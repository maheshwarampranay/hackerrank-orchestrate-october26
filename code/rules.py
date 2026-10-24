"""
Deletion rules and policy engine for Ghost Data Still Exists.
Parses deletion_rules.csv and maps data categories to required actions and operations.
"""

import csv
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

@dataclass
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str

class PolicyEngine:
    def __init__(self, rules_file: Path):
        self.rules_by_category: Dict[str, DeletionRule] = {}
        self.rules_by_id: Dict[str, DeletionRule] = {}
        self._load(rules_file)

    def _load(self, rules_file: Path):
        with open(rules_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rule = DeletionRule(
                    rule_id=r["rule_id"].strip(),
                    data_category=r["data_category"].strip(),
                    condition=r["condition"].strip(),
                    required_action=r["required_action"].strip()
                )
                self.rules_by_category[rule.data_category] = rule
                self.rules_by_id[rule.rule_id] = rule

    def get_action(self, category: str) -> str:
        rule = self.rules_by_category.get(category)
        if rule:
            return rule.required_action
        return "DELETE"

    def get_operations_for_category(self, category: str) -> Dict[str, Tuple[str, str]]:
        """
        Returns mapping of phase -> (operation, state) for the given category.
        """
        action = self.get_action(category)
        if action == "DELETE":
            return {
                "FINDING": ("REPORT_REMAINING_RECORD", "PRESENT"),
                "REMEDIATION": ("DELETE_RECORD", "ABSENT"),
                "VERIFICATION": ("VERIFY_RECORD_ABSENT", "ABSENT"),
            }
        elif action == "REDACT":
            return {
                "FINDING": ("REPORT_EXPOSED_PII", "PRESENT"),
                "REMEDIATION": ("REDACT_RECORD", "REDACTED"),
                "VERIFICATION": ("VERIFY_RECORD_REDACTED", "REDACTED"),
            }
        elif action == "ANONYMIZE":
            return {
                "FINDING": ("REPORT_EXPOSED_PII", "PRESENT"),
                "REMEDIATION": ("ANONYMIZE_RECORD", "ANONYMIZED"),
                "VERIFICATION": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
            }
        elif action == "RETAIN":
            if category == "BACKUP_ARCHIVE":
                return {
                    "FINDING": ("REPORT_RESTORE_RISK", "ACTIVE"),
                    "REMEDIATION": ("BLOCK_RESTORE", "BLOCKED"),
                    "VERIFICATION": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
                }
            return {
                "VERIFICATION": ("VERIFY_RECORD_PRESENT", "PRESENT"),
            }
        return {
            "FINDING": ("REPORT_REMAINING_RECORD", "PRESENT"),
            "REMEDIATION": ("DELETE_RECORD", "ABSENT"),
            "VERIFICATION": ("VERIFY_RECORD_ABSENT", "ABSENT"),
        }
