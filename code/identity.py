"""
Identity resolution module for Ghost Data Still Exists.
Resolves user identifiers across current identities and audit logs.
Computes normalized emails, phones, names, and SHA-256 email hashes.
"""

import csv
import hashlib
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Set, Optional, List, Tuple

def normalize_email(email: Optional[str]) -> str:
    if not email:
        return ""
    return email.strip().lower()

def normalize_phone(phone: Optional[str]) -> str:
    if not phone:
        return ""
    # Strip non-digits except leading +
    s = phone.strip()
    digits = re.sub(r"[^\d+]", "", s)
    return digits

def normalize_name(name: Optional[str]) -> str:
    if not name:
        return ""
    return " ".join(name.strip().split())

def sha256_hash(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest().lower()

@dataclass
class UserIdentity:
    user_id: str
    current_name: str
    current_email: str
    current_phone: str
    current_email_hash: str
    updated_at: str
    
    # Historical and all variants
    all_names: Set[str] = field(default_factory=set)
    all_emails: Set[str] = field(default_factory=set)
    all_phones: Set[str] = field(default_factory=set)
    all_hashes: Set[str] = field(default_factory=set)
    audit_history: List[Dict[str, str]] = field(default_factory=list)

    def matches(self, val: Optional[str]) -> bool:
        if not val:
            return False
        v_raw = val.strip()
        v_lower = v_raw.lower()
        if v_lower in self.all_emails:
            return True
        if v_lower in self.all_hashes:
            return True
        if v_raw in self.all_names or v_lower in {n.lower() for n in self.all_names}:
            return True
        norm_p = normalize_phone(v_raw)
        if norm_p and norm_p in {normalize_phone(p) for p in self.all_phones}:
            return True
        if v_raw == self.user_id:
            return True
        return False

class IdentityResolver:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.users_by_id: Dict[str, UserIdentity] = {}
        self.email_to_user_id: Dict[str, str] = {}
        self.phone_to_user_id: Dict[str, str] = {}
        self.hash_to_user_id: Dict[str, str] = {}
        self._load()

    def _load(self):
        # 1. Load user_identities.csv
        identities_path = self.data_dir / "user_identities.csv"
        with open(identities_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                uid = r["user_id"].strip()
                email = normalize_email(r["email"])
                phone = r["phone"].strip()
                name = normalize_name(r["name"])
                ehash = r["email_hash"].strip().lower()

                u = UserIdentity(
                    user_id=uid,
                    current_name=name,
                    current_email=email,
                    current_phone=phone,
                    current_email_hash=ehash,
                    updated_at=r["updated_at"].strip()
                )
                u.all_names.add(name)
                u.all_emails.add(email)
                u.all_phones.add(phone)
                u.all_hashes.add(ehash)
                u.all_hashes.add(sha256_hash(email))

                self.users_by_id[uid] = u
                self.email_to_user_id[email] = uid
                if phone:
                    self.phone_to_user_id[normalize_phone(phone)] = uid
                if ehash:
                    self.hash_to_user_id[ehash] = uid

        # 2. Load user_audit_log.csv
        audit_path = self.data_dir / "user_audit_log.csv"
        if audit_path.exists():
            with open(audit_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = sorted(reader, key=lambda x: x["event_time"])
                for r in rows:
                    uid = r["user_id"].strip()
                    if uid not in self.users_by_id:
                        continue
                    u = self.users_by_id[uid]
                    field_name = r["field_name"].strip()
                    old_v = r["old_value"].strip()
                    new_v = r["new_value"].strip()
                    u.audit_history.append(r)

                    if field_name == "email":
                        old_e = normalize_email(old_v)
                        new_e = normalize_email(new_v)
                        if old_e:
                            u.all_emails.add(old_e)
                            u.all_hashes.add(sha256_hash(old_e))
                            self.email_to_user_id[old_e] = uid
                        if new_e:
                            u.all_emails.add(new_e)
                            u.all_hashes.add(sha256_hash(new_e))
                            self.email_to_user_id[new_e] = uid
                    elif field_name == "phone":
                        if old_v:
                            u.all_phones.add(old_v)
                            self.phone_to_user_id[normalize_phone(old_v)] = uid
                        if new_v:
                            u.all_phones.add(new_v)
                            self.phone_to_user_id[normalize_phone(new_v)] = uid
                    elif field_name == "name":
                        if old_v:
                            u.all_names.add(normalize_name(old_v))
                        if new_v:
                            u.all_names.add(normalize_name(new_v))

    def resolve(self, email: str) -> Optional[UserIdentity]:
        norm_e = normalize_email(email)
        uid = self.email_to_user_id.get(norm_e)
        if uid:
            return self.users_by_id.get(uid)
        return None

    def get_by_id(self, user_id: str) -> Optional[UserIdentity]:
        return self.users_by_id.get(user_id)
