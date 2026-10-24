"""
Evidence indexing module for Ghost Data Still Exists.
Parses all evidence files (databases, json records, text handovers, logs, and multimodal cache).
Provides query API to retrieve records relevant to a user as of audit_at.
"""

import os
import re
import csv
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any

@dataclass
class EvidenceRecord:
    evidence_id: str
    captured_at: str
    system_id: str
    resource_id: str
    category: str
    state: str  # PRESENT, ABSENT, IDENTIFIABLE, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    user_identifiers: Set[str] = field(default_factory=set)
    details: Dict[str, Any] = field(default_factory=dict)

class EvidenceIndex:
    def __init__(self, dataset_dir: Path, cache_file: Optional[Path] = None):
        self.dataset_dir = dataset_dir
        self.cache_file = cache_file or (Path(__file__).parent / "extracted_cache.json")
        self.manifest: Dict[str, Dict[str, str]] = {} # file_id -> row
        self.path_to_file_id: Dict[str, str] = {} # rel_path -> file_id
        self.records: List[EvidenceRecord] = []
        self._load_manifest()
        self._parse_all()

    def _load_manifest(self):
        manifest_path = self.dataset_dir / "evidence_files.csv"
        with open(manifest_path, "r", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                fid = r["file_id"].strip()
                fpath = r["file_path"].strip().replace("\\", "/")
                self.manifest[fid] = {
                    "file_id": fid,
                    "file_path": fpath,
                    "origin": r["origin"].strip(),
                    "captured_at": r["captured_at"].strip()
                }
                self.path_to_file_id[fpath] = fid
                # Also without 'evidence/' prefix
                if fpath.startswith("evidence/"):
                    self.path_to_file_id[fpath[len("evidence/"):]] = fid

    def _parse_all(self):
        self._parse_text_handover()
        self._parse_multimodal_cache()
        self._parse_json_records()
        self._parse_sql_databases()
        self._parse_log_files()

    def _parse_text_handover(self):
        txt_path = self.dataset_dir / "evidence" / "records" / "customer_account_handover_20261001.txt"
        if not txt_path.exists():
            return
        fid = self.path_to_file_id.get("evidence/records/customer_account_handover_20261001.txt", "evidence_03")
        cap_at = self.manifest[fid]["captured_at"]

        with open(txt_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("-"):
                    continue
                # - 2026-10-01T12:00:00Z | account_service | account_146 | USER_PROFILE | NOT_FOUND | e.lindberg18@yahoo.com
                parts = [p.strip() for p in line[1:].split("|")]
                if len(parts) >= 6:
                    ts, system_id, resource_id, category, status, ident = parts[:6]
                    state = "PRESENT"
                    if status == "NOT_FOUND":
                        state = "ABSENT"
                    elif status == "IDENTIFIABLE":
                        state = "IDENTIFIABLE"
                    elif status == "ANONYMIZED":
                        state = "ANONYMIZED"
                    elif status == "REDACTED":
                        state = "REDACTED"
                    elif status == "FOUND":
                        state = "PRESENT"
                    elif status == "ACTIVE":
                        state = "ACTIVE"
                    elif status == "DISABLED":
                        state = "DISABLED"
                    elif status == "BLOCKED":
                        state = "BLOCKED"

                    idents = set()
                    if ident and ident != "no direct identifier":
                        idents.add(ident.strip().lower())

                    self.records.append(EvidenceRecord(
                        evidence_id=fid,
                        captured_at=cap_at,
                        system_id=system_id,
                        resource_id=resource_id,
                        category=category,
                        state=state,
                        user_identifiers=idents,
                        details={"raw_line": line}
                    ))

    def _parse_multimodal_cache(self):
        if not self.cache_file or not self.cache_file.exists():
            return
        with open(self.cache_file, "r", encoding="utf-8") as f:
            cache = json.load(f)

        for rel_path, img_data in cache.get("images", {}).items():
            fid = img_data.get("file_id")
            if not fid:
                fid = self.path_to_file_id.get(rel_path, "")
            cap_at = self.manifest.get(fid, {}).get("captured_at", "")
            system_id = img_data.get("system_id", "")

            for rec in img_data.get("records", []):
                res_id = rec.get("resource_id", "")
                cat = rec.get("type", "")
                st = rec.get("status", "PRESENT")
                idents = set()
                for k in ["user_id", "email", "phone"]:
                    v = rec.get(k)
                    if v:
                        idents.add(v.strip().lower())

                self.records.append(EvidenceRecord(
                    evidence_id=fid,
                    captured_at=cap_at,
                    system_id=system_id,
                    resource_id=res_id,
                    category=cat,
                    state=st,
                    user_identifiers=idents,
                    details=rec
                ))

        for rel_path, doc_data in cache.get("documents", {}).items():
            fid = self.path_to_file_id.get(rel_path, "")
            cap_at = self.manifest.get(fid, {}).get("captured_at", "")
            txt = doc_data.get("text", "")
            # Look for resource IDs or mentions
            m_res = re.findall(r"(support_\d+|audit_record_\d+|account_\d+|ORD-\d+|user_\d+)", txt)
            idents = set(m_res)
            # Find emails
            emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", txt)
            idents.update(e.lower() for e in emails)

            # Determine system_id and category
            if "delivery_correction" in rel_path or "support_001" in txt:
                sys_id = "support_platform"
                cat = "SUPPORT_ATTACHMENT"
                res_id = "support_001"
            elif "support_" in txt:
                sys_id = "support_platform"
                cat = "SUPPORT_MESSAGE"
                res_id = ""
                for r in m_res:
                    if r.startswith("support_"):
                        res_id = r
                        break
            else:
                sys_id = "security_service"
                cat = "SECURITY_AUDIT_LOG"
                res_id = ""
                for r in m_res:
                    if r.startswith("audit_record_") or r.startswith("account_"):
                        res_id = r
                        break

            if res_id:
                self.records.append(EvidenceRecord(
                    evidence_id=fid,
                    captured_at=cap_at,
                    system_id=sys_id,
                    resource_id=res_id,
                    category=cat,
                    state="PRESENT",
                    user_identifiers=idents,
                    details={"file_name": doc_data.get("file_name")}
                ))

    def _parse_json_records(self):
        records_dir = self.dataset_dir / "evidence" / "records"
        for p in records_dir.glob("*.json"):
            rel_path = f"evidence/records/{p.name}"
            fid = self.path_to_file_id.get(rel_path, "")
            cap_at = self.manifest.get(fid, {}).get("captured_at", "")
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue

            # Case A: snapshot bundle
            if "snapshots" in data and isinstance(data["snapshots"], list):
                for sn in data["snapshots"]:
                    sys_id = sn.get("data_store", "")
                    for rec in sn.get("records", []):
                        res_id = rec.get("resource_id", "")
                        # Determine category and state
                        cat = "USER_PROFILE"
                        state = "PRESENT"
                        if sys_id == "identity_service":
                            cat = "ACCOUNT_TOMBSTONE"
                            # Check if PII is null
                            if not rec.get("name") and not rec.get("email") and not rec.get("phone") and not rec.get("email_hash"):
                                state = "REDACTED"
                            else:
                                state = "IDENTIFIABLE"
                        elif sys_id == "security_service":
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"
                        elif sys_id == "account_service":
                            cat = "USER_PROFILE"
                            state = "PRESENT"

                        idents = set()
                        for k in ["subject_reference", "user_id", "email", "phone", "email_hash", "name"]:
                            v = rec.get(k)
                            if v: idents.add(str(v).strip().lower())

                        self.records.append(EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap_at,
                            system_id=sys_id,
                            resource_id=res_id,
                            category=cat,
                            state=state,
                            user_identifiers=idents,
                            details=rec
                        ))

            # Case B: service_exports
            elif "service_exports" in data and isinstance(data["service_exports"], dict):
                for sys_id, sdata in data["service_exports"].items():
                    for subk, items in sdata.items():
                        if not isinstance(items, list):
                            continue
                        for it in items:
                            res_id = it.get("resource_id", "")
                            idents = set()
                            for k in ["customer_reference", "subject_reference", "user_id", "customer_email", "owner_email", "email", "phone", "owner_phone", "query", "requester_email", "requester_name", "requester_phone"]:
                                v = it.get(k)
                                if v: idents.add(str(v).strip().lower())

                            if "profile" in it and isinstance(it["profile"], dict):
                                for pk in ["customer_reference", "subject_reference", "user_id", "email", "phone", "email_hash", "full_name"]:
                                    pv = it["profile"].get(pk)
                                    if pv: idents.add(str(pv).strip().lower())

                            # Extract hits from search queries
                            if "hits" in it and isinstance(it["hits"], dict):
                                for doc in it["hits"].get("documents", []):
                                    for dk in ["email", "customer_reference", "phone", "email_hash"]:
                                        dv = doc.get(dk)
                                        if dv: idents.add(str(dv).strip().lower())

                            # Determine state & category
                            cat = "USER_PROFILE"
                            state = "PRESENT"
                            if sys_id == "account_service":
                                cat = "USER_PROFILE"
                                state = "ABSENT" if it.get("status_code") == 404 or it.get("profile") is None else "PRESENT"
                            elif sys_id == "analytics_platform":
                                cat = "ANALYTICS_PROFILE"
                                if not it.get("email") and not it.get("phone") and not it.get("customer_reference") and not it.get("email_hash"):
                                    state = "ANONYMIZED"
                                else:
                                    state = "IDENTIFIABLE"
                            elif sys_id == "backup_service":
                                cat = "BACKUP_ARCHIVE"
                                state = "BLOCKED" if it.get("restore_allowed") is False else "ACTIVE"
                            elif sys_id == "export_service":
                                cat = "USER_EXPORT"
                                state = "PRESENT"
                            elif sys_id == "integration_service":
                                cat = "DATA_FLOW"
                                state = "DISABLED" if it.get("enabled") is False else "ACTIVE"
                            elif sys_id == "search_service":
                                cat = "SEARCH_INDEX_ENTRY"
                                total = it.get("hits", {}).get("total", 0)
                                state = "PRESENT" if total > 0 else "ABSENT"
                            elif sys_id == "security_service":
                                cat = "SECURITY_AUDIT_LOG"
                                state = "PRESENT"
                            elif sys_id == "support_platform":
                                cat = "SUPPORT_MESSAGE"
                                if not it.get("requester_email") and not it.get("requester_name") and not it.get("requester_phone"):
                                    state = "REDACTED"
                                else:
                                    state = "IDENTIFIABLE"

                            self.records.append(EvidenceRecord(
                                evidence_id=fid,
                                captured_at=cap_at,
                                system_id=sys_id,
                                resource_id=res_id,
                                category=cat,
                                state=state,
                                user_identifiers=idents,
                                details=it
                            ))

            # Case C: generic records list (manifests, analytics, export jobs, audit logs)
            elif "records" in data and isinstance(data["records"], list):
                for it in data["records"]:
                    res_id = it.get("resource_id", it.get("export_id", ""))
                    idents = set()
                    for k in ["subject_reference", "owner_email", "customer_reference", "user_id", "email", "phone", "email_hash"]:
                        v = it.get(k)
                        if v:
                            idents.add(str(v).strip().lower())

                    # Check if this is a manifest record (e.g. connector_configurations, export_manifest, security_audit_ledger)
                    if "system" in it and "result" in it:
                        sys_id = it.get("system", "")
                        rec_type = it.get("record_type", "USER_PROFILE")
                        res_state = "ABSENT" if it.get("result") == "NOT_FOUND" else "PRESENT"
                        self.records.append(EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap_at,
                            system_id=sys_id,
                            resource_id=res_id,
                            category=rec_type,
                            state=res_state,
                            user_identifiers=idents,
                            details=it
                        ))
                    elif "file_name" in it or "customer_export" in str(data.get("collection", "")) or "export" in res_id:
                        sys_id = "export_service"
                        cat = "USER_EXPORT"
                        self.records.append(EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap_at,
                            system_id=sys_id,
                            resource_id=res_id,
                            category=cat,
                            state="PRESENT",
                            user_identifiers=idents,
                            details=it
                        ))
                    else:
                        # Analytics or profile record
                        sys_id = it.get("system_id", data.get("source_system", "analytics_platform"))
                        cat = "ANALYTICS_PROFILE" if (sys_id == "analytics_platform" or "analytics" in res_id) else "USER_PROFILE"
                        state = "ANONYMIZED" if not it.get("email") and not it.get("phone") and not it.get("user_id") and not it.get("customer_reference") else "IDENTIFIABLE"
                        self.records.append(EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap_at,
                            system_id=sys_id,
                            resource_id=res_id,
                            category=cat,
                            state=state,
                            user_identifiers=idents,
                            details=it
                        ))

    def _parse_sql_databases(self):
        db_dir = self.dataset_dir / "evidence" / "databases"
        for p in db_dir.glob("*.sql"):
            rel_path = f"evidence/databases/{p.name}"
            fid = self.path_to_file_id.get(rel_path, "")
            cap_at = self.manifest.get(fid, {}).get("captured_at", "")

            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Look for INSERT INTO statements
            # INSERT INTO "customer_data_primary" VALUES('analytics_1738','analytics_platform','customer_analytics_reports','{...}','2026-09-21T10:00:00Z');
            # Or INSERT INTO backup_restore_entries VALUES ('backup_4978', NULL, 'k.appiah88@gmail.com', 'archive/customer-data/backup_4978.tar.zst', '1', '2026-09-16T07:59:54Z');
            for line in content.splitlines():
                line = line.strip()
                if not line.startswith("INSERT INTO"):
                    continue

                m_ins = re.match(r"INSERT\s+INTO\s+[\"']?([a-zA-Z0-9_]+)[\"']?\s+VALUES\s*\((.+)\);?", line, re.IGNORECASE)
                if not m_ins:
                    continue
                table_name = m_ins.group(1)
                vals_str = m_ins.group(2)

                # Check if JSON payload is present
                json_match = re.search(r"(\{.*\})", vals_str)
                if json_match:
                    try:
                        rec_json = json.loads(json_match.group(1))
                        res_id = rec_json.get("resource_id", "")
                        sys_id = rec_json.get("origin_system", "")
                        if not sys_id:
                            # Parse from table or fields
                            if "analytics" in res_id: sys_id = "analytics_platform"
                            elif "audit_record" in res_id: sys_id = "security_service"
                            elif "account" in res_id: sys_id = "account_service"
                            elif "search" in res_id: sys_id = "search_service"
                            elif "support" in res_id: sys_id = "support_platform"
                            else: sys_id = "account_service"

                        idents = set()
                        for k in ["user_id", "subject_reference", "customer_reference", "email", "phone", "email_hash"]:
                            v = rec_json.get(k)
                            if v: idents.add(str(v).strip().lower())

                        for sub_k in ["document", "profile", "data", "payload"]:
                            sub = rec_json.get(sub_k)
                            if isinstance(sub, dict):
                                for k in ["user_id", "subject_reference", "customer_reference", "email", "phone", "email_hash"]:
                                    v = sub.get(k)
                                    if v: idents.add(str(v).strip().lower())

                        cat = "USER_PROFILE"
                        state = "PRESENT"
                        if sys_id == "analytics_platform":
                            cat = "ANALYTICS_PROFILE"
                            state = "ANONYMIZED" if not rec_json.get("email") and not rec_json.get("phone") and not rec_json.get("user_id") else "IDENTIFIABLE"
                        elif sys_id == "security_service":
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"
                        elif sys_id == "search_service":
                            cat = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"
                        elif sys_id == "support_platform":
                            cat = "SUPPORT_MESSAGE"
                            state = "IDENTIFIABLE" if rec_json.get("email") or rec_json.get("phone") else "REDACTED"
                        elif sys_id == "identity_service":
                            cat = "ACCOUNT_TOMBSTONE"
                            state = "REDACTED" if not rec_json.get("email") and not rec_json.get("phone") and not rec_json.get("email_hash") else "IDENTIFIABLE"

                        self.records.append(EvidenceRecord(
                            evidence_id=fid,
                            captured_at=cap_at,
                            system_id=sys_id,
                            resource_id=res_id,
                            category=cat,
                            state=state,
                            user_identifiers=idents,
                            details=rec_json
                        ))
                    except Exception:
                        pass
                else:
                    # Non-JSON SQL tables: e.g. backup_restore_entries, customer_exports, etc.
                    # VALUES ('backup_4978', NULL, 'k.appiah88@gmail.com', '...', '1', '...')
                    parts = [p.strip().strip("'\"") for p in vals_str.split(",")]
                    res_id = parts[0]
                    idents = set()
                    for p in parts[1:]:
                        if "@" in p or p.startswith("user_"):
                            idents.add(p.lower())

                    sys_id = "backup_service" if "backup" in res_id else ("export_service" if "export" in res_id else "account_service")
                    cat = "BACKUP_ARCHIVE" if sys_id == "backup_service" else ("USER_EXPORT" if sys_id == "export_service" else "USER_PROFILE")
                    state = "ACTIVE" if sys_id == "backup_service" else "PRESENT"

                    self.records.append(EvidenceRecord(
                        evidence_id=fid,
                        captured_at=cap_at,
                        system_id=sys_id,
                        resource_id=res_id,
                        category=cat,
                        state=state,
                        user_identifiers=idents,
                        details={"table": table_name, "raw_values": vals_str}
                    ))

    def _parse_log_files(self):
        log_dir = self.dataset_dir / "evidence" / "logs"
        for p in log_dir.glob("*.log"):
            rel_path = f"evidence/logs/{p.name}"
            fid = self.path_to_file_id.get(rel_path, "")
            cap_at = self.manifest.get(fid, {}).get("captured_at", "")

            try:
                lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            # Track by trace_id within the log file to correlate lookup_key with completed events
            traces: Dict[str, Dict[str, Any]] = {}

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Try JSON log format
                json_match = re.search(r"(\{.*\})", line)
                if json_match:
                    try:
                        data = json.loads(json_match.group(1))
                        tr_id = data.get("trace_id", data.get("requestId", ""))
                        if tr_id:
                            if tr_id not in traces:
                                traces[tr_id] = {"idents": set(), "events": []}
                            for k in ["lookup_key", "subject_ref", "subject_reference", "customer_reference", "correlation_key", "subject_key", "email", "requester_email", "customer_email", "user_id"]:
                                v = data.get(k)
                                if v and v != "null":
                                    traces[tr_id]["idents"].add(str(v).strip().lower().strip("'\""))
                            traces[tr_id]["events"].append(data)
                    except Exception:
                        pass
                else:
                    # Key=value or bracket format
                    tr_match = re.search(r"trace_id=([a-zA-Z0-9_-]+)|\[(tr-[a-zA-Z0-9_-]+)\]", line)
                    if tr_match:
                        tr_id = tr_match.group(1) or tr_match.group(2)
                        if tr_id not in traces:
                            traces[tr_id] = {"idents": set(), "events": []}
                        
                        for m_key in re.finditer(r'(?:lookup_key|customer_ref|customer_reference|subject_ref|subject_reference|correlation_key|subject_key|email|requester_email|customer_email|user_id)=["\']?([^"\'\s]+)["\']?', line):
                            val = m_key.group(1).strip().strip("'\"")
                            if val and val != "null":
                                traces[tr_id]["idents"].add(val.lower())
                        traces[tr_id]["events"].append({"raw_line": line})

            # Process collected traces
            for tr_id, tr_data in traces.items():
                idents = tr_data["idents"]
                if not idents:
                    continue

                for ev in tr_data["events"]:
                    raw = ev.get("raw_line", "")
                    ev_type = ev.get("event", "") or (re.search(r"event=([a-zA-Z0-9_]+)", raw).group(1) if raw and "event=" in raw else "")
                    if ev_type.endswith("_started"):
                        continue

                    res_id = ev.get("resource_id", "")
                    if not res_id and raw:
                        m_res = re.search(r"resource_id=([a-zA-Z0-9_]+)", raw)
                        if m_res: res_id = m_res.group(1)

                    if not res_id:
                        continue

                    sys_id = ev.get("service", ev.get("logger", ""))
                    if not sys_id and raw:
                        m_sys = re.search(r"service=([a-zA-Z0-9_]+)|\[([a-zA-Z0-9_]+)\]", raw)
                        if m_sys:
                            sys_id = m_sys.group(1) or m_sys.group(2)
                    if sys_id:
                        if "account" in sys_id: sys_id = "account_service"
                        elif "search" in sys_id: sys_id = "search_service"
                        elif "support" in sys_id: sys_id = "support_platform"
                        elif "analytics" in sys_id: sys_id = "analytics_platform"
                        elif "integration" in sys_id or "data_flow" in sys_id or "connector" in sys_id: sys_id = "integration_service"
                        elif "backup" in sys_id: sys_id = "backup_service"
                        elif "security" in sys_id or "audit" in sys_id: sys_id = "security_service"
                        elif "identity" in sys_id: sys_id = "identity_service"
                    if not sys_id:
                        if "account" in res_id: sys_id = "account_service"
                        elif "search" in res_id: sys_id = "search_service"
                        elif "support" in res_id: sys_id = "support_platform"
                        elif "analytics" in res_id: sys_id = "analytics_platform"
                        elif "data_flow" in res_id: sys_id = "integration_service"
                        elif "backup" in res_id: sys_id = "backup_service"
                        elif "audit_record" in res_id: sys_id = "security_service"
                        else: sys_id = "account_service"

                    # Determine state & category
                    cat = "USER_PROFILE"
                    state = "PRESENT"
                    if sys_id == "account_service":
                        cat = "USER_PROFILE"
                        state = "ABSENT" if "404" in str(ev) or "404" in raw or "rows=0" in raw or ev.get("rows") == "0" else "PRESENT"
                    elif sys_id == "analytics_platform":
                        if "contact_lookup" in raw or ev.get("event") == "contact_lookup_completed":
                            cat = "SECONDARY_IDENTIFIER"
                            state = "PRESENT" if "rows=1" in raw or ev.get("rows") == "1" or ev.get("rows") == 1 else "ABSENT"
                        else:
                            cat = "ANALYTICS_PROFILE"
                            if "email=null" in raw or (not ev.get("email") and not ev.get("phone")):
                                state = "ANONYMIZED"
                            else:
                                state = "IDENTIFIABLE"
                    elif sys_id == "support_platform":
                        cat = "SUPPORT_MESSAGE"
                        if "marker_found=false" in raw or "rows=1" in raw or ev.get("rows") == "1" or ev.get("rows") == 1:
                            state = "PRESENT"
                        elif "requester_email=null" in raw or (not ev.get("requester_email") and not ev.get("requester_name")):
                            state = "REDACTED"
                        else:
                            state = "IDENTIFIABLE"
                    elif sys_id == "integration_service":
                        cat = "DATA_FLOW"
                        state = "ACTIVE" if "enabled=true" in raw or ev.get("enabled") is True else "DISABLED"
                    elif sys_id == "backup_service":
                        cat = "BACKUP_ARCHIVE"
                        if "restore_allowed=true" in raw or ev.get("restore_allowed") is True:
                            state = "ACTIVE"
                        elif "eligible=true" in raw and ("deletion_block=false" in raw or ev.get("deletion_block") is False):
                            state = "ACTIVE"
                        elif "deletion_block=true" in raw or ev.get("deletion_block") is True or "restore_allowed=false" in raw:
                            state = "BLOCKED"
                        else:
                            state = "BLOCKED"
                    elif sys_id == "search_service":
                        cat = "SEARCH_INDEX_ENTRY"
                        state = "PRESENT" if "total_hits=1" in raw or "result=hit" in raw or ev.get("total_hits", 0) > 0 else "ABSENT"
                    elif sys_id == "security_service":
                        cat = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"

                    self.records.append(EvidenceRecord(
                        evidence_id=fid,
                        captured_at=cap_at,
                        system_id=sys_id,
                        resource_id=res_id,
                        category=cat,
                        state=state,
                        user_identifiers=set(idents),
                        details={"trace_id": tr_id, "event": ev}
                    ))

    def query_user(self, user_identifiers: Set[str], audit_at: str) -> List[EvidenceRecord]:
        """
        Query all evidence records matching any of the user's identifiers captured at or before audit_at.
        """
        results = []
        norm_idents = {i.lower() for i in user_identifiers if i}
        for rec in self.records:
            if rec.captured_at > audit_at:
                continue
            # Check identifier intersection
            if rec.user_identifiers and (rec.user_identifiers & norm_idents):
                results.append(rec)
        return results
