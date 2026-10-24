import json
from pathlib import Path
import pdfplumber

def build_cache():
    cache = {
        "images": {},
        "documents": {}
    }

    # 1. account_admin_console_20260926.png (evidence_04)
    cache["images"]["evidence/images/account_admin_console_20260926.png"] = {
        "system_id": "account_service",
        "file_id": "evidence_04",
        "records": [
            {
                "resource_id": "account_5762",
                "user_id": "user_11",
                "name": "Haruka Sato",
                "email": "haruka.s1838@zoho.com",
                "phone": "+81 90 7610 2507",
                "email_hash": None,
                "status": "PRESENT",
                "type": "USER_PROFILE",
                "details": "Customer Operations portal shows active account_5762"
            },
            {
                "resource_id": "support_9538",
                "user_id": "user_11",
                "name": "Haruka Sato",
                "email": "haruka.s1838@zoho.com",
                "phone": "+81 90 7610 2507",
                "status": "PRESENT",
                "type": "SUPPORT_MESSAGE",
                "ticket_id": "CS-8538"
            }
        ]
    }

    # 2. analytics_profile_view_20260713.png (evidence_19)
    cache["images"]["evidence/images/analytics_profile_view_20260713.png"] = {
        "system_id": "analytics_platform",
        "file_id": "evidence_19",
        "records": [
            {
                "resource_id": "analytics_7438",
                "user_id": "user_20",
                "name": "Omar Darwish",
                "email": "darwish.omar@icloud.com",
                "phone": None,
                "email_hash": None,
                "status": "PRESENT",
                "type": "ANALYTICS_PROFILE",
                "details": "Pulse Analytics shows customer profile with exposed name and email"
            }
        ]
    }

    # 3. backup_restore_console_20260429.png (evidence_34)
    cache["images"]["evidence/images/backup_restore_console_20260429.png"] = {
        "system_id": "backup_service",
        "file_id": "evidence_34",
        "records": [
            {
                "resource_id": "backup_9287",
                "email": "areed1433@gmail.com",
                "status": "ACTIVE",
                "type": "BACKUP_ARCHIVE",
                "details": "Vault Recovery Manager shows active weekly backup with restore allowed"
            },
            {
                "resource_id": "backup_9291",
                "email": "bluepeakco@outlook.com",
                "status": "ACTIVE",
                "type": "BACKUP_ARCHIVE"
            }
        ]
    }

    # 4. connector_management_console_20260807.png (evidence_14)
    cache["images"]["evidence/images/connector_management_console_20260807.png"] = {
        "system_id": "integration_service",
        "file_id": "evidence_14",
        "records": [
            {
                "resource_id": "data_flow_1121",
                "email": "jain.aditi@gmail.com",
                "destination": "customer_analytics_warehouse",
                "status": "ACTIVE",
                "type": "DATA_FLOW",
                "details": "BridgeOps connector data_flow_1121 active/healthy continuous sync"
            },
            {
                "resource_id": "data_flow_9846",
                "email": "lucia-torres@gmail.com",
                "destination": "customer_analytics_warehouse",
                "status": "ACTIVE",
                "type": "DATA_FLOW"
            }
        ]
    }

    # 5. customer_export_console_20260618.png (evidence_23)
    cache["images"]["evidence/images/customer_export_console_20260618.png"] = {
        "system_id": "export_service",
        "file_id": "evidence_23",
        "records": [
            {
                "resource_id": "export_1260",
                "email": "ingrid.dahl@outlook.com",
                "status": "PRESENT",
                "type": "USER_EXPORT",
                "details": "Customer Download Center shows ready export package"
            }
        ]
    }

    # 6. deleted_account_reference_20260310.png (evidence_42)
    cache["images"]["evidence/images/deleted_account_reference_20260310.png"] = {
        "system_id": "identity_service",
        "file_id": "evidence_42",
        "records": [
            {
                "resource_id": "tombstone_user_17",
                "user_id": "user_17",
                "name": None,
                "email": None,
                "phone": None,
                "email_hash": None,
                "status": "REDACTED",
                "type": "ACCOUNT_TOMBSTONE",
                "details": "Customer Reference Registry shows retained reference without direct PII"
            }
        ]
    }

    # 7. marketing_profile_console.png (evidence_64)
    cache["images"]["evidence/images/marketing_profile_console.png"] = {
        "system_id": "marketing_platform",
        "file_id": "evidence_64",
        "records": [
            {
                "resource_id": "marketing_001",
                "name": "Soo-jin Park",
                "email": "sj.park@naver.com",
                "phone": "+82 10-5837-9451",
                "status": "PRESENT",
                "type": "MARKETING_PROFILE",
                "details": "Audience Operations shows live marketing profile"
            }
        ]
    }

    # 8. object_storage_browser_20260213.png (evidence_46)
    cache["images"]["evidence/images/object_storage_browser_20260213.png"] = {
        "system_id": "support_platform",
        "file_id": "evidence_46",
        "records": [
            {
                "resource_id": "support_attachment_delivery_19",
                "filename": "delivery_confirmation_19.pdf",
                "status": "PRESENT",
                "type": "SUPPORT_ATTACHMENT"
            },
            {
                "resource_id": "support_attachment_delivery_20",
                "filename": "delivery_confirmation_20.pdf",
                "status": "PRESENT",
                "type": "SUPPORT_ATTACHMENT"
            }
        ]
    }

    # 9. search_index_inspector_20260901.png (evidence_09)
    cache["images"]["evidence/images/search_index_inspector_20260901.png"] = {
        "system_id": "search_service",
        "file_id": "evidence_09",
        "records": [
            {
                "resource_id": "search_428",
                "user_id": "user_13",
                "name": "Gabriel Silva",
                "email": "g.silva76@gmail.com",
                "status": "PRESENT",
                "type": "SEARCH_INDEX_ENTRY",
                "details": "Search Console query email:g.silva76@gmail.com returned search_428"
            }
        ]
    }

    # 10. security_audit_explorer_20260905.png (evidence_48)
    cache["images"]["evidence/images/security_audit_explorer_20260905.png"] = {
        "system_id": "security_service",
        "file_id": "evidence_48",
        "records": [
            {
                "resource_id": "audit_record_003",
                "user_id": "user_03",
                "event_type": "account_closure_recorded",
                "status": "PRESENT",
                "type": "SECURITY_AUDIT_LOG",
                "details": "Sentinel Account events shows valid signed audit_record_003"
            },
            {
                "resource_id": "audit_record_002",
                "user_id": "user_03",
                "event_type": "session_revoked",
                "status": "PRESENT",
                "type": "SECURITY_AUDIT_LOG"
            },
            {
                "resource_id": "audit_record_001",
                "user_id": "user_03",
                "event_type": "recovery_challenge_completed",
                "status": "PRESENT",
                "type": "SECURITY_AUDIT_LOG"
            }
        ]
    }

    # 11. support_ticket_console_20260524.png (evidence_28)
    cache["images"]["evidence/images/support_ticket_console_20260524.png"] = {
        "system_id": "support_platform",
        "file_id": "evidence_28",
        "records": [
            {
                "resource_id": "support_1034",
                "name": "Kofi Agyeman",
                "email": "kagyeman8947@fastmail.com",
                "status": "PRESENT",
                "type": "SUPPORT_MESSAGE",
                "details": "Helpline Console ticket CS-5034 has unredacted customer message and email"
            }
        ]
    }

    # Extract PDFs
    for p in Path('dataset/evidence/documents').glob('*.pdf'):
        rel_path = f"evidence/documents/{p.name}"
        pages_text = []
        with pdfplumber.open(p) as pdf:
            for page in pdf.pages:
                pages_text.append(page.extract_text() or "")
        full_text = "\n".join(pages_text)
        cache["documents"][rel_path] = {
            "file_name": p.name,
            "text": full_text
        }

    out_file = Path("code/extracted_cache.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)
    print(f"Saved multimodal cache to {out_file} ({len(cache['images'])} images, {len(cache['documents'])} docs)")

if __name__ == "__main__":
    build_cache()
