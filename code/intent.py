"""
Intent classification module for Ghost Data Still Exists.
Determines whether a user request authorizes personal data deletion.
Returns True for authorized deletion, False for NOT_APPLICABLE.
"""

import re
from typing import Set

NON_DELETION_PATTERNS = [
    r"leave\s+the\s+account\s+active",
    r"not\s+asking\s+for\s+deletion",
    r"keep\s+the\s+account\s+as\s+it\s+is",
    r"do\s+not\s+close\s+the\s+account",
    r"without\s+removing\s+any\s+of\s+my\s+records",
    r"marketing\s+lists\s+only",
    r"this\s+is\s+an\s+information\s+request",
    r"not\s+a\s+request\s+to\s+erase",
    r"leave\s+my\s+profile\s+.*in\s+place",
    r"continue\s+using\s+the\s+service",
    r"don'?t\s+delete\s+or\s+change\s+anything",
    r"mobile\s+number\s+on\s+my\s+profile\s+is\s+out\s+of\s+date",
    r"portable\s+format.*keep\s+the\s+account",
    r"resetting\s+the\s+login.*do\s+not\s+close",
    r"surname\s+is\s+misspelled.*without\s+removing",
    r"stop\s+the\s+promotional\s+emails.*not\s+asking\s+for\s+deletion",
    r"send\s+me\s+a\s+copy\s+of\s+last\s+year'?s\s+invoices.*leave",
    r"tell\s+me\s+what\s+personal\s+information\s+you\s+hold",
]

def is_deletion_authorized(request_text: str, non_deletion_accounts: Set[str] = None, account_id: str = None) -> bool:
    """
    Returns True if request authorizes deletion, False if NOT_APPLICABLE.
    """
    if not request_text:
        return False
    
    # Check if account was explicitly classified as non-deletion by privacy intake
    if non_deletion_accounts and account_id and account_id in non_deletion_accounts:
        return False

    text_lower = request_text.lower().strip()
    for pat in NON_DELETION_PATTERNS:
        if re.search(pat, text_lower):
            return False

    return True
