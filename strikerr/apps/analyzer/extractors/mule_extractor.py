# strikerr/apps/analyzer/extractors/mule_extractor.py
import re
from typing import List, Dict, Any

class FinancialMuleExtractor:
    """Extracts Indonesian bank account and e-wallet mule identifiers from rendered pages."""

    PATTERNS = {
        'BCA': re.compile(r'\b(?:BCA|Bank\s+Central\s+Asia)[^\d]{1,25}(\d{10})\b', re.IGNORECASE),
        'MANDIRI': re.compile(r'\b(?:MANDIRI|Bank\s+Mandiri)[^\d]{1,25}(\d{13})\b', re.IGNORECASE),
        'BRI': re.compile(r'\b(?:BRI|Bank\s+Rakyat\s+Indonesia)[^\d]{1,25}(\d{15})\b', re.IGNORECASE),
        'BNI': re.compile(r'\b(?:BNI|Bank\s+Negara\s+Indonesia)[^\d]{1,25}(\d{10})\b', re.IGNORECASE),
        'DANA': re.compile(r'\b(?:DANA)[^\d]{1,20}(08[1-9][0-9]{7,10})\b', re.IGNORECASE),
        'OVO': re.compile(r'\b(?:OVO)[^\d]{1,20}(08[1-9][0-9]{7,10})\b', re.IGNORECASE),
        'GOPAY': re.compile(r'\b(?:GOPAY|GO-PAY)[^\d]{1,20}(08[1-9][0-9]{7,10})\b', re.IGNORECASE),
    }

    QRIS_REGEX = re.compile(r'00020101[0-9A-Za-z\.\-_]{20,}', re.IGNORECASE)

    HOLDER_REGEX = re.compile(r'\b(?:a/n|atas\s+nama)\b[^\w]{0,5}([A-Za-z\s\.\*]{3,30})', re.IGNORECASE)

    @classmethod
    def extract_mules(cls, content: str) -> List[Dict[str, Any]]:
        """Parses text content to identify potential financial mule accounts."""
        if not content:
            return []

        results = []
        seen = set()

        for institution, pattern in cls.PATTERNS.items():
            for match in pattern.finditer(content):
                acc_num = match.group(1).strip()
                key = (institution, acc_num)
                if key in seen:
                    continue
                seen.add(key)

                # Look forward first for account holder: "<ACC_NUM> a/n <NAME>"
                forward_snippet = content[match.end():min(len(content), match.end() + 60)]
                holder_match = cls.HOLDER_REGEX.search(forward_snippet)

                # If not found forward, look backward: "a/n <NAME> <ACC_NUM>"
                if not holder_match:
                    backward_snippet = content[max(0, match.start() - 60):match.start()]
                    holder_match = cls.HOLDER_REGEX.search(backward_snippet)

                holder_name = holder_match.group(1).strip() if holder_match else ""

                results.append({
                    'institution_type': institution,
                    'account_number': acc_num,
                    'account_holder_name': holder_name,
                    'qris_raw_payload': ''
                })

        # QRIS code extraction
        for qris_match in cls.QRIS_REGEX.finditer(content):
            qris_payload = qris_match.group(0).strip()
            key = ('QRIS', qris_payload[:30])
            if key not in seen:
                seen.add(key)
                results.append({
                    'institution_type': 'QRIS',
                    'account_number': qris_payload[:30],
                    'account_holder_name': 'QRIS Merchant',
                    'qris_raw_payload': qris_payload
                })

        return results
