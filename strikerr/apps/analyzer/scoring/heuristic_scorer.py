# strikerr/apps/analyzer/scoring/heuristic_scorer.py
from urllib.parse import urlparse
from typing import Dict, Any, List

class DynamicHeuristicScorer:
    """Calculates composite threat scores based on extracted observables and local threat signatures."""

    HIGH_RISK_TLDS = {'.xyz', '.top', '.vip', '.icu', '.lat', '.click', '.bond', '.cfd', '.sbs', '.cc', '.tk'}

    @classmethod
    def calculate_score(
        cls,
        target_url: str,
        lexicon_results: Dict[str, Any],
        form_results: Dict[str, Any],
        mule_results: List[Dict[str, Any]],
        is_gov_or_ac_id: bool = False
    ) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        hostname = (parsed.hostname or '').lower()
        tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''

        base_score = 0
        penalties = {}

        judol_weight = lexicon_results.get('judol_score', 0)
        scam_weight = lexicon_results.get('scam_score', 0)

        # 1. Lexical Threat Density
        if judol_weight > 0:
            # Scale judol weight (max 40 pts)
            pts = min(40, judol_weight)
            base_score += pts
            penalties['judol_lexicon'] = pts

        if scam_weight > 0:
            pts = min(40, scam_weight)
            base_score += pts
            penalties['scam_lexicon'] = pts

        # 2. Form & Credential Harvesting Heuristics
        if form_results.get('form_action_mismatch') and form_results.get('has_password_field'):
            base_score += 35
            penalties['credential_action_mismatch'] = 35
        elif form_results.get('form_action_mismatch'):
            base_score += 20
            penalties['form_action_mismatch'] = 20

        if form_results.get('has_otp_field') and form_results.get('has_deceptive_login_form'):
            base_score += 25
            penalties['otp_harvesting_form'] = 25

        if form_results.get('has_telegram_exfiltration'):
            base_score += 45
            penalties['telegram_token_exfiltration'] = 45

        if form_results.get('has_hidden_iframe'):
            base_score += 30
            penalties['cloaked_hidden_iframe'] = 30

        # 3. Financial Mule Accounts Found
        if mule_results:
            pts = min(35, 20 + (len(mule_results) * 5))
            base_score += pts
            penalties['financial_mules_detected'] = pts

        # 4. High Risk TLD Penalty
        if tld in cls.HIGH_RISK_TLDS:
            base_score += 15
            penalties['high_risk_tld'] = 15

        # 5. Sovereign ccTLD Defacement Multiplier (.go.id or .ac.id hosting threats)
        if is_gov_or_ac_id and (judol_weight > 0 or scam_weight > 0 or form_results.get('has_hidden_iframe')):
            base_score += 35
            penalties['sovereign_infrastructure_defacement'] = 35

        # Bound score between 0 and 100
        final_score = min(100, max(0, base_score))

        # Assign verdict
        verdict = cls._determine_verdict(
            final_score, 
            judol_weight, 
            scam_weight, 
            form_results, 
            is_gov_or_ac_id
        )

        return {
            'final_threat_score': final_score,
            'final_verdict': verdict,
            'base_heuristic_score': base_score,
            'penalties_applied': penalties
        }

    @classmethod
    def _determine_verdict(
        cls, 
        score: int, 
        judol_w: int, 
        scam_w: int, 
        form_res: Dict[str, Any],
        is_gov_or_ac_id: bool
    ) -> str:
        if score < 25:
            return 'BENIGN'

        if is_gov_or_ac_id and (judol_w > 0 or scam_w > 0 or form_res.get('has_hidden_iframe')):
            return 'DEFACEMENT'

        if form_res.get('has_telegram_exfiltration') or (form_res.get('form_action_mismatch') and form_res.get('has_password_field')):
            return 'PHISHING'

        if judol_w >= scam_w and judol_w > 0:
            return 'JUDOL'

        if scam_w > 0:
            return 'SCAM'

        return 'BENIGN'
