# strikerr/apps/analyzer/extractors/form_analyzer.py
import re
from urllib.parse import urlparse
from typing import Dict, Any, List
from bs4 import BeautifulSoup

class FormPhishingAnalyzer:
    """Inspects rendered DOM structure for deceptive phishing forms and exfiltration hooks."""

    TELEGRAM_API_REGEX = re.compile(r'api\.telegram\.org/bot(\d+:[A-Za-z0-9_-]+)/(\w+)', re.IGNORECASE)
    WHATSAPP_REDIRECT_REGEX = re.compile(r'(?:api\.whatsapp\.com/send|wa\.me)/(\d+)', re.IGNORECASE)
    OTP_FIELD_REGEX = re.compile(r'otp|pin|token|kode_rahasia|passcode|cvv|m-pin|keybca', re.IGNORECASE)

    @classmethod
    def analyze_dom(cls, raw_html: str, target_url: str) -> Dict[str, Any]:
        results = {
            'has_deceptive_login_form': False,
            'has_password_field': False,
            'has_otp_field': False,
            'form_action_mismatch': False,
            'has_hidden_iframe': False,
            'has_telegram_exfiltration': False,
            'exfiltration_endpoints': [],
            'hidden_iframes': [],
            'detected_forms': []
        }

        if not raw_html:
            return results

        try:
            soup = BeautifulSoup(raw_html, 'lxml')
        except Exception:
            try:
                soup = BeautifulSoup(raw_html, 'html.parser')
            except Exception:
                return results

        target_host = urlparse(target_url).netloc.lower()

        # 1. Analyze HTML Form structures
        forms = soup.find_all('form')
        for idx, form in enumerate(forms):
            has_pwd = bool(form.find('input', {'type': 'password'}))
            has_otp = bool(form.find('input', {'name': cls.OTP_FIELD_REGEX}))
            action = (form.get('action') or '').strip()

            action_mismatch = False
            if action and not action.startswith(('#', 'javascript:')):
                parsed_action = urlparse(action)
                if parsed_action.netloc and parsed_action.netloc.lower() != target_host:
                    action_mismatch = True

            if has_pwd or has_otp:
                results['has_password_field'] = results['has_password_field'] or has_pwd
                results['has_otp_field'] = results['has_otp_field'] or has_otp
                results['form_action_mismatch'] = results['form_action_mismatch'] or action_mismatch
                results['has_deceptive_login_form'] = True

            results['detected_forms'].append({
                'form_index': idx,
                'action': action,
                'has_password': has_pwd,
                'has_otp': has_otp,
                'action_mismatch': action_mismatch
            })

        # 2. Sniff for inline script credential exfiltration (Telegram bots / Webhooks)
        scripts = soup.find_all('script')
        for script in scripts:
            script_text = script.string or script.get_text() or ''
            
            # Check for direct regex or presence of Telegram bot API
            matched_telegram = False
            for match in cls.TELEGRAM_API_REGEX.finditer(script_text):
                token = match.group(1)
                method = match.group(2)
                results['has_telegram_exfiltration'] = True
                results['exfiltration_endpoints'].append(f"Telegram Bot (Token: {token[:6]}... / Method: {method})")
                matched_telegram = True

            if not matched_telegram and 'api.telegram.org/bot' in script_text:
                results['has_telegram_exfiltration'] = True
                results['exfiltration_endpoints'].append("Telegram Bot API endpoint detected in JavaScript")

            for wa_match in cls.WHATSAPP_REDIRECT_REGEX.finditer(script_text):
                phone = wa_match.group(1)
                results['exfiltration_endpoints'].append(f"WhatsApp Lead Exfiltration (Target: {phone})")

        # 3. Detect hidden cloaking iframes (frequent in .go.id / .ac.id defacements)
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            style = (iframe.get('style') or '').lower()
            width = str(iframe.get('width') or '')
            height = str(iframe.get('height') or '')
            src = iframe.get('src') or ''

            is_hidden = (
                'display:none' in style or
                'visibility:hidden' in style or
                'opacity:0' in style or
                width in ('0', '1') or
                height in ('0', '1')
            )

            if is_hidden:
                results['has_hidden_iframe'] = True
                results['hidden_iframes'].append(src)

        return results
