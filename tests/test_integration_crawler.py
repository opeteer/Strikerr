# tests/test_integration_crawler.py
import uuid
import pytest
from unittest.mock import patch
from django.utils import timezone
from strikerr.apps.threats.models import TargetDomain, ScanJob, ScanStatus
from strikerr.apps.analyzer.scoring.heuristic_scorer import DynamicHeuristicScorer
from strikerr.apps.crawler.tasks import execute_scan_pipeline

def test_dynamic_heuristic_scorer_benign():
    scoring = DynamicHeuristicScorer.calculate_score(
        target_url="https://portal.kemkes.go.id/berita",
        lexicon_results={'judol_score': 0, 'scam_score': 0},
        form_results={'form_action_mismatch': False, 'has_password_field': False, 'has_telegram_exfiltration': False},
        mule_results=[],
        is_gov_or_ac_id=True
    )
    assert scoring['final_threat_score'] == 0
    assert scoring['final_verdict'] == 'BENIGN'

def test_dynamic_heuristic_scorer_judol():
    scoring = DynamicHeuristicScorer.calculate_score(
        target_url="https://zeus88-slot-gacor.xyz",
        lexicon_results={'judol_score': 65, 'scam_score': 0},
        form_results={'has_deceptive_login_form': True, 'form_action_mismatch': False},
        mule_results=[{'institution_type': 'BCA', 'account_number': '8820192831'}],
        is_gov_or_ac_id=False
    )
    assert scoring['final_threat_score'] >= 80
    assert scoring['final_verdict'] == 'JUDOL'

def test_dynamic_heuristic_scorer_phishing_telegram():
    scoring = DynamicHeuristicScorer.calculate_score(
        target_url="https://klikbca-update-tarif.com/login",
        lexicon_results={'judol_score': 0, 'scam_score': 35},
        form_results={
            'form_action_mismatch': True,
            'has_password_field': True,
            'has_otp_field': True,
            'has_telegram_exfiltration': True
        },
        mule_results=[],
        is_gov_or_ac_id=False
    )
    assert scoring['final_threat_score'] >= 80
    assert scoring['final_verdict'] == 'PHISHING'

def test_dynamic_heuristic_scorer_sovereign_defacement():
    scoring = DynamicHeuristicScorer.calculate_score(
        target_url="https://dinas.pemkab.go.id/wp-content/uploads/slot/index.html",
        lexicon_results={'judol_score': 45, 'scam_score': 0},
        form_results={'has_hidden_iframe': True},
        mule_results=[],
        is_gov_or_ac_id=True
    )
    assert scoring['final_threat_score'] >= 80
    assert scoring['final_verdict'] == 'DEFACEMENT'
    assert 'sovereign_infrastructure_defacement' in scoring['penalties_applied']

def test_full_pipeline_mock_execution():
    unique_domain = f"slot-gacor-{uuid.uuid4().hex[:8]}.xyz"
    domain = TargetDomain.objects.create(
        domain_name=unique_domain,
        apex_domain=unique_domain,
        tld=".xyz",
        is_gov_or_ac_id=False
    )
    scan_job = ScanJob.objects.create(
        target_domain=domain,
        raw_url=f"https://{unique_domain}",
        submitted_by="TEST"
    )

    mock_triage_return = {
        'status': 'SUCCESS',
        'raw_url': f"https://{unique_domain}",
        'hostname': unique_domain,
        'resolved_ip': '103.145.22.18',
        'dns_records': {'A': ['103.145.22.18']},
        'ssl_info': {'issuer': "Let's Encrypt"},
        'http_status': 200,
        'final_url': f"https://{unique_domain}",
        'redirect_chain': [],
        'headers': {'Server': 'nginx'},
        'dom_html': """
            <html>
              <body>
                <h1>Situs Slot Gacor Maxwin Terpercaya</h1>
                <p>Daftar slot zeus olympus anti rungkad deposit pulsa!</p>
                <p>Transfer Bank BCA: 8820192831 a/n SL** GACOR</p>
              </body>
            </html>
        """,
        'dom_sha256': 'abc123def456',
        'should_escalate_to_headless': False,
        'escalation_reasons': []
    }

    with patch('strikerr.apps.crawler.tasks.FastTriageEngine.triage_url', return_value=mock_triage_return):
        res = execute_scan_pipeline(str(scan_job.id))
        assert res['status'] == 'COMPLETED'
        assert res['threat_score'] >= 50
        assert res['verdict'] == 'JUDOL'

        scan_job.refresh_from_db()
        assert scan_job.status == ScanStatus.COMPLETED
        assert scan_job.target_domain.current_reputation_score == res['threat_score']
        assert scan_job.mule_identifiers.count() == 1
        assert scan_job.mule_identifiers.first().account_number == '8820192831'
