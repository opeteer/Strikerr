# strikerr/apps/crawler/tasks.py
import asyncio
import time
from urllib.parse import urlparse
from django.utils import timezone
from strikerr.celery import app
from strikerr.apps.threats.models import (
    ScanJob, TargetDomain, PageMetadata, FeatureExtraction,
    FinancialMuleIdentifier, ScrapedAsset, AuditScoreLog, ScanStatus, ThreatCategory
)
from strikerr.apps.crawler.triage.triage_engine import FastTriageEngine
from strikerr.apps.crawler.browser.crawler_engine import HeadlessCrawlerEngine
from strikerr.apps.analyzer.lexicon.lexicon_engine import GLOBAL_LEXICON_ENGINE
from strikerr.apps.analyzer.extractors.mule_extractor import FinancialMuleExtractor
from strikerr.apps.analyzer.extractors.form_analyzer import FormPhishingAnalyzer
from strikerr.apps.analyzer.scoring.heuristic_scorer import DynamicHeuristicScorer
from strikerr.apps.vault.storage_client import EvidenceStorageClient

def run_async(coro):
    """Utility to run asynchronous coroutines inside synchronous Celery workers."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    if loop.is_running():
        import nest_asyncio
        nest_asyncio.apply()
        return loop.run_until_complete(coro)
    return loop.run_until_complete(coro)

@app.task(bind=True, name="strikerr.apps.crawler.tasks.execute_scan_pipeline")
def execute_scan_pipeline(self, scan_job_id: str, force_headless: bool = False):
    """Executes the full triaged threat hunting pipeline for a given ScanJob."""
    start_time = time.time()
    try:
        scan_job = ScanJob.objects.select_related('target_domain').get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        return {'status': 'ERROR', 'error': f'ScanJob {scan_job_id} not found'}

    raw_url = scan_job.raw_url
    target_domain = scan_job.target_domain
    storage = EvidenceStorageClient()

    # Stage 1: L1 Fast Triage
    scan_job.status = ScanStatus.TRIAGING
    scan_job.save(update_fields=['status'])

    triage_result = run_async(FastTriageEngine.triage_url(raw_url))

    if triage_result.get('status') == 'BLOCKED_SSRF':
        scan_job.status = ScanStatus.FAILED
        scan_job.error_message = f"Security Intercept: {triage_result.get('error')}"
        scan_job.completed_at = timezone.now()
        scan_job.save(update_fields=['status', 'error_message', 'completed_at'])
        return {'status': 'BLOCKED_SSRF', 'error': scan_job.error_message}

    # Persist PageMetadata observables
    PageMetadata.objects.update_or_create(
        scan_job=scan_job,
        defaults={
            'resolved_ip': triage_result.get('resolved_ip'),
            'dns_records': triage_result.get('dns_records', {}),
            'ssl_issuer': triage_result.get('ssl_info', {}).get('issuer'),
            'http_status_code': triage_result.get('http_status'),
            'final_redirect_url': triage_result.get('final_url'),
            'redirect_chain': triage_result.get('redirect_chain', [])
        }
    )

    should_escalate = force_headless or triage_result.get('should_escalate_to_headless', False)
    scan_job.triage_escalated = should_escalate
    dom_html = triage_result.get('dom_html', '')

    # Stage 2: L2 Headless Crawl (if escalated)
    if should_escalate:
        scan_job.status = ScanStatus.HEADLESS_RUNNING
        scan_job.save(update_fields=['status', 'triage_escalated'])

        crawl_result = run_async(HeadlessCrawlerEngine.crawl_url(raw_url))
        if crawl_result.get('status') == 'SUCCESS' and crawl_result.get('dom_html'):
            dom_html = crawl_result['dom_html']

        # Store screenshot artifact in MinIO / S3
        if crawl_result.get('screenshot_bytes'):
            screenshot_meta = storage.store_artifact(
                str(scan_job.id),
                'SCREENSHOT_PNG',
                crawl_result['screenshot_bytes'],
                file_extension='png'
            )
            ScrapedAsset.objects.create(
                scan_job=scan_job,
                asset_type='SCREENSHOT_PNG',
                storage_path=screenshot_meta['storage_path'],
                file_sha256=screenshot_meta['file_sha256'],
                file_size_bytes=screenshot_meta['file_size_bytes']
            )

    # Store post-hydration or triage DOM HTML in MinIO
    if dom_html:
        dom_meta = storage.store_artifact(
            str(scan_job.id),
            'DOM_HTML',
            dom_html.encode('utf-8', errors='replace'),
            file_extension='html'
        )
        ScrapedAsset.objects.create(
            scan_job=scan_job,
            asset_type='DOM_HTML',
            storage_path=dom_meta['storage_path'],
            file_sha256=dom_meta['file_sha256'],
            file_size_bytes=dom_meta['file_size_bytes']
        )

    # Stage 3: Feature Extraction & Analysis
    scan_job.status = ScanStatus.ANALYZING
    scan_job.save(update_fields=['status'])

    lexicon_res = GLOBAL_LEXICON_ENGINE.scan_text(dom_html)
    form_res = FormPhishingAnalyzer.analyze_dom(dom_html, raw_url)
    mules_res = FinancialMuleExtractor.extract_mules(dom_html)

    # Persist FeatureExtraction
    import hashlib
    dom_hash = hashlib.sha256(dom_html.encode('utf-8', errors='replace')).hexdigest() if dom_html else ""
    FeatureExtraction.objects.update_or_create(
        scan_job=scan_job,
        defaults={
            'dom_sha256': dom_hash,
            'matched_lexicon_keywords': lexicon_res.get('matched_keywords', []),
            'has_deceptive_login_form': form_res.get('has_deceptive_login_form', False),
            'has_hidden_iframe': form_res.get('has_hidden_iframe', False),
            'has_telegram_exfiltration': form_res.get('has_telegram_exfiltration', False),
            'exfiltration_endpoints': form_res.get('exfiltration_endpoints', [])
        }
    )

    # Persist Financial Mules
    for mule in mules_res:
        FinancialMuleIdentifier.objects.get_or_create(
            scan_job=scan_job,
            institution_type=mule['institution_type'],
            account_number=mule['account_number'],
            defaults={
                'account_holder_name': mule.get('account_holder_name', ''),
                'qris_raw_payload': mule.get('qris_raw_payload', '')
            }
        )

    # Stage 4: Scoring Matrix Calculation
    scoring_result = DynamicHeuristicScorer.calculate_score(
        target_url=raw_url,
        lexicon_results=lexicon_res,
        form_results=form_res,
        mule_results=mules_res,
        is_gov_or_ac_id=target_domain.is_gov_or_ac_id
    )

    AuditScoreLog.objects.update_or_create(
        scan_job=scan_job,
        defaults={
            'base_heuristic_score': scoring_result['base_heuristic_score'],
            'penalties_applied': scoring_result['penalties_applied'],
            'final_threat_score': scoring_result['final_threat_score'],
            'final_verdict': scoring_result['final_verdict']
        }
    )

    # Update domain reputation score and scan completion
    target_domain.current_reputation_score = scoring_result['final_threat_score']
    target_domain.last_scanned_at = timezone.now()
    target_domain.save(update_fields=['current_reputation_score', 'last_scanned_at'])

    scan_job.status = ScanStatus.COMPLETED
    scan_job.completed_at = timezone.now()
    scan_job.execution_time_ms = int((time.time() - start_time) * 1000)
    scan_job.save(update_fields=['status', 'completed_at', 'execution_time_ms'])

    return {
        'scan_job_id': str(scan_job.id),
        'status': 'COMPLETED',
        'threat_score': scoring_result['final_threat_score'],
        'verdict': scoring_result['final_verdict'],
        'execution_time_ms': scan_job.execution_time_ms
    }
