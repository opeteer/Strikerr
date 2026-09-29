import sys
from urllib.parse import urlparse
from django.core.management.base import BaseCommand
from strikerr.apps.threats.models import TargetDomain, ScanJob, ScanStatus
from strikerr.apps.crawler.tasks import execute_scan_pipeline

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

class Command(BaseCommand):
    help = 'Executes a threat hunting scan against a target URL.'

    def add_arguments(self, parser):
        parser.add_argument('url', type=str, help='Target URL to scan (e.g. https://example.com)')
        parser.add_argument('--sync', action='store_true', help='Execute scan synchronously in foreground')
        parser.add_argument('--headless', action='store_true', help='Force Layer 2 Headless Browser execution')
        parser.add_argument('--priority', type=int, default=1, help='Task priority (0=Critical, 1=Normal, 2=Low)')

    def handle(self, *args, **options):
        raw_url = options['url'].strip()
        if not raw_url.startswith(('http://', 'https://')):
            raw_url = 'https://' + raw_url

        parsed = urlparse(raw_url)
        domain_name = (parsed.hostname or '').lower()
        if not domain_name:
            self.stderr.write(self.style.ERROR(f"[-] Invalid URL: {raw_url}"))
            return

        # Extract domain components
        if HAS_TLDEXTRACT:
            ext = tldextract.extract(domain_name)
            apex_domain = ext.registered_domain or domain_name
            tld = f".{ext.suffix}"
            is_cc_tld_id = ext.suffix.endswith('id')
            is_gov_or_ac_id = ext.suffix in ('go.id', 'ac.id') or domain_name.endswith(('.go.id', '.ac.id'))
        else:
            parts = domain_name.split('.')
            apex_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain_name
            tld = f".{parts[-1]}" if parts else ""
            is_cc_tld_id = domain_name.endswith('.id')
            is_gov_or_ac_id = domain_name.endswith(('.go.id', '.ac.id'))

        # Get or create TargetDomain
        target_domain, _ = TargetDomain.objects.get_or_create(
            domain_name=domain_name,
            defaults={
                'apex_domain': apex_domain,
                'tld': tld,
                'is_cc_tld_id': is_cc_tld_id,
                'is_gov_or_ac_id': is_gov_or_ac_id,
            }
        )

        # Create ScanJob
        scan_job = ScanJob.objects.create(
            target_domain=target_domain,
            raw_url=raw_url,
            priority=options['priority'],
            submitted_by='CLI'
        )

        self.stdout.write(self.style.SUCCESS(f"[+] Initialized ScanJob: {scan_job.id}"))
        self.stdout.write(f"    Target URL: {raw_url}")
        self.stdout.write(f"    Domain: {domain_name} (Apex: {apex_domain})")
        self.stdout.write(f"    Sovereign ccTLD (.go.id/.ac.id): {is_gov_or_ac_id}")

        if options['sync']:
            self.stdout.write("[*] Executing pipeline synchronously in foreground...")
            result = execute_scan_pipeline(str(scan_job.id), force_headless=options['headless'])
            
            # Refresh scan job from database
            scan_job.refresh_from_db()
            self.stdout.write("\n" + "="*60)
            self.stdout.write(self.style.SUCCESS("SCAN EXECUTION SUMMARY"))
            self.stdout.write("="*60)
            self.stdout.write(f"Status:          {scan_job.status}")
            self.stdout.write(f"Execution Time:  {scan_job.execution_time_ms} ms")
            
            if hasattr(scan_job, 'score_log'):
                score_log = scan_job.score_log
                self.stdout.write(f"Threat Score:    {score_log.final_threat_score} / 100")
                self.stdout.write(f"Final Verdict:   {score_log.final_verdict}")
                self.stdout.write(f"Penalties:       {score_log.penalties_applied}")
            
            if hasattr(scan_job, 'features'):
                features = scan_job.features
                self.stdout.write(f"Keywords Found:  {len(features.matched_lexicon_keywords)}")
                self.stdout.write(f"Deceptive Form:  {features.has_deceptive_login_form}")
                self.stdout.write(f"Telegram Exfil:  {features.has_telegram_exfiltration}")
            
            mules = scan_job.mule_identifiers.all()
            if mules.exists():
                self.stdout.write(self.style.WARNING(f"\n[!] Extracted Financial Mules ({mules.count()}):"))
                for m in mules:
                    self.stdout.write(f"    - {m.institution_type}: {m.account_number} (Holder: {m.account_holder_name or 'N/A'})")
            
            assets = scan_job.assets.all()
            if assets.exists():
                self.stdout.write(f"\nArtifacts Preserved ({assets.count()}):")
                for a in assets:
                    self.stdout.write(f"    - [{a.asset_type}] {a.storage_path} (SHA-256: {a.file_sha256[:12]}...)")
            
            self.stdout.write("="*60)
        else:
            self.stdout.write("[*] Dispatching task to Celery triage queue...")
            execute_scan_pipeline.delay(str(scan_job.id), force_headless=options['headless'])
            self.stdout.write(self.style.SUCCESS(f"[+] Task dispatched to queue. Check status in SOC admin."))
