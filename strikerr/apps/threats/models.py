import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _

class ThreatCategory(models.TextChoices):
    BENIGN = 'BENIGN', _('Safe / Clean')
    ONLINE_GAMBLING = 'JUDOL', _('Online Gambling (Judi Online)')
    FINANCIAL_SCAM = 'SCAM', _('Financial Scam / Social Engineering')
    PHISHING = 'PHISHING', _('Phishing / Credential Harvesting')
    GOV_DEFACEMENT = 'DEFACEMENT', _('Government / Academic Defacement')
    MALWARE_APK = 'MALWARE', _('Malicious APK / Trojan Distribution')

class ScanStatus(models.TextChoices):
    PENDING = 'PENDING', _('Queued in Broker')
    TRIAGING = 'TRIAGING', _('L1 Fast Triage')
    HEADLESS_RUNNING = 'HEADLESS_RUNNING', _('L2 Headless Crawl Active')
    ANALYZING = 'ANALYZING', _('Vector Analysis In Progress')
    COMPLETED = 'COMPLETED', _('Completed Successfully')
    FAILED = 'FAILED', _('Scan Failed')

class TargetDomain(models.Model):
    """Normalized domain entity with historical reputation tracking."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain_name = models.CharField(max_length=255, unique=True, db_index=True)
    apex_domain = models.CharField(max_length=255, db_index=True)
    tld = models.CharField(max_length=50, db_index=True)
    is_cc_tld_id = models.BooleanField(default=False, db_index=True)
    is_gov_or_ac_id = models.BooleanField(default=False, db_index=True) # .go.id or .ac.id
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    current_reputation_score = models.IntegerField(default=0) # 0 to 100
    is_whitelisted = models.BooleanField(default=False)

    class Meta:
        verbose_name = _('Target Domain')
        verbose_name_plural = _('Target Domains')
        indexes = [
            models.Index(fields=['apex_domain', 'is_gov_or_ac_id']),
            models.Index(fields=['current_reputation_score']),
        ]

    def __str__(self):
        return f"{self.domain_name} (Score: {self.current_reputation_score})"

class ScanJob(models.Model):
    """Lifecycle tracking for an individual scan execution."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_domain = models.ForeignKey(TargetDomain, on_delete=models.CASCADE, related_name='scans')
    raw_url = models.URLField(max_length=2048)
    submitted_by = models.CharField(max_length=150, default='SYSTEM')
    priority = models.PositiveSmallIntegerField(default=1) # 0=Critical, 1=Normal, 2=Low
    status = models.CharField(max_length=20, choices=ScanStatus.choices, default=ScanStatus.PENDING, db_index=True)
    triage_escalated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    execution_time_ms = models.PositiveIntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        verbose_name = _('Scan Job')
        verbose_name_plural = _('Scan Jobs')
        ordering = ['-created_at']

    def __str__(self):
        return f"Scan {self.id} [{self.status}] - {self.raw_url}"

class PageMetadata(models.Model):
    """Network, TLS, and DNS observables captured during scan."""
    scan_job = models.OneToOneField(ScanJob, on_delete=models.CASCADE, related_name='network_metadata')
    resolved_ip = models.GenericIPAddressField(null=True, blank=True)
    asn_number = models.CharField(max_length=50, null=True, blank=True)
    asn_organization = models.CharField(max_length=255, null=True, blank=True)
    country_iso = models.CharField(max_length=5, default='UNKNOWN')
    dns_records = models.JSONField(default=dict) # A, AAAA, MX, NS, TXT, SOA
    ssl_issuer = models.CharField(max_length=255, null=True, blank=True)
    ssl_valid_from = models.DateTimeField(null=True, blank=True)
    ssl_valid_to = models.DateTimeField(null=True, blank=True)
    ssl_jarm_hash = models.CharField(max_length=64, null=True, blank=True)
    http_status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    final_redirect_url = models.URLField(max_length=2048, null=True, blank=True)
    redirect_chain = models.JSONField(default=list)

    class Meta:
        verbose_name = _('Page Metadata')
        verbose_name_plural = _('Page Metadata')

    def __str__(self):
        return f"Metadata for {self.scan_job_id} ({self.resolved_ip})"

class FeatureExtraction(models.Model):
    """Extracted heuristic, NLP, and structural DOM features."""
    scan_job = models.OneToOneField(ScanJob, on_delete=models.CASCADE, related_name='features')
    dom_title = models.CharField(max_length=512, blank=True)
    dom_meta_description = models.TextField(blank=True)
    dom_sha256 = models.CharField(max_length=64, db_index=True)
    matched_lexicon_keywords = models.JSONField(default=list) # Aho-Corasick matches
    has_deceptive_login_form = models.BooleanField(default=False)
    has_hidden_iframe = models.BooleanField(default=False)
    has_telegram_exfiltration = models.BooleanField(default=False)
    exfiltration_endpoints = models.JSONField(default=list)

    class Meta:
        verbose_name = _('Feature Extraction')
        verbose_name_plural = _('Feature Extractions')

    def __str__(self):
        return f"Features for {self.scan_job_id} (Title: {self.dom_title[:30]})"

class FinancialMuleIdentifier(models.Model):
    """Indonesian bank account and e-wallet mule details extracted from target."""
    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='mule_identifiers')
    institution_type = models.CharField(max_length=50) # BCA, MANDIRI, BRI, BNI, DANA, OVO, GOPAY, QRIS
    account_number = models.CharField(max_length=100, db_index=True)
    account_holder_name = models.CharField(max_length=255, blank=True)
    qris_raw_payload = models.TextField(blank=True)
    cekrekening_status = models.CharField(max_length=50, default='UNCHECKED')
    report_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Financial Mule Identifier')
        verbose_name_plural = _('Financial Mule Identifiers')
        indexes = [
            models.Index(fields=['institution_type', 'account_number']),
        ]

    def __str__(self):
        return f"{self.institution_type} - {self.account_number}"

class ScrapedAsset(models.Model):
    """Forensic evidence pointers in MinIO / S3."""
    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name='assets')
    asset_type = models.CharField(max_length=30) # SCREENSHOT_PNG, DOM_HTML, NETWORK_HAR, DOSSIER_PDF
    storage_path = models.CharField(max_length=1024)
    file_sha256 = models.CharField(max_length=64)
    file_size_bytes = models.BigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Scraped Asset')
        verbose_name_plural = _('Scraped Assets')

    def __str__(self):
        return f"{self.asset_type} ({self.file_sha256[:12]})"

class AuditScoreLog(models.Model):
    """Scoring matrix calculation audit trail."""
    scan_job = models.OneToOneField(ScanJob, on_delete=models.CASCADE, related_name='score_log')
    base_heuristic_score = models.FloatField()
    nlp_prob_score = models.FloatField(default=0.0)
    visual_score = models.FloatField(default=0.0)
    penalties_applied = models.JSONField(default=dict)
    final_threat_score = models.PositiveSmallIntegerField(db_index=True)
    final_verdict = models.CharField(max_length=50, choices=ThreatCategory.choices, db_index=True)
    is_escalated_to_regulator = models.BooleanField(default=False)
    calculated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Audit Score Log')
        verbose_name_plural = _('Audit Score Logs')
        ordering = ['-calculated_at']

    def __str__(self):
        return f"Score {self.final_threat_score}/100 [{self.final_verdict}] for Scan {self.scan_job_id}"
