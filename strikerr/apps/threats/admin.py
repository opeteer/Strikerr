from django.contrib import admin
from django.utils.html import format_html
from .models import (
    TargetDomain, ScanJob, PageMetadata, FeatureExtraction,
    FinancialMuleIdentifier, ScrapedAsset, AuditScoreLog, ThreatCategory
)

class PageMetadataInline(admin.StackedInline):
    model = PageMetadata
    extra = 0
    can_delete = False
    readonly_fields = ('resolved_ip', 'asn_number', 'asn_organization', 'country_iso', 'dns_records', 'ssl_issuer', 'ssl_valid_from', 'ssl_valid_to', 'http_status_code', 'final_redirect_url', 'redirect_chain')

class FeatureExtractionInline(admin.StackedInline):
    model = FeatureExtraction
    extra = 0
    can_delete = False
    readonly_fields = ('dom_title', 'dom_meta_description', 'dom_sha256', 'matched_lexicon_keywords', 'has_deceptive_login_form', 'has_hidden_iframe', 'has_telegram_exfiltration', 'exfiltration_endpoints')

class FinancialMuleInline(admin.TabularInline):
    model = FinancialMuleIdentifier
    extra = 0
    readonly_fields = ('institution_type', 'account_number', 'account_holder_name', 'cekrekening_status', 'created_at')

class ScrapedAssetInline(admin.TabularInline):
    model = ScrapedAsset
    extra = 0
    readonly_fields = ('asset_type', 'storage_path', 'file_sha256', 'file_size_bytes', 'created_at')

class AuditScoreLogInline(admin.StackedInline):
    model = AuditScoreLog
    extra = 0
    can_delete = False
    readonly_fields = ('base_heuristic_score', 'nlp_prob_score', 'visual_score', 'penalties_applied', 'final_threat_score', 'final_verdict', 'is_escalated_to_regulator', 'calculated_at')

@admin.register(TargetDomain)
class TargetDomainAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'apex_domain', 'tld', 'is_gov_or_ac_id', 'reputation_badge', 'is_whitelisted', 'last_scanned_at')
    list_filter = ('is_cc_tld_id', 'is_gov_or_ac_id', 'is_whitelisted', 'tld')
    search_fields = ('domain_name', 'apex_domain')
    readonly_fields = ('id', 'first_seen_at')

    def reputation_badge(self, obj):
        score = obj.current_reputation_score
        if score >= 80:
            color = 'red'
        elif score >= 55:
            color = 'orange'
        elif score >= 25:
            color = '#b8860b'
        else:
            color = 'green'
        return format_html('<span style="font-weight:bold; color:{};">{} / 100</span>', color, score)
    reputation_badge.short_description = 'Reputation Score'

@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ('id', 'target_domain', 'status_badge', 'priority', 'triage_escalated', 'created_at', 'execution_time_ms')
    list_filter = ('status', 'triage_escalated', 'priority')
    search_fields = ('id', 'raw_url', 'target_domain__domain_name')
    readonly_fields = ('id', 'created_at', 'completed_at', 'execution_time_ms')
    inlines = [PageMetadataInline, FeatureExtractionInline, FinancialMuleInline, ScrapedAssetInline, AuditScoreLogInline]

    def status_badge(self, obj):
        colors = {
            'PENDING': '#6c757d',
            'TRIAGING': '#17a2b8',
            'HEADLESS_RUNNING': '#007bff',
            'ANALYZING': '#ffc107',
            'COMPLETED': '#28a745',
            'FAILED': '#dc3545',
        }
        color = colors.get(obj.status, '#333')
        return format_html('<span style="background:{}; color:#fff; padding:3px 8px; border-radius:4px; font-size:11px;">{}</span>', color, obj.status)
    status_badge.short_description = 'Status'

@admin.register(FinancialMuleIdentifier)
class FinancialMuleIdentifierAdmin(admin.ModelAdmin):
    list_display = ('institution_type', 'account_number', 'account_holder_name', 'cekrekening_status', 'scan_job', 'created_at')
    list_filter = ('institution_type', 'cekrekening_status')
    search_fields = ('account_number', 'account_holder_name')

@admin.register(AuditScoreLog)
class AuditScoreLogAdmin(admin.ModelAdmin):
    list_display = ('scan_job', 'score_badge', 'final_verdict', 'is_escalated_to_regulator', 'calculated_at')
    list_filter = ('final_verdict', 'is_escalated_to_regulator')
    search_fields = ('scan_job__raw_url', 'scan_job__target_domain__domain_name')

    def score_badge(self, obj):
        score = obj.final_threat_score
        color = 'red' if score >= 80 else 'orange' if score >= 55 else 'gold' if score >= 25 else 'green'
        return format_html('<span style="font-weight:bold; color:{};">{} / 100</span>', color, score)
    score_badge.short_description = 'Threat Score'
