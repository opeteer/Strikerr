# tests/test_lexicon_engine.py
import pytest
from strikerr.apps.analyzer.lexicon.lexicon_engine import LocalizedLexiconEngine

@pytest.fixture
def lexicon_engine():
    return LocalizedLexiconEngine()

def test_detects_indonesian_judol_slang(lexicon_engine):
    sample_text = """
    Selamat datang di link alternatif agen resmi Zeus Olympus!
    Daftar slot gacor hari ini dan raih maxwin jackpot paus.
    Nikmati promo depo pulsa tanpa potongan dan scatter hitam rtp live 98%!
    """
    results = lexicon_engine.scan_text(sample_text)
    
    assert results['judol_score'] > 40
    matched_terms = [item['term'] for item in results['matched_keywords']]
    
    assert 'gacor' in matched_terms
    assert 'slot' in matched_terms
    assert 'maxwin' in matched_terms
    assert 'link alternatif' in matched_terms
    assert 'zeus olympus' in matched_terms
    assert 'depo pulsa tanpa potongan' in matched_terms

def test_detects_financial_scam_patterns(lexicon_engine):
    sample_text = """
    PEMBERITAHUAN RESMI: Aktivasi rekening dibekukan karena adanya pembaruan tarif BCA.
    Silakan instal surat undangan pernikahan apk di bawah ini untuk konfirmasi blokir kartu.
    """
    results = lexicon_engine.scan_text(sample_text)
    
    assert results['scam_score'] > 30
    matched_terms = [item['term'] for item in results['matched_keywords']]
    
    assert 'aktivasi rekening dibekukan' in matched_terms
    assert 'pembaruan tarif bca' in matched_terms
    assert 'surat undangan pernikahan apk' in matched_terms

def test_benign_content_yields_zero_score(lexicon_engine):
    sample_text = """
    Portal resmi Dinas Komunikasi dan Informatika Provinsi Jawa Barat.
    Menyediakan layanan informasi publik, berita pembangunan daerah, dan arsip data terbuka.
    """
    results = lexicon_engine.scan_text(sample_text)
    assert results['total_weight'] == 0
    assert len(results['matched_keywords']) == 0
