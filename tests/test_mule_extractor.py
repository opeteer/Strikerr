# tests/test_mule_extractor.py
import pytest
from strikerr.apps.analyzer.extractors.mule_extractor import FinancialMuleExtractor

def test_extracts_bca_and_mandiri_mules():
    content = """
    Untuk deposit instan, transfer ke:
    Bank BCA: 8820192831 a/n SL** GACOR
    Bank Mandiri: 1400019283912 atas nama JOKO TINGKIR
    """
    mules = FinancialMuleExtractor.extract_mules(content)
    assert len(mules) >= 2
    
    bca_mule = next((m for m in mules if m['institution_type'] == 'BCA'), None)
    assert bca_mule is not None
    assert bca_mule['account_number'] == '8820192831'
    assert 'SL** GACOR' in bca_mule['account_holder_name']

    mandiri_mule = next((m for m in mules if m['institution_type'] == 'MANDIRI'), None)
    assert mandiri_mule is not None
    assert mandiri_mule['account_number'] == '1400019283912'
    assert 'JOKO TINGKIR' in mandiri_mule['account_holder_name']

def test_extracts_indonesian_ewallet_mules():
    content = """
    Deposit E-Wallet Bebas Potongan:
    DANA: 081299882233
    OVO: 085711223344
    GOPAY: 087855443322
    """
    mules = FinancialMuleExtractor.extract_mules(content)
    institutions = {m['institution_type']: m['account_number'] for m in mules}
    
    assert institutions.get('DANA') == '081299882233'
    assert institutions.get('OVO') == '085711223344'
    assert institutions.get('GOPAY') == '087855443322'

def test_extracts_qris_static_payload():
    content = """
    Scan QRIS berikut untuk deposit otomatis:
    00020101021126580016ID.CO.QRIS.WWW011893600999000000000102150000000000000015204581253033605802ID
    """
    mules = FinancialMuleExtractor.extract_mules(content)
    qris_mule = next((m for m in mules if m['institution_type'] == 'QRIS'), None)
    assert qris_mule is not None
    assert qris_mule['qris_raw_payload'].startswith('00020101')
