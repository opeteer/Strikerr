# tests/test_stream_guard.py
import pytest
import gzip
from unittest.mock import MagicMock
from strikerr.apps.crawler.security.stream_guard import SafeStreamReader, DecompressionBombException

@pytest.mark.asyncio
async def test_stream_guard_allows_normal_response():
    normal_html = b"<html><body>Normal benign landing page content</body></html>"
    
    mock_resp = MagicMock()
    mock_resp.headers = {'Content-Length': str(len(normal_html))}
    
    async def chunk_gen(chunk_size=16384):
        yield normal_html

    mock_resp.aiter_raw = chunk_gen
    content = await SafeStreamReader.read_bounded_content(mock_resp)
    assert content == normal_html

@pytest.mark.asyncio
async def test_stream_guard_blocks_huge_content_length():
    mock_resp = MagicMock()
    # 25 MB content-length (exceeds 15 MB threshold)
    mock_resp.headers = {'Content-Length': str(25 * 1024 * 1024)}
    
    with pytest.raises(DecompressionBombException) as exc:
        await SafeStreamReader.read_bounded_content(mock_resp)
    assert "exceeds maximum allowed" in str(exc.value)

@pytest.mark.asyncio
async def test_stream_guard_blocks_high_compression_ratio_bomb():
    # 1.5 MB of zeroes compressed with gzip to ~1.5 KB (ratio ~1000:1)
    huge_null_bytes = b"\x00" * (1500 * 1024)
    compressed_payload = gzip.compress(huge_null_bytes)
    
    mock_resp = MagicMock()
    mock_resp.headers = {'Content-Encoding': 'gzip'}

    async def chunk_gen(chunk_size=16384):
        yield compressed_payload

    mock_resp.aiter_raw = chunk_gen
    
    with pytest.raises(DecompressionBombException):
        await SafeStreamReader.read_bounded_content(mock_resp)
