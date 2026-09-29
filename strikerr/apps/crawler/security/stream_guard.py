# strikerr/apps/crawler/security/stream_guard.py
import zlib
import httpx
from typing import AsyncIterator

class DecompressionBombException(Exception):
    """Raised when an HTTP response stream exceeds safe expansion thresholds."""
    pass

class SafeStreamReader:
    """Reads and decompresses HTTP streams with strict byte caps and ratio guards to defeat crawl-bombs."""

    MAX_RAW_BYTES = 15 * 1024 * 1024       # 15 MB max compressed download
    MAX_EXPANDED_BYTES = 30 * 1024 * 1024  # 30 MB max decompressed in-memory size
    MAX_COMPRESSION_RATIO = 10             # Alert if 1 byte expands to > 10 bytes

    @classmethod
    async def read_bounded_content(cls, response: httpx.Response) -> bytes:
        """Reads a response stream while enforcing strict payload size and expansion limits."""
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                cl_int = int(content_length)
                if cl_int > cls.MAX_RAW_BYTES:
                    raise DecompressionBombException(
                        f"Response Content-Length {cl_int} bytes exceeds maximum allowed {cls.MAX_RAW_BYTES} bytes"
                    )
            except ValueError:
                pass

        total_compressed = 0
        total_decompressed = 0
        buffer = bytearray()
        
        # 32 + MAX_WBITS enables zlib with automatic gzip and deflate header detection
        is_compressed = response.headers.get("Content-Encoding", "").lower() in ("gzip", "deflate")
        decompressor = zlib.decompressobj(32 + zlib.MAX_WBITS) if is_compressed else None

        async for chunk in response.aiter_raw(chunk_size=16384):
            total_compressed += len(chunk)
            if total_compressed > cls.MAX_RAW_BYTES:
                raise DecompressionBombException(
                    f"Raw incoming stream exceeded limit of {cls.MAX_RAW_BYTES} bytes"
                )

            if decompressor:
                try:
                    decompressed_chunk = decompressor.decompress(chunk)
                except zlib.error:
                    decompressed_chunk = chunk
                total_decompressed += len(decompressed_chunk)
                
                if total_decompressed > cls.MAX_EXPANDED_BYTES:
                    raise DecompressionBombException(
                        f"Decompressed stream exceeded {cls.MAX_EXPANDED_BYTES} bytes (Decompression Bomb Detected)"
                    )

                if total_decompressed > 500 * 1024 and total_compressed > 0:
                    ratio = total_decompressed / total_compressed
                    if ratio > cls.MAX_COMPRESSION_RATIO:
                        raise DecompressionBombException(
                            f"Abnormal compression ratio {ratio:.2f}:1 detected (Decompression Bomb Signature)"
                        )

                buffer.extend(decompressed_chunk)
            else:
                total_decompressed = total_compressed
                if total_decompressed > cls.MAX_RAW_BYTES:
                    raise DecompressionBombException(f"Uncompressed stream exceeded {cls.MAX_RAW_BYTES} bytes")
                buffer.extend(chunk)

        if decompressor:
            try:
                buffer.extend(decompressor.flush())
            except zlib.error:
                pass

        return bytes(buffer)
