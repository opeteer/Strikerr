# strikerr/apps/vault/storage_client.py
import os
import hashlib
from io import BytesIO
from typing import Dict, Any, Tuple
from django.conf import settings

try:
    from minio import Minio
    HAS_MINIO = True
except ImportError:
    HAS_MINIO = False

class EvidenceStorageClient:
    """Manages forensic evidence artifacts in MinIO S3 Object Storage with local fallback."""

    def __init__(self):
        self.endpoint = getattr(settings, 'MINIO_ENDPOINT', 'localhost:9000')
        self.access_key = getattr(settings, 'MINIO_ACCESS_KEY', 'strikerr_minio_admin')
        self.secret_key = getattr(settings, 'MINIO_SECRET_KEY', 'strikerr_minio_secret_key')
        self.bucket_name = getattr(settings, 'MINIO_BUCKET_NAME', 'strikerr-artifacts')
        self.use_ssl = getattr(settings, 'MINIO_USE_SSL', False)
        self.client = None

        if HAS_MINIO:
            try:
                self.client = Minio(
                    self.endpoint,
                    access_key=self.access_key,
                    secret_key=self.secret_key,
                    secure=self.use_ssl
                )
            except Exception:
                self.client = None

    def store_artifact(
        self, 
        scan_job_id: str, 
        asset_type: str, 
        content_bytes: bytes, 
        file_extension: str = "bin"
    ) -> Dict[str, Any]:
        """Saves artifact blob and returns storage path, sha256 digest, and size in bytes."""
        file_sha256 = hashlib.sha256(content_bytes).hexdigest()
        file_size = len(content_bytes)
        object_key = f"scans/{scan_job_id}/{asset_type}_{file_sha256[:12]}.{file_extension}"

        # 1. Attempt upload to MinIO S3
        if self.client:
            try:
                if not self.client.bucket_exists(self.bucket_name):
                    self.client.make_bucket(self.bucket_name)

                stream = BytesIO(content_bytes)
                self.client.put_object(
                    self.bucket_name,
                    object_key,
                    stream,
                    length=file_size
                )
                return {
                    'storage_backend': 'MINIO',
                    'storage_path': f"s3://{self.bucket_name}/{object_key}",
                    'file_sha256': file_sha256,
                    'file_size_bytes': file_size
                }
            except Exception:
                pass

        # 2. Local filesystem storage fallback with /tmp resilience
        local_base = getattr(settings, 'MEDIA_ROOT', None) or os.path.join(settings.BASE_DIR, 'media')
        local_dir = os.path.join(local_base, 'artifacts', scan_job_id)
        try:
            os.makedirs(local_dir, exist_ok=True)
        except OSError:
            local_dir = os.path.join('/tmp', 'strikerr', 'artifacts', scan_job_id)
            os.makedirs(local_dir, exist_ok=True)

        local_file = os.path.join(local_dir, f"{asset_type}_{file_sha256[:12]}.{file_extension}")
        
        with open(local_file, 'wb') as f:
            f.write(content_bytes)

        return {
            'storage_backend': 'LOCAL',
            'storage_path': local_file,
            'file_sha256': file_sha256,
            'file_size_bytes': file_size
        }
