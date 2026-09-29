# strikerr/settings/base.py
import os
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = os.environ.get('SECRET_KEY', 'strikerr-dev-insecure-key-change-in-production-^9#z!k1@0')

DEBUG = False

ALLOWED_HOSTS = [h.strip() for h in os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1,[::1]').split(',') if h.strip()]

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Strikerr Apps
    'strikerr.apps.threats.apps.ThreatsConfig',
    'strikerr.apps.crawler.apps.CrawlerConfig',
    'strikerr.apps.analyzer.apps.AnalyzerConfig',
    'strikerr.apps.vault.apps.VaultConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'strikerr.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'strikerr.wsgi.application'
ASGI_APPLICATION = 'strikerr.asgi.application'

# Database Configuration with Environment URL support
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    parsed_db = urlparse(DATABASE_URL)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': parsed_db.path.lstrip('/'),
            'USER': parsed_db.username,
            'PASSWORD': parsed_db.password,
            'HOST': parsed_db.hostname,
            'PORT': parsed_db.port or 5432,
            'CONN_MAX_AGE': 600,
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Jakarta'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static'] if (BASE_DIR / 'static').exists() else []

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Celery Configuration
CELERY_BROKER_URL = os.environ.get('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672//')
CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# MinIO / AWS S3 Evidence Storage Settings
MINIO_ENDPOINT = os.environ.get('MINIO_ENDPOINT', 'localhost:9000')
MINIO_ACCESS_KEY = os.environ.get('MINIO_ACCESS_KEY', 'strikerr_minio_admin')
MINIO_SECRET_KEY = os.environ.get('MINIO_SECRET_KEY', 'strikerr_minio_secret_key')
MINIO_BUCKET_NAME = os.environ.get('MINIO_BUCKET_NAME', 'strikerr-artifacts')
MINIO_USE_SSL = os.environ.get('MINIO_USE_SSL', 'False').lower() in ('true', '1', 't')

# Egress Proxies (Indonesian Residential)
ID_RESIDENTIAL_PROXY_URL = os.environ.get('ID_RESIDENTIAL_PROXY_URL', '')
PROXY_ROTATOR_ENABLED = os.environ.get('PROXY_ROTATOR_ENABLED', 'False').lower() in ('true', '1', 't')

# Crawler Guardrails
CRAWLER_TIMEOUT_SECONDS = int(os.environ.get('CRAWLER_TIMEOUT_SECONDS', '12'))
MAX_REDIRECT_HOPS = int(os.environ.get('MAX_REDIRECT_HOPS', '5'))
MAX_DOM_NODES = int(os.environ.get('MAX_DOM_NODES', '25000'))
MAX_DOM_DEPTH = int(os.environ.get('MAX_DOM_DEPTH', '64'))
MAX_EXPANDED_STREAM_BYTES = int(os.environ.get('MAX_EXPANDED_STREAM_BYTES', '31457280'))  # 30 MB
