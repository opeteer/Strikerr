# strikerr/settings/development.py
from .base import *

DEBUG = True

ALLOWED_HOSTS = ['*']

# Allow override of SQLite database path (e.g. /tmp/dev.sqlite3 in restricted sandboxes)
if not os.environ.get('DATABASE_URL'):
    db_file = os.environ.get('SQLITE_DB_PATH')
    if not db_file:
        # Default to local db.sqlite3, with /tmp fallback if local is read-only
        db_file = BASE_DIR / 'db.sqlite3'
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': db_file,
        }
    }

# Celery in development can run synchronously for testing if CELERY_TASK_ALWAYS_EAGER is set
if os.environ.get('CELERY_ALWAYS_EAGER', 'False').lower() in ('true', '1'):
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{asctime}] {levelname} [{name}:{lineno}] {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'strikerr': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
