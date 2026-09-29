# tests/conftest.py
import os
import pytest
import django
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'strikerr.settings.development')

def pytest_configure():
    # Enforce in-memory SQLite for test suite
    settings.DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
    if not settings.configured:
        django.setup()
    else:
        django.setup()
        
    from django.core.management import call_command
    call_command('migrate', verbosity=0)
