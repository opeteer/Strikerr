# strikerr/celery.py
import os
import functools

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'strikerr.settings.development')

try:
    from celery import Celery
    from kombu import Queue, Exchange

    app = Celery('strikerr')
    app.config_from_object('django.conf:settings', namespace='CELERY')

    default_exchange = Exchange('strikerr_exchange', type='direct')

    app.conf.task_queues = (
        Queue('triage_queue', default_exchange, routing_key='triage', queue_arguments={'x-max-priority': 5}),
        Queue('headless_queue', default_exchange, routing_key='headless', queue_arguments={'x-max-priority': 10}),
        Queue('analysis_queue', default_exchange, routing_key='analysis', queue_arguments={'x-max-priority': 5}),
    )

    app.conf.task_default_queue = 'triage_queue'
    app.conf.task_default_exchange = 'strikerr_exchange'
    app.conf.task_default_routing_key = 'triage'
    app.conf.worker_prefetch_multiplier = 1
    app.conf.task_acks_late = True
    app.conf.task_reject_on_worker_lost = True
    app.conf.worker_max_tasks_per_child = 25

    app.autodiscover_tasks()

except ImportError:
    # Graceful shim for local testing when celery is not in local python env
    class MockCelery:
        def __init__(self, name):
            self.name = name
            self.conf = {}

        def task(self, *args, **kwargs):
            bind = kwargs.get('bind', False)
            def decorator(func):
                @functools.wraps(func)
                def wrapper(*f_args, **f_kwargs):
                    if bind:
                        return func(wrapper, *f_args, **f_kwargs)
                    return func(*f_args, **f_kwargs)
                wrapper.delay = lambda *d_args, **d_kwargs: wrapper(*d_args, **d_kwargs)
                wrapper.apply_async = lambda args=(), kwargs=None, **opts: wrapper(*(args or ()), **(kwargs or {}))
                return wrapper
            if len(args) == 1 and callable(args[0]):
                return decorator(args[0])
            return decorator

        def autodiscover_tasks(self):
            pass

    app = MockCelery('strikerr')
