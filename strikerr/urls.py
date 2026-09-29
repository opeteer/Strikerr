# strikerr/urls.py
from django.contrib import admin
from django.urls import path

urlpatterns = [
    path('admin/', admin.site.urls),
]

admin.site.site_header = "Strikerr SOC & Threat Hunting Console"
admin.site.site_title = "Strikerr Threat Intelligence"
admin.site.index_title = "Security Operations & Evidence Management"
