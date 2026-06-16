# monitor/urls.py

from django.urls import path
from . import views

app_name = 'monitor'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('add/', views.add_domain, name='add_domain'),
    path('check/<int:domain_id>/', views.check_domain_intelx, name='check_domain'),
    path('verification/<int:verification_id>/', views.verification_details_view, name='verification_details'),
    path('threat/<int:threat_id>/', views.threat_detail_view, name='threat_detail'),
    path('threat-content/<int:threat_id>/', views.threat_content_view, name='threat_content'),
]