from django.urls import path
from . import views

app_name = 'monitor'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('add/', views.add_domain, name='add_domain'),
]