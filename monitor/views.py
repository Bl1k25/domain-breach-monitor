from django.shortcuts import render, redirect
from .models import CorporateDomain
from .forms import CorporateDomainForm


def dashboard(request):
    """Главная страница: список доменов"""
    domains = CorporateDomain.objects.all().order_by('name')
    return render(request, 'monitor/dashboard.html', {'domains': domains})


def add_domain(request):
    """Страница добавления домена"""
    if request.method == 'POST':
        form = CorporateDomainForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('monitor:dashboard')
    else:
        form = CorporateDomainForm()
        
    return render(request, 'monitor/domain_form.html', {
        'form': form,
        'title': 'Добавить домен'
    })