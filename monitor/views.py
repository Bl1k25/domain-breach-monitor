from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import CorporateDomain, BreachRecord, VerificationLog
from .forms import CorporateDomainForm
from .api_clients import query_intelx
import datetime


def dashboard(request):
    """Главная страница: список доменов с последними проверками"""
    domains = CorporateDomain.objects.all().order_by('name')
    
    # Добавляем последние проверки для отображения в шаблоне
    for domain in domains:
        last_check = domain.verifications.order_by('-checked_at').first()
        domain.last_status = last_check.status if last_check else None
        domain.last_score = last_check.risk_comment if last_check else None
    
    return render(request, 'monitor/dashboard.html', {'domains': domains})


def add_domain(request):
    """Страница добавления домена"""
    if request.method == 'POST':
        form = CorporateDomainForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, f"Домен {form.cleaned_data['name']} добавлен")
            return redirect('monitor:dashboard')
    else:
        form = CorporateDomainForm()
    return render(request, 'monitor/domain_form.html', {'form': form, 'title': 'Добавить домен'})


def check_domain_intelx(request, domain_id):
    """Запускает проверку домена через IntelX API"""
    domain = get_object_or_404(CorporateDomain, id=domain_id)
    
    try:
        result = query_intelx(domain.name, indicator_type="domain")
        
        # Показываем сообщение пользователю
        if result.get("error"):
            messages.warning(request, f"API: {result['error']}")
        else:
            messages.success(request, f"Проверка завершена: {result['category']}")
        
        # Сохраняем запись об угрозе (даже если угроз нет — для статистики)
        BreachRecord.objects.create(
            domain=domain,
            breach_name=result["category"],
            breach_date=result["last_seen"] or datetime.date.today(),
            data_classes=f"Score: {result['threat_score']}",
            accounts_count=0,
            source=result["source"]
        )
        
        # Определяем статус для журнала проверок
        score = result["threat_score"]
        if score > 70:
            status = "Critical"
        elif score > 30:
            status = "Warning"
        else:
            status = "Clean"
        
        # Сохраняем лог проверки
        VerificationLog.objects.create(
            domain=domain,
            status=status,
            breaches_found=1 if score > 0 else 0,
            risk_comment=f"IntelX Score: {score}"
        )
        
    except ValueError as e:
        messages.error(request, f"Ошибка конфигурации: {str(e)}")
    except Exception as e:
        messages.error(request, f"Непредвиденная ошибка: {str(e)}")
    
    return redirect("monitor:dashboard")