# monitor/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import CorporateDomain, BreachRecord, VerificationLog, ThreatDetail
from .forms import CorporateDomainForm
from .api_clients import query_intelx
import datetime


def dashboard(request):
    """Главная страница: список доменов с последними проверками"""
    domains = CorporateDomain.objects.all().order_by('name')
    
    # Добавляем последние проверки для отображения
    for domain in domains:
        last_check = domain.verifications.order_by('-checked_at').first()
        domain.last_status = last_check.status if last_check else None
        domain.last_score = last_check.risk_comment if last_check else None
        domain.last_verification_id = last_check.id if last_check else None
    
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
        
        if result.get("error"):
            messages.warning(request, f"API: {result['error']}")
        else:
            messages.success(request, f"Проверка завершена: {result['category']}")
        
        # Сохраняем основную запись об утечке
        BreachRecord.objects.create(
            domain=domain,
            breach_name=result["category"],
            breach_date=result["last_seen"] or datetime.date.today(),
            data_classes=f"Score: {result['threat_score']}",
            accounts_count=0,
            source=result["source"]
        )
        
        # Определяем статус
        score = result["threat_score"]
        status = "Critical" if score > 70 else "Warning" if score > 30 else "Clean"
        
        # Создаём лог проверки
        verification = VerificationLog.objects.create(
            domain=domain,
            status=status,
            breaches_found=len(result.get("records", [])),
            risk_comment=f"IntelX Score: {score}"
        )
        
        # Сохраняем детали найденных записей
        from django.utils import timezone
        
        for record_data in result.get("records", []):
            # Парсинг дат
            date_found = record_data.get("date_found") or record_data.get("date_original")
            if date_found and isinstance(date_found, str) and "T" in date_found:
                date_found = date_found.replace("Z", "+00:00")
                try:
                    date_found = timezone.datetime.fromisoformat(date_found)
                except:
                    date_found = timezone.now()
            elif not date_found:
                date_found = timezone.now()
            
            ThreatDetail.objects.create(
                verification=verification,
                system_id=record_data["system_id"],
                storage_id=record_data.get("storage_id", ""),
                name=record_data.get("name", ""),
                xscore=record_data["xscore"],
                bucket=record_data["bucket"],
                media_type=record_data["media_type_human"],
                size=record_data["size"],
                date_found=date_found,
            )
        
    except ValueError as e:
        messages.error(request, f"Ошибка конфигурации: {str(e)}")
    except Exception as e:
        messages.error(request, f"Непредвиденная ошибка: {str(e)}")
    
    return redirect("monitor:dashboard")


def threat_detail_view(request, threat_id):
    """Детальная страница с ВСЕЙ информацией из IntelX"""
    threat = get_object_or_404(ThreatDetail, id=threat_id)
    
    context = {
        'threat': threat,
        'verification': threat.verification,
        'domain': threat.verification.domain
    }
    
    return render(request, 'monitor/threat_detail.html', context)


def verification_details_view(request, verification_id):
    """Страница со списком всех угроз для одной проверки"""
    verification = get_object_or_404(VerificationLog, id=verification_id)
    threats = verification.threats.all()
    
    context = {
        'verification': verification,
        'threats': threats,
        'domain': verification.domain
    }
    
    return render(request, 'monitor/verification_details.html', context)