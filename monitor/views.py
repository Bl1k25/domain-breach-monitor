# monitor/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from .models import CorporateDomain, BreachRecord, VerificationLog, ThreatDetail
from .forms import CorporateDomainForm
from .api_clients import query_intelx
from .api_clients import query_intelx, get_file_preview
import datetime
import logging
import pandas as pd
import plotly.express as px
import plotly.io as pio
from django.db.models import Count, Avg, Q
from django.utils import timezone
from datetime import timedelta

logger = logging.getLogger(__name__)

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

from django.http import JsonResponse

def threat_content_view(request, threat_id):
    if request.method != 'POST':
        return JsonResponse({"error": "Метод не поддерживается"}, status=405)

    threat = get_object_or_404(ThreatDetail, id=threat_id)
    
    if not threat.storage_id:
        return JsonResponse({"error": "Нет доступного файла"})

    result = get_file_preview(
        storage_id=threat.storage_id,
        bucket=threat.bucket,
        media_type=24,      # Text file
        content_type=1      # Plain text
    )

    if result["success"]:
        preview_text = result["content"][:800]
        from django.utils.html import escape
        safe_text = escape(preview_text)
        
        return JsonResponse({"content": safe_text})
    else:
        return JsonResponse({"error": result["error"]}, status=400)

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

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect

def delete_domain(request, domain_id):
    """Удаляет домен и все связанные данные (отчёты, проверки, угрозы)"""
    if request.method == 'POST':
        domain = get_object_or_404(CorporateDomain, id=domain_id)
        domain_name = domain.name
        domain.delete()  # CASCADE автоматически удалит BreachRecord, VerificationLog, ThreatDetail
        messages.success(request, f'Домен {domain_name} и все связанные данные успешно удалены.')
    
    return redirect('monitor:dashboard')

def get_analytics_data(request):
    """
    Генерирует аналитические данные и графики Plotly.
    Возвращает dict с HTML-строками графиков для вставки в шаблон.
    """
    # Собираем данные из БД в DataFrame
    threats = ThreatDetail.objects.select_related('verification__domain').values(
        'xscore',
        'bucket',
        'media_type',
        'date_found',
        'verification__domain__name',
        'verification__domain__criticality'
    )
    
    df = pd.DataFrame(list(threats))
    
    if df.empty:
        return {
            'bucket_chart': '<p class="text-muted">Недостаточно данных для аналитики</p>',
            'score_chart': '<p class="text-muted">Недостаточно данных для аналитики</p>',
            'timeline_chart': '<p class="text-muted">Недостаточно данных для аналитики</p>',
            'risk_matrix': '<p class="text-muted">Недостаточно данных для аналитики</p>',
        }
    
    # Преобразуем даты
    df['date_found'] = pd.to_datetime(df['date_found'], errors='coerce')
    
    #  График 1: Распределение по bucket (топ-10)
    bucket_counts = df['bucket'].value_counts().head(10).reset_index()
    bucket_counts.columns = ['bucket', 'count']
    
    fig_bucket = px.pie(
        bucket_counts, 
        names='bucket', 
        values='count',
        title='🔍 Топ-10 источников угроз',
        color_discrete_sequence=px.colors.sequential.RdBu,
        hole=0.3  # Donut chart
    )
    fig_bucket.update_traces(textposition='inside', textinfo='percent+label')
    fig_bucket.update_layout(height=400, margin=dict(t=30, b=0, l=0, r=0))
    
    #  График 2: Распределение X-Score
    fig_score = px.histogram(
        df, 
        x='xscore', 
        nbins=20,
        title='🎯 Распределение релевантности (X-Score)',
        color_discrete_sequence=['#6366f1'],
        labels={'xscore': 'X-Score', 'count': 'Количество записей'}
    )
    fig_score.add_vline(x=30, line_dash="dash", line_color="orange", annotation_text="Warning")
    fig_score.add_vline(x=70, line_dash="dash", line_color="red", annotation_text="Critical")
    fig_score.update_layout(height=350, margin=dict(t=30, b=0, l=0, r=0))
    
    #  График 3: Временная шкала обнаружений
    df['date_short'] = df['date_found'].dt.date
    timeline = df.groupby('date_short').size().reset_index(name='count')
    
    fig_timeline = px.line(
        timeline, 
        x='date_short', 
        y='count',
        title='📅 Динамика обнаружений угроз',
        markers=True,
        color_discrete_sequence=['#10b981']
    )
    fig_timeline.update_layout(height=300, margin=dict(t=30, b=0, l=0, r=0), xaxis_title='Дата')
    
    #  График 4: Матрица рисков (домен × критичность)
    risk_data = df.groupby(['verification__domain__name', 'verification__domain__criticality']).agg(
        avg_score=('xscore', 'mean'),
        threat_count=('xscore', 'count')
    ).reset_index()
    
    # Добавляем цветовой индикатор риска
    risk_data['risk_level'] = risk_data['avg_score'].apply(
        lambda x: 'High' if x > 70 else 'Medium' if x > 30 else 'Low'
    )
    
    fig_risk = px.scatter(
        risk_data,
        x='verification__domain__name',
        y='verification__domain__criticality',
        size='threat_count',
        color='risk_level',
        color_discrete_map={'Low': '#22c55e', 'Medium': '#f59e0b', 'High': '#ef4444'},
        title='🔴 Матрица рисков по доменам',
        hover_data=['avg_score'],
        size_max=40
    )
    fig_risk.update_layout(height=400, margin=dict(t=30, b=40, l=0, r=0), xaxis_title='Домен', yaxis_title='Критичность')
    
    # Конвертируем графики в HTML
    return {
        'bucket_chart': pio.to_html(fig_bucket, full_html=False, include_plotlyjs='cdn'),
        'score_chart': pio.to_html(fig_score, full_html=False, include_plotlyjs=False),
        'timeline_chart': pio.to_html(fig_timeline, full_html=False, include_plotlyjs=False),
        'risk_matrix': pio.to_html(fig_risk, full_html=False, include_plotlyjs=False),
    }

def dashboard(request):
    """Главная страница с таблицей доменов и аналитикой"""
    domains = CorporateDomain.objects.all().order_by('name')
    
    # Добавляем последние проверки для отображения
    for domain in domains:
        last_check = domain.verifications.order_by('-checked_at').first()
        domain.last_status = last_check.status if last_check else None
        domain.last_score = last_check.risk_comment if last_check else None
        domain.last_verification_id = last_check.id if last_check else None
    
    #  Генерируем аналитику
    analytics = get_analytics_data(request)
    
    context = {
        'domains': domains,
        **analytics  # Распаковываем графики в контекст
    }
    
    return render(request, 'monitor/dashboard.html', context)