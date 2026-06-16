from django.contrib import admin
from .models import CorporateDomain, BreachRecord, VerificationLog, ThreatDetail


@admin.register(CorporateDomain)
class CorporateDomainAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'criticality', 'is_active', 'created_at')
    list_filter = ('criticality', 'is_active')
    search_fields = ('name', 'owner')
    ordering = ('name',)


@admin.register(BreachRecord)
class BreachRecordAdmin(admin.ModelAdmin):
    list_display = ('domain', 'breach_name', 'breach_date', 'accounts_count', 'source')
    list_filter = ('source', 'breach_date', 'domain__criticality')
    search_fields = ('domain__name', 'breach_name', 'data_classes')
    ordering = ('-breach_date',)
    readonly_fields = ('discovered_at',)


@admin.register(VerificationLog)
class VerificationLogAdmin(admin.ModelAdmin):
    list_display = ('domain', 'status', 'checked_at', 'breaches_found')
    list_filter = ('status', 'domain__criticality', 'checked_at')
    search_fields = ('domain__name', 'risk_comment')
    ordering = ('-checked_at',)
    readonly_fields = ('checked_at',)


@admin.register(ThreatDetail)
class ThreatDetailAdmin(admin.ModelAdmin):
    list_display = ('name', 'bucket', 'media_type', 'xscore', 'date_found', 'intelx_url_link')
    list_filter = ('bucket', 'media_type', 'verification__domain')
    search_fields = ('name', 'system_id', 'bucket')
    ordering = ('-xscore', '-date_found')
    readonly_fields = ('discovered_at', 'intelx_url_display')
    
    def intelx_url_link(self, obj):
        """Кликабельная ссылка в админке"""
        from django.utils.html import format_html
        return format_html('<a href="{}" target="_blank">Открыть в IntelX</a>', obj.intelx_url)
    intelx_url_link.short_description = "IntelX"
    
    def intelx_url_display(self, obj):
        """Отображение ссылки как текст"""
        return obj.intelx_url
    intelx_url_display.short_description = "URL"