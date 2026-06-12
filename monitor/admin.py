from django.contrib import admin
from .models import CorporateDomain, BreachRecord, VerificationLog


@admin.register(CorporateDomain)
class CorporateDomainAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "criticality", "is_active", "created_at")
    list_filter = ("criticality", "is_active", "created_at")
    search_fields = ("name", "owner")
    ordering = ("name",)


@admin.register(BreachRecord)
class BreachRecordAdmin(admin.ModelAdmin):
    list_display = ("domain", "breach_name", "breach_date", "accounts_count", "discovered_at")
    list_filter = ("breach_date", "domain__criticality")
    search_fields = ("domain__name", "breach_name", "data_classes")
    ordering = ("-breach_date",)


@admin.register(VerificationLog)
class VerificationLogAdmin(admin.ModelAdmin):
    list_display = ("domain", "status", "checked_at", "breaches_found")
    list_filter = ("status", "domain__criticality", "checked_at")
    search_fields = ("domain__name", "risk_comment")
    ordering = ("-checked_at",)