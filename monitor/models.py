from django.db import models
from django.core.validators import RegexValidator
from django.utils import timezone


class CorporateDomain(models.Model):
    """Реестр корпоративных доменов компании"""

    class Criticality(models.TextChoices):
        LOW = 'Low', 'Низкий'
        MEDIUM = 'Medium', 'Средний'
        HIGH = 'High', 'Высокий'

    domain_validator = RegexValidator(
        regex=r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        message='Введите корректное доменное имя'
    )

    name = models.CharField(
        max_length=100,
        unique=True,
        validators=[domain_validator],
        help_text="Доменное имя (например, company.ru)"
    )

    owner = models.CharField(
        max_length=150,
        help_text="Ответственный сотрудник"
    )

    criticality = models.CharField(
        max_length=10,
        choices=Criticality.choices,
        default=Criticality.MEDIUM,
        help_text="Уровень критичности"
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Мониторинг включён"
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Корпоративный домен"
        verbose_name_plural = "Корпоративные домены"
        ordering = ["name"]

    def __str__(self):
        return f"{self.name}"
    

class BreachRecord(models.Model):
    """Информация об обнаруженной утечке"""

    domain = models.ForeignKey(
        CorporateDomain,
        on_delete=models.CASCADE,
        related_name="breaches"
    )

    breach_name = models.CharField(
        max_length=150,
        help_text="Название утечки"
    )

    breach_date = models.DateField(
        help_text="Дата утечки"
    )

    data_classes = models.TextField(
        help_text="Типы скомпрометированных данных"
    )

    accounts_count = models.PositiveIntegerField(
        default=0,
        help_text="Количество затронутых аккаунтов"
    )

    source = models.CharField(
        max_length=100,
        default="HaveIBeenPwned",
        help_text="Источник информации"
    )

    discovered_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        verbose_name = "Запись об утечке"
        verbose_name_plural = "Записи об утечках"
        ordering = ["-breach_date"]

    def __str__(self):
        return f"{self.domain.name} - {self.breach_name}"


class VerificationLog(models.Model):
    """История проверок доменов"""

    class Status(models.TextChoices):
        CLEAN = 'Clean', 'Чисто'
        WARNING = 'Warning', 'Предупреждение'
        CRITICAL = 'Critical', 'Критично'

    domain = models.ForeignKey(
        CorporateDomain,
        on_delete=models.CASCADE,
        related_name="verifications"
    )

    checked_at = models.DateTimeField(
        default=timezone.now
    )

    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.CLEAN
    )

    breaches_found = models.PositiveIntegerField(
        default=0
    )

    risk_comment = models.TextField(
        blank=True,
        null=True
    )

    class Meta:
        verbose_name = "Журнал проверки"
        verbose_name_plural = "Журналы проверок"
        ordering = ["-checked_at"]

    def __str__(self):
        return (
            f"{self.domain.name} - "
            f"{self.status} - "
            f"{self.checked_at.strftime('%d.%m.%Y %H:%M')}"
        )