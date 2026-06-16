from django.db import models
from django.core.validators import RegexValidator
from django.utils import timezone
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator

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
    
class ThreatDetail(models.Model):
    
    verification = models.ForeignKey(
        VerificationLog,
        on_delete=models.CASCADE,
        related_name='threats',
        help_text="Связанная проверка"
    )
    
    # Идентификаторы 
    system_id = models.CharField(
        max_length=100,
        help_text="System ID для формирования ссылки"
    )
    storage_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="ID для доступа к содержимому файла через /file/read"
    )

    # Основная информация 
    name = models.CharField(
        max_length=255,
        blank=True,
        help_text="Название или заголовок записи"
    )
    xscore = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Релевантность (0-100). Показывает вероятность реальной угрозы"
    )
    bucket = models.CharField(
        max_length=100,
        help_text="Тип базы (например, pastes, darknet.tor, leaks.public)"
    )
    
    # Типы данных 
    media_type = models.CharField(
        max_length=50,
        help_text="Человекочитаемый тип контента (Paste, PDF, и т.д.)"
    )
    size = models.PositiveIntegerField(
        default=0,
        help_text="Размер данных в байтах"
    )

    # Даты 
    date_found = models.DateTimeField(
        help_text="Дата оригинальной записи или индексации"
    )
    
    discovered_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Когда наша система нашла эту запись"
    )

    class Meta:
        verbose_name = "Деталь угрозы IntelX"
        verbose_name_plural = "Детали угроз IntelX"
        ordering = ['-xscore', '-date_found']
        indexes = [
            models.Index(fields=['-xscore']),
            models.Index(fields=['bucket']),
        ]

    def __str__(self):
        return f"{self.bucket} | {self.media_type} (Score: {self.xscore})"

    @property
    def intelx_url(self):
        """Генерирует прямую ссылку на результат"""
        return f"https://intelx.io/?did={self.system_id}"
    
    @property
    def size_human(self):
        """Возвращает размер в человекочитаемом формате"""
        if self.size < 1024:
            return f"{self.size} B"
        elif self.size < 1024 * 1024:
            return f"{self.size / 1024:.1f} KB"
        elif self.size < 1024 * 1024 * 1024:
            return f"{self.size / (1024 * 1024):.1f} MB"
        else:
            return f"{self.size / (1024 * 1024 * 1024):.1f} GB"
    
    @property
    def is_high_risk(self):
        """Быстрая проверка: является ли запись высокорисковой"""
        return self.xscore > 70