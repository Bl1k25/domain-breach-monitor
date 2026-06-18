# 🔒 Domain Breach Monitor — Система мониторинга утечек данных

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-5.2-green.svg)](https://www.djangoproject.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Domain Breach Monitor** — это веб-сервис для IT-администраторов, позволяющий оперативно выявлять факты компрометации корпоративных доменов через интеграцию с платформой **Intelligence X**. Система автоматически сканирует публичные базы утечек данных (darknet, pastes, leaks) и предоставляет детальные отчёты с визуализацией угроз.

## 🚀 Возможности

### Для IT-администраторов:
-  **Реестр доменов** — централизованное управление корпоративными доменами с указанием ответственных и уровней критичности
-  **Автоматическое сканирование** — интеграция с Intelligence X API для поиска утечек в real-time
-  **Детальные отчёты** — просмотр найденных угроз с метаданными (тип файла, источник, релевантность)
-  **Просмотр содержимого** — безопасный предпросмотр файлов утечек (текст, HEX-дамп для бинарных данных)
-  **Аналитика и визуализация** — интерактивные графики Plotly:
  - Распределение угроз по источникам (buckets)
  - Гистограмма X-Score (релевантности)
  - Динамика обнаружений во времени
  - Матрица рисков по доменам
-  **Система алертов** — цветовая индикация статуса (Clean/Warning/Critical)
-  **Экспорт данных** — возможность выгрузки результатов для отчётности

### Для суперпользователей:
- 🔧 Полное управление через Django Admin
- 🔧 Настройка политик хранения данных
- 🔧 Мониторинг использования API

---

## 🛠️ Стек технологий

### Backend
- **Python 3.10+** — основной язык
- **Django 5.2** — веб-фреймворк
- **SQLite** — база данных (по умолчанию)
- **python-dotenv** — управление переменными окружения
- **requests** — HTTP-клиент для API

### Frontend
- **Bootstrap 5** — UI-фреймворк
- **Plotly.js** — интерактивные графики
- **Vanilla JavaScript** — AJAX-запросы

### Аналитика
- **Pandas** — обработка и агрегация данных
- **Plotly Express** — визуализация

### Внешние интеграции
- **Intelligence X API v5** — платформа Threat Intelligence

### Деплой
- **PythonAnywhere** — хостинг для Python-приложений
- **Git** — система контроля версий

---

## 📦 Установка

### 1. Клонируйте репозиторий

bash
git clone https://github.com/Bl1k25/domain-breach-monitor.git
cd domain-breach-monitor

### 2. Создайте виртуальное окружение
Windows:

python -m venv venv
venv\Scripts\activate

### 3. Установите зависимости

bash
pip install -r requirements.txt

### 4. Примените миграции

bash
python manage.py createsuperuser

### Настройка
Переменные окружения
Создайте файл .env в корне проекта:
# Intelligence X API
INTELX_API_KEY=your_api_key_here
INTELX_API_URL=https://free.intelx.io

# Django
DEBUG=True
SECRET_KEY=your_secret_key_here
ALLOWED_HOSTS=localhost,127.0.0.1

### Получение API ключа:

    Зарегистрируйтесь на intelx.io
    Перейдите в Account → Developer
    Скопируйте API ключ

### Настройка core/settings.py
- Убедитесь, что в конце файла есть:

import os
from dotenv import load_dotenv

load_dotenv()

INTELX_API_KEY = os.getenv("INTELX_API_KEY")
INTELX_API_URL = os.getenv("INTELX_API_URL", "https://free.intelx.io")

### Запуск 
- Локальный сервер

bash
python manage.py runserver

- Откройте браузер: http://127.0.0.1:8000/
- Доступ к админке
- URL: http://127.0.0.1:8000/admin/
- Используйте учётные данные суперпользователя.

### Структура проекта:

domain-breach-monitor/
├── core/                    # Настройки Django
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── monitor/                 # Основное приложение
│   ├── models.py           # Модели данных
│   ├── views.py            # Представления
│   ├── urls.py             # Маршруты
│   ├── api_clients.py      # Интеграция с IntelX API
│   ├── forms.py            # Формы
│   ├── admin.py            # Настройки админки
│   └── templates/
│       └── monitor/
│           ├── base.html
│           ├── dashboard.html
│           ├── domain_form.html
│           ├── verification_details.html
│           └── threat_detail.html
├── static/                  # Статические файлы
├── media/                   # Загруженные файлы
├── .env                     # Переменные окружения (не в Git)
├── .gitignore
├── requirements.txt
├── manage.py
└── README.md

### API Интеграция Intelligence X API v5
Проект использует двухэтапный поиск:

    Инициация поиска (POST /intelligent/search)
        Отправка селектора (домена)
        Получение search_id
    Получение результатов (GET /intelligent/search/result)
        Опрос статуса (до 5 попыток)
        Извлечение записей с метаданными
    Терминация (GET /intelligent/search/terminate)
        Освобождение ресурсов сервера

### Проверить параметры
X-Score (релевантность)

    0–30: Низкая релевантность (упоминания)
    31–70: Средняя (требует анализа)
    71–100: Высокая (критический риск)