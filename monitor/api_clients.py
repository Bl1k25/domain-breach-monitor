import requests
import time
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

# Маппинг типов (добавьте свои, если нужно расширить)
INTELX_TYPE_MAP = {
    
    "domain": 2,
    "email": 3,
    "url": 4
}
def _parse_date(date_string):
    """Преобразует ISO 8601 дату в формат YYYY-MM-DD"""
    if not date_string:
        return None
    
    try:
        # Если дата в формате ISO 8601 (с временем)
        if "T" in date_string:
            return date_string.split("T")[0]
        # Если уже в формате YYYY-MM-DD
        return date_string
    except Exception:
        return None
    
def query_intelx(indicator: str, indicator_type: str = "domain") -> dict:
    """
    Выполняет поиск в Intelligence X согласно официальной документации (v5, 2022).
    """
    # 1. Валидация и настройки
    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("indicator должен быть непустой строкой")
    
    indicator = indicator.strip()
    indicator_type = indicator_type.lower()
    
    if indicator_type not in INTELX_TYPE_MAP:
        raise ValueError(f"Неподдерживаемый тип индикатора: {indicator_type}")

    api_key = getattr(settings, "INTELX_API_KEY", None)
    base_url = getattr(settings, "INTELX_API_URL", "https://public.intelx.io").rstrip('/')
    
    if not api_key:
        raise ValueError("INTELX_API_KEY не найден в настройках")

    headers = {
        "x-key": api_key,
        "Content-Type": "application/json",
        "User-Agent": "DomainBreachMonitor/1.1"
    }

    search_id = None

    try:
        #ЭТАП 1: Инициация поиска 
        search_url = f"{base_url}/intelligent/search"
        search_payload = {
            "term": indicator,
            "buckets": [],      # Пусто = все доступные бакеты 
            "lookuplevel": 0,   # Всегда 0 
            "maxresults": 10,
            "timeout": 0,       # 0 = default 
            "datefrom": "",     # Пустые строки для полноты схемы 
            "dateto": "",
            "sort": 4,          # 4 = Date DESC, самые новые
            "media": 0,         # 0 = все типы
            "terminate": []     # Список ID для закрытия старых поисков
        }

        logger.info(f"IntelX: Starting search for {indicator}")
        search_resp = requests.post(search_url, headers=headers, json=search_payload, timeout=10)
        search_resp.raise_for_status()
        
        search_data = search_resp.json()
        search_id = search_data.get("id")
        
        if search_data.get("status") != 0 or not search_id:
            return {"threat_score": 0, "category": "API Error", "last_seen": None, "source": "IntelX", "error": "Search initialization failed"}

        # ЭТАП 2: Получение результатов в цикле 
        # Документация требует ждать минимум 400ms и проверять статус
        result_url = f"{base_url}/intelligent/search/result"
        records = []
        
        # Делаем до 5 попыток опроса, если статус 3 (результаты еще готовятся)
        for attempt in range(5):
            time.sleep(1.0) # Спим 1 сек между попытками
            
            result_params = {"id": search_id, "limit": 10}
            result_resp = requests.get(result_url, headers=headers, params=result_params, timeout=10)
            result_resp.raise_for_status()
            
            result_data = result_resp.json()
            status = result_data.get("status")
            records = result_data.get("records", [])

            if status in [0, 1]: 
                # 0 = Успех с данными, 1 = Поиск завершен
                break
            elif status == 3:
                # 3 = "No results yet available but keep trying" 
                logger.info(f"IntelX: Search {search_id} in progress (attempt {attempt+1})...")
                continue
            elif status == 2:
                # 2 = Search ID not found
                break

        # ЭТАП 3: Терминация поиска 
        if search_id:
            try:
                terminate_url = f"{base_url}/intelligent/search/terminate"
                requests.get(terminate_url, headers=headers, params={"id": search_id}, timeout=5)
            except Exception as e:
                logger.warning(f"IntelX: Failed to terminate search {search_id}: {e}")

        #ЭТАП 4: Обработка данных 
        if not records:
            return {
                "threat_score": 0, "category": "No Threats",
                "last_seen": None, "source": "IntelX", "error": None
            }

        # Берем самый свежий результат
        latest = records[0]
        
        # Маппинг медиа-типов
        media_map = {
            1: "Paste", 9: "Web Copy", 13: "Tweet", 14: "URL", 15: "PDF",
            16: "Word", 21: "Video", 23: "HTML", 24: "Text"
        }
        media_type = media_map.get(latest.get("media"), "Document")
        bucket = latest.get("bucket", "leak")
        
        return {
            "threat_score": latest.get("xscore", 0), 
            "category": f"{media_type} ({bucket})",
            "last_seen": _parse_date(latest.get("date")) or _parse_date(latest.get("added")),
            "source": "IntelX",
            "error": None,
            "system_id": latest.get("systemid") # Для построения прямой ссылки 
        }

    # Обработка исключений
    except requests.Timeout:
        return {"threat_score": 0, "category": "Timeout", "last_seen": None, "source": "IntelX", "error": "Timeout"}
    except requests.HTTPError as exc:
        # Обработка 401 (нет прав), 402 (нет кредитов)
        return {"threat_score": 0, "category": "HTTP Error", "last_seen": None, "source": "IntelX", "error": f"Status {exc.response.status_code}"}
    except Exception as exc:
        logger.error(f"IntelX API Error: {exc}")
        return {"threat_score": 0, "category": "Error", "last_seen": None, "source": "IntelX", "error": str(exc)}