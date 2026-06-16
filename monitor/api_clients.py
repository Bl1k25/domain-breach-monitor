import requests
import time
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

# Маппинг типов индикаторов
INTELX_TYPE_MAP = {
    "domain": 2,
    "email": 3,
    "url": 4,
    "ip": 1  # Добавил для полноты
}

def _parse_date(date_string):
    """Преобразует ISO 8601 дату в формат YYYY-MM-DD"""
    if not date_string:
        return None
    try:
        if "T" in date_string:
            return date_string.split("T")[0]
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
        # ЭТАП 1: Инициация поиска 
        search_url = f"{base_url}/intelligent/search"
        search_payload = {
            "term": indicator,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 10,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0,
            "terminate": []
        }

        logger.info(f"IntelX: Starting search for {indicator}")
        search_resp = requests.post(search_url, headers=headers, json=search_payload, timeout=10)
        search_resp.raise_for_status()
        
        search_data = search_resp.json()
        search_id = search_data.get("id")
        
        if search_data.get("status") != 0 or not search_id:
            return {"threat_score": 0, "category": "API Error", "last_seen": None, "source": "IntelX", "error": "Search initialization failed", "records": []}

        # ЭТАП 2: Получение результатов в цикле 
        result_url = f"{base_url}/intelligent/search/result"
        records = []
        
        for attempt in range(5):
            time.sleep(1.0)
            
            result_params = {"id": search_id, "limit": 10}
            result_resp = requests.get(result_url, headers=headers, params=result_params, timeout=10)
            result_resp.raise_for_status()
            
            result_data = result_resp.json()
            status = result_data.get("status")
            records = result_data.get("records", [])

            if status in [0, 1]: 
                break
            elif status == 3:
                logger.info(f"IntelX: Search {search_id} in progress (attempt {attempt+1})...")
                continue
            elif status == 2:
                break

        # ЭТАП 3: Терминация поиска 
        if search_id:
            try:
                terminate_url = f"{base_url}/intelligent/search/terminate"
                requests.get(terminate_url, headers=headers, params={"id": search_id}, timeout=5)
            except Exception as e:
                logger.warning(f"IntelX: Failed to terminate search {search_id}: {e}")

        # ЭТАП 4: Обработка данных 
        if not records:
            return {
                "threat_score": 0, "category": "No Threats",
                "last_seen": None, "source": "IntelX", "error": None, "records": []
            }

        # 🆕 Формируем список threat_details из записей API
        threat_details = []
        media_map = {
            1: "Paste", 2: "Paste User", 3: "Forum", 4: "Forum Board",
            5: "Forum Thread", 6: "Forum Post", 7: "Forum User",
            8: "Screenshot", 9: "Web Copy", 13: "Tweet", 14: "URL",
            15: "PDF", 16: "Word", 17: "Excel", 18: "PowerPoint",
            19: "Picture", 20: "Audio", 21: "Video", 22: "Container",
            23: "HTML", 24: "Text"
        }
    
        for record in records[:10]:  # Берём топ-10
            threat_details.append({
                "system_id": record.get("systemid", ""),
                "storage_id": record.get("storageid", ""),
                "name": record.get("name", ""),
                "xscore": record.get("xscore", 0),
                "bucket": record.get("bucket", ""),
                "media_type_human": media_map.get(record.get("media"), "Unknown"),
                "size": record.get("size", 0),
                "date_found": record.get("date") or record.get("added"),
            })

        latest = records[0]
        media_type = media_map.get(latest.get("media"), "Document")
        bucket = latest.get("bucket", "leak")
        
        # ✅ ВОЗВРАЩАЕМ С threat_details
        return {
            "threat_score": latest.get("xscore", 0),
            "category": f"{media_type} ({bucket})",
            "last_seen": _parse_date(latest.get("date")) or _parse_date(latest.get("added")),
            "source": "IntelX",
            "error": None,
            "records": threat_details  # ← Теперь эта переменная определена!
        }

    except requests.Timeout:
        return {"threat_score": 0, "category": "Timeout", "last_seen": None, "source": "IntelX", "error": "Timeout", "records": []}
    except requests.HTTPError as exc:
        return {"threat_score": 0, "category": "HTTP Error", "last_seen": None, "source": "IntelX", "error": f"Status {exc.response.status_code}", "records": []}
    except Exception as exc:
        logger.error(f"IntelX API Error: {exc}")
        return {"threat_score": 0, "category": "Error", "last_seen": None, "source": "IntelX", "error": str(exc), "records": []}
def get_file_preview(storage_id: str, bucket: str, media_type: int = 24, content_type: int = 1) -> dict:
    if not storage_id or not bucket:
        return {"success": False, "error": "Отсутствует storage_id или bucket"}

    api_key = getattr(settings, "INTELX_API_KEY", None)
    base_url = getattr(settings, "INTELX_API_URL", "https://free.intelx.io").rstrip('/')

    headers = {
        "x-key": api_key,
        "User-Agent": "DomainBreachMonitor/1.1",
        "Accept": "text/plain; charset=utf-8" 
    }

    url = f"{base_url}/file/preview"
    params = {
        "sid": storage_id,
        "b": bucket,
        "c": content_type,
        "m": media_type,
        "f": 0,      # 0 = text output
        "e": 0,      # 0 = ОТКЛЮЧИТЬ HTML-escaping
        "l": 50      # Максимум строк
    }

    logger.info(f"IntelX Preview: {url} | params={params}")

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        
        if resp.status_code == 401:
            return {"success": False, "error": "Нет доступа (401)"}
        elif resp.status_code == 404:
            return {"success": False, "error": "Файл не найден (404)"}
        elif resp.status_code == 402:
            return {"success": False, "error": "Лимит исчерпан (402)"}
        
        resp.raise_for_status()
        
        try:
            # Пробуем UTF-8
            text_content = resp.text
        except UnicodeDecodeError:
            try:
                text_content = resp.content.decode('cp1251') 
            except:
                text_content = resp.content.decode('latin-1')  
        
        return {"success": True, "content": text_content}

    except requests.HTTPError as e:
        logger.error(f"IntelX HTTP Error: {e}")
        return {"success": False, "error": f"Ошибка {resp.status_code}"}
    except Exception as e:
        logger.error(f"IntelX Exception: {e}")
        return {"success": False, "error": str(e)}