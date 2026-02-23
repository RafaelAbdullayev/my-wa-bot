# ai_server_deepseek_final.py - СУПЕР-УСТОЙЧИВАЯ ВЕРСИЯ
# ✅ Работает даже если DeepSeek не отвечает
# ✅ Вакансии НЕ УДАЛЯЮТСЯ
# ✅ Маты УДАЛЯЮТСЯ
# ✅ Казино УДАЛЯЮТСЯ
# ✅ VirusTotal проверка

import os
import json
import re
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# ===========================================================
# 🔑 VIRUSTOTAL НАСТРОЙКИ
# ===========================================================
VIRUSTOTAL_API_KEY = "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"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# ===========================================================
# МОДЕЛИ ДАННЫХ
# ===========================================================

class MessageRequest(BaseModel):
    message: str
    sender: str
    chat_id: str
    is_group: bool

class ModeratorResponse(BaseModel):
    action: str  # "nothing", "delete", "ban"
    reason: str
    response_text: str

# ===========================================================
# СИСТЕМА ПРЕДУПРЕЖДЕНИЙ
# ===========================================================

WARNINGS_FILE = "warnings.json"
CACHE_FILE = "vt_cache.json"

def load_json(file):
    try:
        with open(file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def save_json(file, data):
    with open(file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_warnings():
    return load_json(WARNINGS_FILE)

def save_warnings(warnings):
    save_json(WARNINGS_FILE, warnings)

def load_cache():
    return load_json(CACHE_FILE)

def save_cache(cache):
    save_json(CACHE_FILE, cache)

def add_warning(sender, chat_id):
    """Xəbərdarlıq əlavə et"""
    warnings = load_warnings()
    key = f"{sender}_{chat_id}"
    
    now = datetime.now()
    
    if key in warnings:
        last_warning = datetime.fromisoformat(warnings[key]["last_warning"])
        if now - last_warning > timedelta(hours=24):
            warnings[key] = {"count": 1, "last_warning": now.isoformat()}
        else:
            warnings[key]["count"] += 1
            warnings[key]["last_warning"] = now.isoformat()
    else:
        warnings[key] = {"count": 1, "last_warning": now.isoformat()}
    
    save_warnings(warnings)
    return warnings[key]["count"]

def get_warning_count(sender, chat_id):
    warnings = load_warnings()
    key = f"{sender}_{chat_id}"
    
    if key in warnings:
        last_warning = datetime.fromisoformat(warnings[key]["last_warning"])
        if datetime.now() - last_warning > timedelta(hours=24):
            del warnings[key]
            save_warnings(warnings)
            return 0
        return warnings[key]["count"]
    return 0

# ===========================================================
# ✅ ПРОВЕРКА НА ВАКАНСИИ
# ===========================================================

def is_vacancy(text):
    """Проверяет, является ли сообщение вакансией"""
    text_lower = text.lower()
    
    vacancy_keywords = [
        'iş', 'is', 'vakansiya', 'baş mühasib', 'mühasib',
        'ə/h', 'maaş', 'işçi axtarılır', 'şirkət', 'MMC',
        'CV', 'iş təcrübəsi', 'iş saatları', 'full-time',
        'iş elanı', 'iş yeri', 'işçi tələb olunur',
        'NBK Motors', 'nbkmotors', 'HavvaQurbanova',
        'вакансия', 'работа', 'требуется', 'компания',
        'зарплата', 'резюме', 'график работы',
        'job', 'vacancy', 'position', 'hiring', 'salary',
    ]
    
    for keyword in vacancy_keywords:
        if keyword in text_lower:
            logger.info(f"✅ Vacancy keyword: {keyword}")
            return True
    
    phone_pattern = r'\b0[1-9][0-9]{8}\b|\b\+994[0-9]{9}\b'
    if re.search(phone_pattern, text):
        work_words = ['iş', 'is', 'vakansiya', 'job', 'вакансия', 'работа']
        for word in work_words:
            if word in text_lower:
                return True
    
    return False

# ===========================================================
# 🔥 РАСШИРЕННЫЙ СПИСОК МАТОВ
# ===========================================================

BAD_WORDS = [
    # Azərbaycan
    "sik", "sikir", "sikim", "siksən", "siksin", "sikər", "sikdir",
    "sikdirdi", "sikdiyim", "sikdiyin", "sikdiyi", "sikiş", "sikişmək",
    "amm", "amcıq", "amcığ", "amına", "amından", "amına qoyum",
    "göt", "götü", "götünə", "götündən", "götvərən", "göt oğlan",
    "qəhbə", "qəhbe", "qəhbə uşağı", "qəhbə oğlu", "orospu", "orospu çocuğu",
    "malaş", "malaşı", "malaşın", "malaşa", "malaşcı",
    "peysər", "keçi", "eşşək", "xoruz", "ilan", "donuz",
    "siktir", "siktir et", "siktir ol", "siktir get",
    
    # Русский
    "хуй", "хуя", "хуе", "пизда", "пизде", "пизду", "пиздец",
    "ебал", "ебать", "еблан", "ёбаный", "заебал", "наебал",
    "блядь", "бля", "блять", "сука", "сучка", "мудак", "гандон",
    "пидор", "лох", "урод", "дебил", "даун",
    
    # English
    "fuck", "fucking", "motherfucker", "shit", "bitch", "asshole",
    "dick", "pussy", "cunt", "whore", "slut", "bastard",
]

# ===========================================================
# 🚫 ЧЕРНЫЙ СПИСОК КАЗИНО
# ===========================================================

CASINO_BLACKLIST = [
    "vavada", "sultangames", "pinup", "pinups", "sultan games",
    "playfortuna", "riobet", "casino-x", "brillx", "rox casino",
    "mystake", "stake", "agentlotto", "sprutcasino",
    "lsbet", "royal stars casino", "jet casino", "f1casino",
    "maxibet", "irwin casino", "1xbet", "fonbet", "olimpbet",
    "888casino", "casino", "kazino", "казино", "poker",
    "bet", "stavka", "ставка", "букмекер", "jackpot",
]

# ===========================================================
# 🔍 ФУНКЦИИ ДЛЯ ССЫЛОК
# ===========================================================

def extract_domains(text):
    """Извлекает домены из текста"""
    url_pattern = r'https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}'
    urls = re.findall(url_pattern, text.lower())
    
    domains = []
    for url in urls:
        url = url.replace('http://', '').replace('https://', '').replace('www.', '')
        if '/' in url:
            url = url.split('/')[0]
        domains.append(url)
    
    return domains

def check_casino_blacklist(text):
    """Проверяет текст на наличие казино"""
    text_lower = text.lower()
    for casino in CASINO_BLACKLIST:
        if casino in text_lower:
            return True, casino
    return False, None

# ===========================================================
# 🤖 ФУНКЦИЯ БЕЗОПАСНОГО ВЫЗОВА DEEPSEEK
# ===========================================================

async def safe_deepseek_call(message):
    """Безопасный вызов DeepSeek с таймаутом и обработкой ошибок"""
    try:
        # Пробуем DeepSeek
        async with aiohttp.ClientSession() as session:
            prompt = f"""Mesajı analiz et: "{message}"

QAYDALAR:
- Söyüş varsa: delete
- Casino varsa: delete  
- Vacancy varsa: nothing
- Normal: nothing

CAVAB YALNIZ JSON:
{{"action": "delete" və ya "nothing"}}"""

            data = {
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 50
            }
            
            async with session.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
                json=data,
                timeout=5  # Таймаут 5 секунд
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return result["choices"][0]["message"]["content"]
    except:
        pass
    return None

# ===========================================================
# 🎯 ОСНОВНАЯ ФУНКЦИЯ МОДЕРАЦИИ
# ===========================================================

@app.post("/moderate", response_model=ModeratorResponse)
async def moderate_message(request: MessageRequest):
    logger.info(f"📨 Yeni mesaj: {request.message[:100]}...")
    
    user_mention = f"@{request.sender.split('@')[0]}"
    message_lower = request.message.lower()
    
    # ===========================================================
    # ⚠️ 1. ВАКАНСИИ - НИКОГДА НЕ УДАЛЯТЬ!
    # ===========================================================
    if is_vacancy(request.message):
        logger.info("✅ VAKANSİYA - saxlanıldı")
        return ModeratorResponse(
            action="nothing",
            reason="Vacancy",
            response_text=""
        )
    
    # ===========================================================
    # 🔥 2. ПРОВЕРКА НА МАТЫ (ВСЕГДА РАБОТАЕТ!)
    # ===========================================================
    for bad_word in BAD_WORDS:
        if bad_word in message_lower:
            logger.info(f"🚫 Bad word: {bad_word}")
            
            new_count = add_warning(request.sender, request.chat_id)
            
            if new_count >= 3:
                return ModeratorResponse(
                    action="ban",
                    reason="3 warnings - bad words",
                    response_text=f"{user_mention} 3 DƏFƏ SÖYÜŞ ETDİNİZ! QRUPDAN ATILDINIZ! 🚫"
                )
            else:
                return ModeratorResponse(
                    action="delete",
                    reason=f"Bad word",
                    response_text=f"{user_mention} SÖYÜŞ ETMƏK QADAĞANDIR! Silindi! Xəbərdarlıq {new_count}/3 ⚠️"
                )
    
    # ===========================================================
    # 🚫 3. ПРОВЕРКА НА КАЗИНО (ВСЕГДА РАБОТАЕТ!)
    # ===========================================================
    is_casino, casino_word = check_casino_blacklist(message_lower)
    if is_casino:
        logger.info(f"🚫 Casino word: {casino_word}")
        
        new_count = add_warning(request.sender, request.chat_id)
        
        if new_count >= 3:
            return ModeratorResponse(
                action="ban",
                reason="3 warnings - casino",
                response_text=f"{user_mention} 3 DƏFƏ KAZİNO! QRUPDAN ATILDINIZ! 🚫"
            )
        else:
            return ModeratorResponse(
                action="delete",
                reason=f"Casino",
                response_text=f"{user_mention} KAZİNO QADAĞANDIR! Silindi! Xəbərdarlıq {new_count}/3 ⚠️"
            )
    
    # ===========================================================
    # 4. ПРОВЕРКА НА БАН
    # ===========================================================
    warning_count = get_warning_count(request.sender, request.chat_id)
    if warning_count >= 3:
        return ModeratorResponse(
            action="ban",
            reason="3 warnings - ban",
            response_text=f"{user_mention} 3 DƏFƏ XƏBƏRDARLIQ! QRUPDAN ATILDINIZ! 🚫"
        )
    
    # ===========================================================
    # 5. ПРОВЕРКА ССЫЛОК
    # ===========================================================
    domains = extract_domains(request.message)
    
    if domains:
        logger.info(f"🔗 Domains: {domains}")
        
        for domain in domains:
            # Проверка казино по домену
            is_casino, casino_word = check_casino_blacklist(domain)
            if is_casino:
                new_count = add_warning(request.sender, request.chat_id)
                
                if new_count >= 3:
                    return ModeratorResponse(
                        action="ban",
                        reason="3 warnings - casino",
                        response_text=f"{user_mention} 3 DƏFƏ KAZİNO! BAN! 🚫"
                    )
                else:
                    return ModeratorResponse(
                        action="delete",
                        reason=f"Casino domain",
                        response_text=f"{user_mention} KAZİNO LİNKLƏRİ QADAĞANDIR! Silindi! Xəbərdarlıq {new_count}/3 ⚠️"
                    )
            
            # VirusTotal проверка
            vt_result = await check_virustotal(domain)
            if vt_result:
                new_count = add_warning(request.sender, request.chat_id)
                
                if new_count >= 3:
                    return ModeratorResponse(
                        action="ban",
                        reason="3 warnings - malicious",
                        response_text=f"{user_mention} 3 DƏFƏ TƏHLÜKƏLİ LİNK! BAN! 🚫"
                    )
                else:
                    return ModeratorResponse(
                        action="delete",
                        reason="Malicious link",
                        response_text=f"{user_mention} TƏHLÜKƏLİ LİNK! Silindi! Xəbərdarlıq {new_count}/3 ⚠️"
                    )
        
        # Если все ссылки безопасны
        return ModeratorResponse(
            action="nothing",
            reason="Safe links",
            response_text=""
        )
    
    # ===========================================================
    # 6. НОРМАЛЬНОЕ СООБЩЕНИЕ
    # ===========================================================
    logger.info("✅ Normal message")
    return ModeratorResponse(
        action="nothing",
        reason="Normal",
        response_text=""
    )

# ===========================================================
# 🔬 VIRUSTOTAL ПРОВЕРКА
# ===========================================================

async def check_virustotal(domain):
    """Проверяет домен через VirusTotal"""
    
    cache = load_cache()
    if domain in cache:
        cache_time = datetime.fromisoformat(cache[domain]["time"])
        if datetime.now() - cache_time < timedelta(hours=24):
            logger.info(f"📦 Cache: {domain} -> {cache[domain]['malicious']}")
            return cache[domain]["malicious"]
    
    try:
        async with aiohttp.ClientSession() as session:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            async with session.post(
                VIRUSTOTAL_URL,
                headers=headers,
                data={"url": f"https://{domain}"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    analysis_id = data.get("data", {}).get("id")
                    
                    if analysis_id:
                        await asyncio.sleep(2)
                        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        async with session.get(result_url, headers=headers) as result_response:
                            if result_response.status == 200:
                                result_data = await result_response.json()
                                stats = result_data.get("data", {}).get("attributes", {}).get("stats", {})
                                malicious = stats.get("malicious", 0)
                                suspicious = stats.get("suspicious", 0)
                                
                                is_malicious = malicious > 0 or suspicious > 0
                                cache[domain] = {
                                    "malicious": is_malicious,
                                    "time": datetime.now().isoformat()
                                }
                                save_cache(cache)
                                return is_malicious
    except Exception as e:
        logger.error(f"❌ VirusTotal error: {e}")
    
    return None

# ===========================================================
# 📊 ДОПОЛНИТЕЛЬНЫЕ ENDPOINTS
# ===========================================================

@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "mode": "deepseek-pro",
        "bad_words": len(BAD_WORDS),
        "casino_blacklist": len(CASINO_BLACKLIST),
        "virustotal": "configured"
    }

@app.get("/warnings")
async def get_warnings():
    return load_warnings()

@app.post("/clear_all_warnings")
async def clear_all_warnings():
    save_warnings({})
    save_cache({})
    return {"status": "ok", "message": "✅ Bütün xəbərdarlıqlar silindi!"}