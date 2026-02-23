# ai_server_best.py - ИДЕАЛЬНАЯ ВЕРСИЯ
# ✅ Вакансии НЕ УДАЛЯЮТСЯ
# ✅ Маты УДАЛЯЮТСЯ
# ✅ Казино из списка УДАЛЯЮТСЯ
# ✅ VirusTotal проверка
# ✅ Система предупреждений 1/3, 2/3, БАН

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
VIRUSTOTAL_API_KEY = "45e72a1fa2c661e7db3d9ad134c4aeeb8f74fe9bdc6e16a09f02e4d2479ba686"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
DEEPSEEK_API_KEY="sk-08eb9672f5864f30bc20f895201cc58d"
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
        # 24 saatdan sonra sıfırla
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
    """Xəbərdarlıq sayını qaytar"""
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
# ✅ ПРОВЕРКА НА ВАКАНСИИ (САМАЯ ВАЖНАЯ!)
# ===========================================================

def is_vacancy(text):
    """
    Проверяет, является ли сообщение вакансией
    ВАЖНО: Такие сообщения НИКОГДА не удаляются!
    """
    text_lower = text.lower()
    
    # Ключевые слова для вакансий
    vacancy_keywords = [
        # Azərbaycan dilində
        'iş', 'is', 'vakansiya', 'baş mühasib', 'mühasib',
        'ə/h', 'maaş', 'işçi axtarılır', 'şirkət', 'MMC',
        'CV', 'iş təcrübəsi', 'iş saatları', 'full-time',
        'iş elanı', 'iş yeri', 'işçi tələb olunur',
        'işə qəbul', 'kadr', 'personal', 'işçi',
        'NBK Motors', 'nbkmotors', 'HavvaQurbanova',
        'ofis menecer', 'satış menecer', 'menecer',
        'mühəndis', 'proqramçı', 'developer',
        'xidmət', 'servis', 'operator',
        
        # Русский
        'вакансия', 'работа', 'требуется', 'компания',
        'главный бухгалтер', 'бухгалтер', 'зарплата',
        'откликнуться', 'резюме', 'график работы',
        'полный день', 'частичная занятость',
        'офис', 'сотрудник', 'персонал',
        
        # English
        'job', 'vacancy', 'position', 'hiring',
        'salary', 'experience', 'full-time', 'part-time',
        'company', 'candidate', 'resume', 'CV',
        'manager', 'engineer', 'developer',
    ]
    
    # Проверяем ключевые слова
    for keyword in vacancy_keywords:
        if keyword in text_lower:
            logger.info(f"✅ Vacancy keyword tapıldı: {keyword}")
            return True
    
    # Проверка на наличие азербайджанского телефона
    phone_pattern = r'\b0[1-9][0-9]{8}\b|\b\+994[0-9]{9}\b'
    if re.search(phone_pattern, text):
        # Если есть телефон и слова о работе - это вакансия
        work_words = ['iş', 'is', 'vakansiya', 'job', 'вакансия', 'работа']
        for word in work_words:
            if word in text_lower:
                logger.info("✅ Telefon + iş sözü aşkarlandı")
                return True
    
    # Проверка на email в контексте вакансии
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.search(email_pattern, text):
        work_words = ['iş', 'is', 'vakansiya', 'job', 'вакансия', 'работа', 'company', 'şirkət']
        for word in work_words:
            if word in text_lower:
                logger.info("✅ Email + iş sözü aşkarlandı")
                return True
    
    return False

# ===========================================================
# 🔥 РАСШИРЕННЫЙ СПИСОК МАТОВ (Azərbaycan + Русский + English)
# ===========================================================

BAD_WORDS = [
    # ===== AZƏRBAYCAN MATLARI (ən geniş siyahı) =====
    # Sözün bütün variantları
    "sik", "sikir", "sikim", "siksən", "siksin", "sikər", "sikdi",
    "sikdir", "sikdirdi", "sikdiyim", "sikdiyin", "sikdiyi", 
    "sikiş", "sikişmək", "sikişən", "sikişdi", "sikişir",
    "siktir", "siktir et", "siktir ol", "siktir get", "siktirsin",
    
    # Am (qadın cinsiyyət orqanı)
    "amm", "amcıq", "amcığ", "amcığı", "amcığa", "amcıqdan",
    "amına", "amından", "amına qoyum", "amına qoyaram", "amına sıçdım",
    
    # Göt (anus)
    "göt", "götü", "götünə", "götündən", "götvərən", "göt oğlan",
    "göt qulaq", "göt ləpə", "göt verən", "göt çalan", "göt yalayan",
    "götəgirən", "götəgirən oğlu", "göt verən qız",
    
    # Qəhbə (fahişə)
    "qəhbə", "qəhbe", "qəhbə uşağı", "qəhbə oğlu", "qəhbə qızı",
    "qəhbəlik", "qəhbəxana", "qəhbəçilik",
    
    # Orospu (fahişə - türkcə)
    "orospu", "orospu çocuğu", "orospu evladı", "orospu qızı",
    "orospuluk", "orospu çocukları",
    
    # Malaş (əxlaqsız, yaramaz)
    "malaş", "malaşı", "malaşın", "malaşa", "malaşcı", "malaş qarı",
    "malaş oğlu", "malaş qızı", "malaş uşağı",
    
    # Peysər (baş, kəllə - təhqir)
    "peysər", "peysər baş", "peysər kəllə", "peysər oğlu",
    
    # Heyvan adları ilə təhqirlər
    "it", "it oğlu", "it uşağı", "it qızı", "it balası", "it sürüsü",
    "donuz", "donuz adam", "donuzun balası", "donuz sürüsü",
    "eşşək", "eşşək oğlu", "eşşək baş", "eşşək qulaq",
    "keçi", "keçi adam", "keçi oğlu", "keçi saqqal",
    "xoruz", "xoruz baş", "xoruz beyin", "xoruz kəllə",
    "ilan", "ilan adam", "ilan dili", "ilan sürüsən",
    "çayan", "çayan adam", "çayan iynəsi", "çayan ürək",
    "qurbağa", "qurbağa adam", "qurbağa sifət",
    
    # Ağıl və beyinlə bağlı təhqirlər
    "axmaq", "axmaq adam", "axmaq uşaq", "axmaq qadın", "axmaq kişi",
    "sarsaq", "sarsaq adam", "sarsaq hərəkət", "sarsaq danışıq",
    "gerizə", "gerizə adam", "gerizə söz", "gerizə danışan",
    "kəmağıl", "kəm ağıl", "ağılsız", "ağıl ölüsü", "ağıl çatışmazlığı",
    "beyinsiz", "başsız", "beyin ölüsü", "beyni yox", "beyinsiz heyvan",
    
    # Ümumi təhqirlər
    "zibil", "zibil adam", "zibil insan", "zibil qrup", "zibil söz",
    "çirkli", "çirkli adam", "çirkli ağız", "çirkli ürək",
    "yaramaz", "yaramaz uşaq", "yaramaz adam", "yaramaz hərəkət",
    "bəd", "bəd adam", "bəd nəfəs", "bəd söz", "bəd əməl",
    "qara", "qara ürək", "qara qəlb", "qara ruh", "qara niyyət",
    "şər", "şər adam", "şər iş", "şər düşüncə", "şər qüvvə",
    "lənət", "lənət adam", "lənət olsun", "lənət söz",
    
    # ===== RUSSIAN MATS (все варианты) =====
    # Хуй и производные
    "хуй", "хуя", "хую", "хуем", "хуе", "хуи", "хуёвый", "хуйло",
    "хуйня", "хуйнуть", "захуй", "нахуй", "похуй", "охуй", "охуенно",
    "охуел", "охуели", "охуевший", "распиздяй", "хуйлан", "хуйланить",
    
    # Пизда и производные
    "пизда", "пизде", "пизду", "пиздой", "пиздец", "пиздос", "пиздёж",
    "пиздеть", "пиздануть", "распиздяй", "пиздюк", "пиздюлька",
    "пиздатый", "пиздато", "пизданько", "пиздабол", "пиздаболка",
    
    # Ебать и производные
    "ебал", "ебать", "ебучий", "ёбаный", "заебал", "наебал", "объебал",
    "выебал", "выебать", "выебон", "еблан", "ебанат", "ебарь",
    "ёб твою мать", "ёбаный в рот", "ёбаный насос", "ебаться",
    "заебись", "заебато", "охуеть", "ахуеть", "охринеть",
    
    # Блядь и производные
    "блядь", "бля", "блять", "блядство", "блядский", "блядина",
    "блядовать", "блядюга", "блядюшка", "блядёнок",
    
    # Сука и производные
    "сука", "сучка", "сучонок", "сукин сын", "сучий потрох",
    "сучий", "сучье", "сука блядь", "сука пизда", "сука ебаная",
    
    # Мудак и производные
    "мудак", "мудака", "мудаку", "мудаком", "мудацкий", "мудачина",
    "мудозвон", "мудозвонить", "мудак хренов",
    
    # Гандон и производные
    "гандон", "гандона", "гандону", "гандоном", "гандонский",
    "гандонство", "гандонщина", "гандон вонючий",
    
    # Шлюха и производные
    "шлюха", "шлюш", "шлюшка", "шлюхин", "шлюхский",
    "шлюшить", "шлюховатый", "шлюха драная",
    
    # Пидор и производные
    "пидор", "пидора", "пидору", "пидором", "пидоры", "пидорас",
    "пидорасия", "пидорство", "пидор гнойный", "пидрила",
    
    # Лох и производные
    "лох", "лоха", "лоху", "лохом", "лохи", "лоховский", "лохушка",
    "лохотрон", "лохотронщик", "лох педальный", "лох обыкновенный",
    
    # Урод и производные
    "урод", "урода", "уроду", "уродом", "уроды", "уродский", "уродина",
    "уродство", "уродовать", "уродливый", "урод моральный",
    
    # Дебил и производные
    "дебил", "дебила", "дебилу", "дебилом", "дебилы", "дебильный",
    "дебилизм", "дебилизация", "дебил конченый", "дебил ёбаный",
    
    # Даун и производные
    "даун", "дауна", "дауну", "дауном", "дауны", "даунский",
    "даунизм", "даун болезнь", "даун ёбаный", "даун конченый",
    
    # ===== ENGLISH BAD WORDS =====
    # Основные
    "fuck", "fucking", "fucker", "motherfucker", "fuckin", "fucked",
    "shit", "bitch", "asshole", "dick", "pussy", "cunt", "whore", "slut",
    "bastard", "twat", "wanker", "prick", "cock", "balls", "damn", "hell",
    
    # Производные
    "fuck you", "fuck off", "fuck this", "fuck that", "what the fuck",
    "holy shit", "bullshit", "shitty", "bitchy", "asshead", "asswipe",
    "dickhead", "dickface", "pussylips", "cuntsucker", "whorehouse",
]

# ===========================================================
# 🚫 ЧЕРНЫЙ СПИСОК КАЗИНО
# ===========================================================

CASINO_BLACKLIST = [
    # Из твоего списка
    "vavada", "sultangames", "pinup", "pinups", "sultan games",
    "playfortuna", "riobet", "casino-x", "brillx", "rox casino",
    "mystake", "stake", "agentlotto", "sprutcasino",
    "lsbet", "royal stars casino", "jet casino", "f1casino",
    "maxibet", "irwin casino", "1xbet", "fonbet", "olimpbet",
    "888casino",
    
    # Общие слова для казино
    "casino", "kazino", "cazino", "казино",
    "poker", "pokermatch", "покер",
    "bet", "stavka", "ставка", "букмекер",
    "jackpot", "dжекпот", "джекпот",
    "roulette", "ruletka", "рулетка",
    "slot", "slots", "игровые автоматы",
    "vulkan", "vulcan", "вулкан",
    "azino", "азино", "azino777",
]

# ===========================================================
# 🔍 ФУНКЦИИ ДЛЯ ССЫЛОК
# ===========================================================

def extract_domains(text):
    """Извлекает все домены из текста"""
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*|www\.[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s]*)?'
    urls = re.findall(url_pattern, text.lower())
    
    domains = []
    for url in urls:
        try:
            # Очищаем URL от протоколов и путей
            url = url.replace('http://', '').replace('https://', '').replace('www.', '')
            if '/' in url:
                url = url.split('/')[0]
            domains.append(url)
        except:
            continue
    
    return domains

def check_casino_blacklist(domain):
    """Проверяет домен по черному списку казино"""
    domain_lower = domain.lower()
    
    for casino in CASINO_BLACKLIST:
        if casino in domain_lower:
            return True, casino
    
    return False, None

# ===========================================================
# 🔬 VIRUSTOTAL ПРОВЕРКА
# ===========================================================

async def check_virustotal(domain):
    """Проверяет домен через VirusTotal"""
    
    # Проверяем кэш
    cache = load_cache()
    if domain in cache:
        cache_time = datetime.fromisoformat(cache[domain]["time"])
        if datetime.now() - cache_time < timedelta(hours=24):
            logger.info(f"📦 Keshden: {domain} -> {cache[domain]['malicious']}")
            return cache[domain]["malicious"]
    
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "твой_ключ_сюда":
        return None
    
    try:
        async with aiohttp.ClientSession() as session:
            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            async with session.post(
                VIRUSTOTAL_URL,
                headers=headers,
                data={"url": f"https://{domain}"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    analysis_id = data.get("data", {}).get("id")
                    
                    if analysis_id:
                        await asyncio.sleep(2)  # Ждем анализа
                        
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
                                    "time": datetime.now().isoformat(),
                                    "stats": stats
                                }
                                save_cache(cache)
                                
                                logger.info(f"✅ VirusTotal: {domain} -> malicious={malicious}, suspicious={suspicious}")
                                return is_malicious
                elif response.status == 429:
                    logger.warning("⚠️ VirusTotal limiti aşıldı")
                else:
                    logger.warning(f"⚠️ VirusTotal xətası: {response.status}")
    except Exception as e:
        logger.error(f"❌ VirusTotal xətası: {e}")
    
    return None

# ===========================================================
# 🎯 ОСНОВНАЯ ФУНКЦИЯ МОДЕРАЦИИ (ИСПРАВЛЕННАЯ!)
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
        logger.info("✅ VAKANSİYA - SAXLANILDI! (silinmədi)")
        return ModeratorResponse(
            action="nothing",
            reason="Vacancy - allowed",
            response_text=""
        )
    
    # ===========================================================
    # 🔥 2. ПРОВЕРКА НА МАТЫ (САМАЯ ВАЖНАЯ!)
    # ===========================================================
    for bad_word in BAD_WORDS:
        if bad_word in message_lower:
            logger.info(f"🚫 QADAĞAN söz aşkarlandı: {bad_word}")
            
            new_count = add_warning(request.sender, request.chat_id)
            
            if new_count >= 3:
                return ModeratorResponse(
                    action="ban",
                    reason=f"3 xəbərdarlıq - söyüş",
                    response_text=f"{user_mention} 3 DƏFƏ SÖYÜŞ ETDİNİZ! QRUPDAN ATILDINIZ! 🚫"
                )
            else:
                return ModeratorResponse(
                    action="delete",
                    reason=f"Söyüş: {bad_word[:30]}...",
                    response_text=f"{user_mention} SÖYÜŞ ETMƏK QADAĞANDIR! Silindi! Xəbərdarlıq {new_count}/3 ⚠️"
                )
    
    # ===========================================================
    # 🚫 3. ПРОВЕРКА НА КАЗИНО
    # ===========================================================
    for casino_word in CASINO_BLACKLIST:
        if casino_word in message_lower:
            logger.info(f"🚫 KAZİNO sözü aşkarlandı: {casino_word}")
            
            new_count = add_warning(request.sender, request.chat_id)
            
            if new_count >= 3:
                return ModeratorResponse(
                    action="ban",
                    reason=f"3 xəbərdarlıq - kazino",
                    response_text=f"{user_mention} 3 DƏFƏ KAZİNO LİNKİ GÖNDƏRDİNİZ! QRUPDAN ATILDINIZ! 🚫"
                )
            else:
                return ModeratorResponse(
                    action="delete",
                    reason=f"Casino: {casino_word}",
                    response_text=f"{user_mention} KAZİNO LİNKLƏRİ QADAĞANDIR! Silindi! Xəbərdarlıq {new_count}/3 ⚠️"
                )
    
    # ===========================================================
    # 4. ПРОВЕРЯЕМ КОЛИЧЕСТВО ПРЕДУПРЕЖДЕНИЙ
    # ===========================================================
    warning_count = get_warning_count(request.sender, request.chat_id)
    
    if warning_count >= 3:
        logger.info(f"🚫 İstifadəçi banlandı: {request.sender}")
        return ModeratorResponse(
            action="ban",
            reason="3 xəbərdarlıq - ban",
            response_text=f"{user_mention} 3 DƏFƏ XƏBƏRDARLIQ ALDINIZ! QRUPDAN BAN OLUNDUNUZ! 🚫"
        )
    
    # ===========================================================
    # 5. ИЩЕМ ССЫЛКИ В СООБЩЕНИИ
    # ===========================================================
    domains = extract_domains(request.message)
    
    if domains:
        logger.info(f"🔗 Tapılan domainlər: {domains}")
        
        for domain in domains:
            # Проверка по черному списку казино
            is_blacklisted, casino_name = check_casino_blacklist(domain)
            
            if is_blacklisted:
                logger.info(f"🚫 QADAĞAN olunmuş kazino: {domain} ({casino_name})")
                
                new_count = add_warning(request.sender, request.chat_id)
                
                if new_count >= 3:
                    return ModeratorResponse(
                        action="ban",
                        reason=f"3 xəbərdarlıq - kazino",
                        response_text=f"{user_mention} 3 DƏFƏ KAZİNO LİNKİ GÖNDƏRDİNİZ! QRUPDAN ATILDINIZ! 🚫"
                    )
                else:
                    return ModeratorResponse(
                        action="delete",
                        reason=f"Casino: {casino_name}",
                        response_text=f"{user_mention} KAZİNO LİNKLƏRİ QADAĞANDIR! Silindi! Xəbərdarlıq {new_count}/3 ⚠️"
                    )
            
            # Проверка через VirusTotal
            vt_result = await check_virustotal(domain)
            
            if vt_result:
                logger.info(f"🚫 VIRUSTOTAL təhlükəli aşkar etdi: {domain}")
                
                new_count = add_warning(request.sender, request.chat_id)
                
                if new_count >= 3:
                    return ModeratorResponse(
                        action="ban",
                        reason="3 xəbərdarlıq - təhlükəli link",
                        response_text=f"{user_mention} 3 DƏFƏ TƏHLÜKƏLİ LİNK GÖNDƏRDİNİZ! QRUPDAN ATILDINIZ! 🚫"
                    )
                else:
                    return ModeratorResponse(
                        action="delete",
                        reason="Malicious link",
                        response_text=f"{user_mention} TƏHLÜKƏLİ LİNK AŞKAR EDİLDİ! Silindi! Xəbərdarlıq {new_count}/3 ⚠️"
                    )
        
        # Если все проверки пройдены
        logger.info("✅ Bütün linklər təhlükəsizdir")
        return ModeratorResponse(
            action="nothing",
            reason="Safe links",
            response_text=""
        )
    
    # ===========================================================
    # 6. НОРМАЛЬНОЕ СООБЩЕНИЕ
    # ===========================================================
    logger.info("✅ Normal mesaj - saxlanıldı")
    return ModeratorResponse(
        action="nothing",
        reason="Normal message",
        response_text=""
    )

# ===========================================================
# 📊 ДОПОЛНИТЕЛЬНЫЕ ENDPOINTS
# ===========================================================

@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "mode": "production",
        "virustotal": "configured" if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "твой_ключ_сюда" else "not configured",
        "casino_blacklist": len(CASINO_BLACKLIST),
        "bad_words_count": len(BAD_WORDS)
    }

@app.get("/warnings")
async def get_warnings():
    return load_warnings()

@app.post("/clear_all_warnings")
async def clear_all_warnings():
    """Təmizləmək üçün: curl -X POST http://127.0.0.1:8000/clear_all_warnings"""
    save_warnings({})
    save_cache({})
    return {"status": "ok", "message": "✅ Bütün xəbərdarlıqlar və kəş silindi!"}

@app.post("/add_to_blacklist/{domain}")
async def add_to_blacklist(domain: str):
    """Yeni kazino əlavə et: curl -X POST http://127.0.0.1:8000/add_to_blacklist/example.com"""
    if domain not in CASINO_BLACKLIST:
        CASINO_BLACKLIST.append(domain)
        return {"status": "ok", "message": f"✅ {domain} qara siyahıya əlavə edildi"}
    return {"status": "ok", "message": f"⚠️ {domain} artıq siyahıdadır"}

@app.get("/test_vacancy")
async def test_vacancy():
    """Test üçün"""
    test_messages = [
        "🏢 NBK Motors MMC\n\n- *Baş Mühasib*\n\nƏ/h 5000-10000AZN\n📲0102395930\n📧HavvaQurbanova@nbkmotors.az",
        "Salam, necəsən?",
        "1xbet.com",
        "Sik siktir",
    ]
    
    results = []
    for msg in test_messages:
        results.append({
            "message": msg[:50],
            "is_vacancy": is_vacancy(msg),
            "has_bad_words": any(word in msg.lower() for word in BAD_WORDS[:10])
        })
    
    return results