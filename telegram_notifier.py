"""
Модуль для отправки уведомлений в Telegram о событиях безопасности.
Содержит функции для отправки сообщений об алертах Suricata, угрозах VirusTotal,
а также о запуске и завершении модулей анализа.
Использует переменные окружения TELEGRAM_TOKEN и TELEGRAM_CHAT_ID для настройки бота.
"""

import requests
import os
from dotenv import load_dotenv

# Загружаем переменные окружения из .env файла
load_dotenv()

# Токен бота и идентификатор чата, куда будут отправляться уведомления
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_telegram_message(message, parse_mode="HTML"):
    """
    Базовый метод отправки текстового сообщения в Telegram.

    Args:
        message (str): Текст сообщения.
        parse_mode (str): Режим разметки (по умолчанию "HTML").

    Returns:
        bool: True, если сообщение успешно отправлено, иначе False.
    """
    # Проверяем, настроены ли токен и chat_id
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram не настроен. Пропускаем...")
        return False

    # Формируем URL и данные для запроса к API Telegram
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": parse_mode
    }

    try:
        # Отправляем POST-запрос с таймаутом 5 секунд
        response = requests.post(url, data=data, timeout=5)
        if response.status_code == 200:
            return True
        else:
            print(f"Ошибка Telegram: {response.text}")
            return False
    except Exception as e:
        print(f"Ошибка отправки в Telegram: {e}")
        return False


def notify_suricata_alert(alert):
    """
    Формирует и отправляет уведомление об алерте Suricata.

    Args:
        alert (dict): Словарь с данными алерта, содержащий ключи:
            severity, timestamp, src_ip, src_port, dest_ip, dest_port,
            category, signature.

    Returns:
        bool: Результат отправки сообщения (True/False).
    """
    # Определяем уровень критичности и соответствующий заголовок
    severity = alert.get('severity', 3)
    if severity == 1:
        icon = "КРИТИЧЕСКАЯ"
    elif severity == 2:
        icon = "ВЫСОКАЯ"
    elif severity == 3:
        icon = "СРЕДНЯЯ"
    else:
        icon = "НИЗКАЯ"

    # Формируем текст сообщения
    message = f"""
{icon} УГРОЗА SURICATA

Время: {alert.get('timestamp')}
Источник: {alert.get('src_ip')}:{alert.get('src_port')}
Цель: {alert.get('dest_ip')}:{alert.get('dest_port')}
Категория: {alert.get('category')}
Сигнатура: {alert.get('signature')}
Уровень: {severity}
    """
    # Отправляем через базовую функцию
    return send_telegram_message(message)


def notify_vt_threat(result, attrs, stats):
    """
    Формирует и отправляет уведомление об угрозе, обнаруженной VirusTotal.

    Args:
        result (dict): Словарь с информацией о запросе (ключ 'query', 'type').
        attrs (dict): Атрибуты объекта (репутация, страна, владелец AS и т.д.).
        stats (dict): Статистика детектов (malicious, suspicious).

    Returns:
        bool: Результат отправки сообщения, либо False, если угроза незначительная.
    """
    # Извлекаем статистику
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    reputation = attrs.get('reputation', 0)

    # Определяем уровень угрозы на основе наличия вредоносных детектов,
    # подозрительных или низкой репутации.
    if malicious > 0:
        threat_level = "КРИТИЧЕСКАЯ УГРОЗА VT"
    elif suspicious > 0:
        threat_level = "ПОДОЗРИТЕЛЬНО VT"
    elif reputation < 0:
        threat_level = "НИЗКАЯ РЕПУТАЦИЯ VT"
    elif reputation < 10 and reputation > 0:
        threat_level = "РЕПУТАЦИЯ НИЖЕ СРЕДНЕГО VT"
    else:
        # Если нет признаков угрозы, уведомление не отправляем
        return False

    # Получаем имя проверяемого объекта (хеш, URL, домен)
    name = result['query']
    # Формируем основную часть сообщения
    msg = f"""
{threat_level}

{result['type'].upper()}: {name[:50]}{'...' if len(name) > 50 else ''}

Статистика:
  Malicious: {malicious}
  Suspicious: {suspicious}
  Репутация: {reputation}
"""

    # Добавляем дополнительную информацию, если она доступна
    if 'country' in attrs:
        msg += f"   Страна: {attrs['country']}\n"
    if 'as_owner' in attrs:
        msg += f"   Владелец: {attrs['as_owner']}\n"

    return send_telegram_message(msg)


def notify_start(module):
    """
    Отправляет уведомление о запуске указанного модуля.

    Args:
        module (str): Название модуля.

    Returns:
        bool: Результат отправки.
    """
    return send_telegram_message(f"Модуль {module} запущен")


def notify_end(module, results_count):
    """
    Отправляет уведомление о завершении работы модуля с указанием количества обработанных результатов.

    Args:
        module (str): Название модуля.
        results_count (int): Количество обработанных объектов.

    Returns:
        bool: Результат отправки.
    """
    return send_telegram_message(f"Модуль {module} завершен. Обработано: {results_count}")