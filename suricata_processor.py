"""
Модуль для обработки логов Suricata.
Читает JSON-логи, извлекает события типа 'alert', формирует DataFrame,
сохраняет результаты в CSV и при необходимости отправляет уведомления
о критических алертах через Telegram.
"""

import os
import json
import pandas as pd
from datetime import datetime
from telegram_notifier import notify_suricata_alert

def process_suricata_logs(file_path, send_notifications=True):
    """
    Обрабатывает лог-файл Suricata, извлекает алерты и возвращает DataFrame.
    
    Функция проверяет существование файла, загружает JSON-данные,
    фильтрует события с event_type == 'alert', собирает нужные поля,
    формирует pandas DataFrame, сохраняет его в CSV в папку reports
    и возвращает DataFrame. Если send_notifications=True, для каждого
    алерта с severity=1 вызывается функция notify_suricata_alert.
    
    Args:
        file_path (str): Путь к JSON-файлу с логами Suricata.
        send_notifications (bool): Флаг отправки уведомлений о критических алертах.
    
    Returns:
        pandas.DataFrame: DataFrame с алертами. Если файл не найден или
        алертов нет, возвращается None или пустой DataFrame соответственно.
    """
    print("\n" + "="*60)
    print("SURICATA LOG PROCESSOR")
    print("="*60)
    
    # Проверяем существование файла
    if not os.path.exists(file_path):
        print(f"Файл не найден: {file_path}")
        return None
    
    # Загружаем JSON (предполагается, что файл содержит список объектов)
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    alerts = []  # список для сбора алертов
    for event in data:
        # Нас интересуют только события типа alert
        if event.get('event_type') == 'alert':
            # Извлекаем необходимые поля с защитой от отсутствия ключей
            alert = {
                'flow_id': event.get('flow_id'),
                'src_ip': event.get('src_ip'),
                'src_port': event.get('src_port'),
                'dest_ip': event.get('dest_ip'),
                'dest_port': event.get('dest_port'),
                'timestamp': event.get('timestamp'),
                'category': event.get('alert', {}).get('category'),
                'signature': event.get('alert', {}).get('signature'),
                'severity': event.get('alert', {}).get('severity'),
                'proto': event.get('proto')
            }
            alerts.append(alert)
            
            # Если включены уведомления и это критический алерт (severity=1),
            # отправляем уведомление через Telegram
            if send_notifications and alert['severity'] == 1:
                notify_suricata_alert(alert)
    
    # Создаём DataFrame из собранных алертов
    df = pd.DataFrame(alerts)
    print(f"Найдено алертов: {len(df)}")
    
    if len(df) > 0:
        # Определяем путь к папке reports (рядом с текущим скриптом)
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(reports_dir, exist_ok=True)  # создаём, если нет
        
        # Формируем имя CSV-файла с временной меткой
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_filename = os.path.join(reports_dir, f"suricata_alerts_{timestamp}.csv")
        # Сохраняем DataFrame в CSV (кодировка UTF-8)
        df.to_csv(csv_filename, index=False, encoding='utf-8')
        print(f"CSV сохранен: {csv_filename}")
        
        # Возвращаем DataFrame для дальнейшего использования (например, построения графиков)
        return df
    else:
        print("Нет алертов для обработки")
        # Возвращаем пустой DataFrame, чтобы вызывающий код мог проверить наличие данных
        return pd.DataFrame()