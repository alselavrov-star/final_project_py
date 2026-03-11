"""
Модуль для визуализации данных анализа безопасности.
Содержит функции построения графиков по результатам VirusTotal и Suricata.
Графики сохраняются в папку 'reports' рядом со скриптом.
"""

import matplotlib
# Устанавливаем бэкенд Agg для работы без графического интерфейса
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os
from datetime import datetime

def get_reports_dir():
    """
    Создаёт и возвращает путь к директории reports, расположенной в той же папке, что и текущий скрипт.
    
    Returns:
        str: абсолютный путь к папке reports.
    """
    # Получаем абсолютный путь к каталогу, содержащему этот файл
    script_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(script_dir, "reports")
    # Создаём директорию, если она ещё не существует (exist_ok=True предотвращает ошибку)
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir

def plot_vt_results(data, out=None):
    """
    Строит и сохраняет график с результатами проверок VirusTotal.
    
    График состоит из двух подграфиков:
      - столбчатая диаграмма количества вредоносных (malicious) и подозрительных 
      (suspicious) детектов по объектам;
      - горизонтальная столбчатая диаграмма репутации (если данные есть).
    
    Args:
        data (dict): Словарь с ключом 'results', содержащий список результатов проверок.
        out (str, optional): Имя выходного файла. Если не указано, генерируется автоматически 
        с временной меткой.
    """
    try:
        results = data.get('results', [])
        if not results: 
            return print("Нет данных")
        
        # Подготовка данных для построения
        names, mal, susp, reps, rnames = [], [], [], [], []
        for r in results:
            if not r.get('data'):  # Пропускаем записи без данных
                continue
            d = r['data']
            # Обрезаем длинные имена для читаемости на графике
            name = r['query'][:15] + ('...' if len(r['query']) > 15 else '')
            names.append(name)
            mal.append(d.get('stats', {}).get('malicious', 0))
            susp.append(d.get('stats', {}).get('suspicious', 0))
            # Если есть информация о репутации, запоминаем отдельно
            if 'reputation' in d:
                rnames.append(name)
                reps.append(d['reputation'])
        
        if not names: 
            return print("Нет данных для графика")
        
        # Создаём фигуру с двумя подграфиками в одной строке
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # ---- Левый график: детекты ----
        x = np.arange(len(names))
        w = 0.35  # ширина столбцов
        ax1.bar(x - w/2, mal, w, label='Malicious', color='#ff4444')
        ax1.bar(x + w/2, susp, w, label='Suspicious', color='#ff8800')
        ax1.set_title('Детекты по объектам')
        ax1.set_xticks(x)
        ax1.set_xticklabels(names, rotation=45, ha='right')
        ax1.legend()
        ax1.grid(alpha=0.3)
        
        # ---- Правый график: репутация (если есть) ----
        if reps:
            # Цвет: зелёный для положительной репутации, красный для отрицательной
            colors = ['#00C851' if v > 0 else "#ff2e2e" for v in reps]
            ax2.barh(rnames, reps, color=colors)
            ax2.set_title('Репутация')
            ax2.axvline(x=0, color='black', ls='--', alpha=0.5)  # вертикальная линия в нуле
        
        plt.suptitle(f'VirusTotal: {len(results)} объектов')
        plt.tight_layout()
        
        # Сохранение графика
        reports_dir = get_reports_dir()
        if out is None:
            # Формируем имя файла с временной меткой
            out = f"vt_plot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        # Если out уже содержит путь к директории, используем его как есть,
        # иначе добавляем путь к reports_dir
        if os.path.dirname(out):
            full_path = out
        else:
            full_path = os.path.join(reports_dir, out)
        
        plt.savefig(full_path, dpi=100, bbox_inches='tight')
        plt.close()  # Закрываем фигуру для освобождения памяти
        print(f"График VT сохранен: {full_path}")
        
    except Exception as e:
        print(f"Ошибка графика VT: {e}")

def plot_suricata_alerts(df, out=None):
    """
    Строит и сохраняет набор графиков на основе DataFrame с алертами Suricata.
    
    Графики включают:
      - топ источников угроз (source IP)
      - топ целей атак (destination IP)
      - распределение по уровню опасности (severity)
      - топ категорий угроз
    
    Args:
        df (pandas.DataFrame): DataFrame, содержащий колонки 'src_ip', 'dest_ip', 
        'severity', 'category'.
        out (str, optional): Имя выходного файла. Если не указано, генерируется 
        автоматически с временной меткой.
    """
    try:
        if df is None or df.empty:
            return print("Нет данных Suricata")
        
        # Создаём сетку 2x2 подграфиков
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        
        # Верхний левый: топ источников
        top_src = df['src_ip'].value_counts().head(8)
        ax1.barh(range(len(top_src)), top_src.values, color='#ff4444')
        ax1.set_yticks(range(len(top_src)))
        # Обрезаем длинные IP для читаемости
        ax1.set_yticklabels([i[:15] for i in top_src.index])
        ax1.set_title('Топ источников угроз')
        ax1.set_xlabel('Количество')
        
        # Верхний правый: топ целей
        top_dst = df['dest_ip'].value_counts().head(8)
        ax2.barh(range(len(top_dst)), top_dst.values, color='#ff8800')
        ax2.set_yticks(range(len(top_dst)))
        ax2.set_yticklabels([i[:15] for i in top_dst.index])
        ax2.set_title('Топ целей атак')
        ax2.set_xlabel('Количество')
        
        # Нижний левый: распределение severity
        sev = df['severity'].value_counts().sort_index()
        # Словарь для преобразования числовых значений severity в текстовые метки
        labs = {1: 'Критический', 2: 'Высокий', 3: 'Средний', 4: 'Низкий'}
        # Цвета в порядке возрастания severity (чем выше опасность, тем ярче)
        colors = ['#ff4444', '#ff8800', '#ffbb33', '#00C851'][:len(sev)]
        ax3.pie(sev.values, labels=[labs.get(s, str(s)) for s in sev.index],
                autopct='%1.0f%%', colors=colors)
        ax3.set_title('Уровень опасности')
        
        # Нижний правый: топ категорий
        top_cat = df['category'].value_counts().head(8)
        bars = ax4.bar(range(len(top_cat)), top_cat.values, color=plt.cm.viridis(np.linspace(0, 1, 8)))
        ax4.set_xticks(range(len(top_cat)))
        # Обрезаем длинные названия категорий
        ax4.set_xticklabels([c[:15] + ('...' if len(c) > 15 else '') for c in top_cat.index],
                            rotation=45, ha='right')
        ax4.set_title('Топ категорий угроз')
        ax4.set_ylabel('Количество')
        
        # Добавляем подписи значений над столбцами
        for i, (bar, val) in enumerate(zip(bars, top_cat.values)):
            ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                     str(val), ha='center', va='bottom', fontsize=9)
        
        plt.suptitle(f'Suricata Alerts: всего {len(df)}', fontsize=14)
        plt.tight_layout()
        
        # Сохранение графика
        reports_dir = get_reports_dir()
        if out is None:
            out = f"suricata_plot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        if os.path.dirname(out):
            full_path = out
        else:
            full_path = os.path.join(reports_dir, out)
        
        plt.savefig(full_path, dpi=100, bbox_inches='tight')
        plt.close()
        print(f"График Suricata сохранен: {full_path}")
        
    except Exception as e:
        print(f"Ошибка графика Suricata: {e}")