
import os
import threading
import time
import queue
from dotenv import load_dotenv
from suricata_processor import process_suricata_logs
from virustotal_processor import VirusTotalProcessor
import matplotlib
from pathlib import Path

# Устанавливаем бэкенд для matplotlib для возможности генерации графиков в фоне
matplotlib.use('Agg')

# Загружаем переменные окружения из .env файла
load_dotenv()

# Глобальные переменные для обмена данными между потоками
suricata_result = None          # DataFrame с результатами Suricata
suricata_done = False           # Флаг завершения потока Suricata
suricata_error = None           # Сообщение об ошибке (если возникла)
vt_results = None               # Результаты VirusTotal (словарь)


def run_suricata_processing():
    """
    Запускает обработку логов Suricata в отдельном потоке.
    
    Функция считывает путь к лог-файлу из переменной окружения SURICATA_LOG_PATH,
    вызывает модуль обработки и сохраняет результат в глобальную переменную.
    В случае ошибки записывает сообщение в suricata_error.
    По окончании работы устанавливает флаг suricata_done = True.
    """
    global suricata_result, suricata_done, suricata_error
    print("\n Запуск обработки Suricata...")
    
    # Определяем корень проекта и загружаем .env повторно (на случай, если основной поток уже загрузил)
    PROJECT_ROOT = Path(__file__).parent
    dotenv_path = PROJECT_ROOT / '.env'
    load_dotenv(dotenv_path)
    
    # Получаем относительный путь к логу Suricata из переменной окружения
    log_filename = os.getenv("SURICATA_LOG_PATH")
    
    if log_filename:
        # Преобразуем относительный путь в абсолютный относительно корня проекта
        log_path = PROJECT_ROOT / log_filename
        log_path = str(log_path)  # преобразуем обратно в строку, если функция ожидает строку
    else:
        log_path = None
    
    try:
        # Вызываем функцию обработки логов Suricata (из внешнего модуля)
        df = process_suricata_logs(log_path, send_notifications=True)
        if df is not None:
            suricata_result = df
            print(f"Suricata: обработано {len(df)} алертов")
    except Exception as e:
        # В случае исключения сохраняем ошибку
        suricata_error = str(e)
    finally:
        # Обязательно отмечаем завершение потока
        suricata_done = True
        print("Поток Suricata завершен")


def run_virustotal_interactive():
    """
    Запускает интерактивный режим VirusTotal.
    
    Создаёт экземпляр VirusTotalProcessor, вызывает его метод interactive_mode(),
    который позволяет пользователю вводить хеши файлов для проверки.
    Результаты сохраняются в глобальную переменную vt_results.
    """
    global vt_results
    print("\n Запуск VirusTotal...")
    vt = VirusTotalProcessor(send_notifications=True)
    vt.interactive_mode()  # Интерактивный ввод хешей
    if vt.all_results:
        vt_results = vt.all_results
        print(f"VirusTotal: {len(vt_results)} проверок")


def generate_plots():
    """
    Генерирует графики на основе полученных данных Suricata и VirusTotal.
    
    Использует внешние функции plot_suricata_alerts и plot_vt_results из модуля plot_generator.
    Графики сохраняются в файлы с временной меткой в имени.
    Функция вызывается только один раз после завершения всех процессов.
    """
    from plot_generator import plot_suricata_alerts, plot_vt_results
    from datetime import datetime
    
    print("\n Генерация графиков...")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    plots_created = 0
    
    # Построение графика по данным Suricata, если они есть
    if suricata_result is not None and not suricata_result.empty:
        try:
            plot_suricata_alerts(suricata_result, f"suricata_plot_{timestamp}.png")
            plots_created += 1
        except Exception as e:
            print(f"Ошибка графика Suricata: {e}")
    else:
        print("Нет данных Suricata для графика")
    
    # Построение графика по данным VirusTotal, если они есть
    if vt_results:
        try:
            # Оборачиваем результаты в словарь с ключом 'results' для совместимости с plot_vt_results
            plot_vt_results({"results": vt_results}, f"vt_plot_{timestamp}.png")
            plots_created += 1
        except Exception as e:
            print(f"Ошибка графика VT: {e}")
    else:
        print("Нет данных VirusTotal для графика")
    
    print(f"Создано графиков: {plots_created}")


def parallel_processing():
    """
    Выполняет параллельную обработку Suricata и VirusTotal.
    
    Suricata запускается в фоновом потоке, VirusTotal — в интерактивном режиме в основном потоке.
    После завершения интерактивного режима ожидается завершение потока Suricata,
    затем генерируются итоговые графики.
    """
    global suricata_done, suricata_result, vt_results
    
    print("\n" + "="*60)
    print("ПАРАЛЛЕЛЬНАЯ ОБРАБОТКА")
    print("="*60)
    
    # Сбрасываем глобальные переменные перед запуском
    suricata_result = None
    suricata_done = False
    vt_results = None
    
    # Запускаем поток для обработки Suricata
    suricata_thread = threading.Thread(target=run_suricata_processing)
    suricata_thread.daemon = True   # Поток завершится вместе с основной программой
    suricata_thread.start()
    
    time.sleep(1)  # Небольшая пауза для гарантии запуска потока
    
    # Запускаем интерактивный режим VirusTotal (блокирует основной поток)
    print("\n VirusTotal (интерактивный режим)")
    run_virustotal_interactive()
    
    # Ожидаем завершения потока Suricata
    print("\n Ожидание завершения Suricata...")
    while not suricata_done:
        time.sleep(1)
        print(f"   Ожидание...", end='\r')
    
    print("\nSuricata завершена")
    
    # Генерация графиков (один раз после сбора всех данных)
    generate_plots()
    
    print("\n Параллельная обработка завершена")


def main():
    """
    Точка входа в программу. Предлагает пользователю выбрать режим работы:
    1 - только Suricata
    2 - только VirusTotal
    3 - параллельная обработка
    4 - выход
    После выбора запускает соответствующие функции и генерирует графики.
    Обрабатывает прерывание с клавиатуры (Ctrl+C).
    """
    print("="*60)
    print("SECURITY ANALYZER")
    print("="*60)
    print("1. Только Suricata")
    print("2. Только VirusTotal")
    print("3. Параллельно")
    print("4. Выход")
    print("="*60)
    
    choice = input("\n Выберите (1-4): ").strip()
    
    try:
        if choice == "1":
            run_suricata_processing()
            # Даём время потоку завершиться
            time.sleep(2)
            generate_plots()
        elif choice == "2":
            run_virustotal_interactive()
            generate_plots()
        elif choice == "3":
            parallel_processing()
        elif choice == "4":
            print("Выход")
    except KeyboardInterrupt:
        print("\n\n Прервано")


if __name__ == "__main__":
    main()