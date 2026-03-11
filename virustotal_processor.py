"""
Модуль для взаимодействия с VirusTotal API.
Позволяет проверять IP-адреса, домены и файлы на наличие угроз,
сохранять результаты в JSON и отправлять уведомления в Telegram.
"""

import os
import json
import hashlib
import vt
from datetime import datetime
from dotenv import load_dotenv
from telegram_notifier import notify_vt_threat

# Загружаем переменные окружения (API ключ)
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
# Определяем директорию, в которой находится скрипт
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class VirusTotalProcessor:
    """
    Класс для обработки запросов к VirusTotal.

    Атрибуты:
        all_results (list): Список всех результатов проверок.
        send_notifications (bool): Флаг отправки уведомлений в Telegram.
    """

    def __init__(self, send_notifications=True):
        """
        Инициализирует экземпляр процессора VirusTotal.

        Args:
            send_notifications (bool): Нужно ли отправлять уведомления об угрозах.
        """
        self.all_results = []
        self.send_notifications = send_notifications

    def save_results(self):
        """
        Сохраняет все накопленные результаты проверок в JSON-файл в папке reports.

        Returns:
            str или None: Путь к сохранённому файлу или None, если нет данных.
        """
        if not self.all_results:
            print("Нет данных для сохранения")
            return None

        # Создаём папку reports, если её нет
        reports_dir = os.path.join(SCRIPT_DIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        # Формируем имя файла с временной меткой
        filename = f"vt_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(reports_dir, filename)

        # Сохраняем данные в JSON (с отступами для читаемости)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({"results": self.all_results}, f, indent=2, default=str)
        print(f"JSON сохранен: {filepath}")

        return filepath

    def check(self, url, name, type_name, client):
        """
        Выполняет запрос к VirusTotal по указанному URL, извлекает статистику и репутацию,
        добавляет результат в список и при необходимости отправляет уведомление.

        Args:
            url (str): URL объекта в API VirusTotal (например, "/ip_addresses/8.8.8.8").
            name (str): Человеко-читаемое имя объекта (сам IP, домен и т.п.).
            type_name (str): Тип объекта ("ip", "domain", "file").
            client (vt.Client): Экземпляр клиента VirusTotal (уже открыт).
        """
        # Получаем объект из API
        obj = client.get_object(url)
        # Извлекаем статистику последнего анализа
        stats = dict(obj.last_analysis_stats)
        rep = getattr(obj, 'reputation', 0)

        # Выводим информацию в консоль
        print(f"\n{type_name}: {name}")
        print(f"  Mal: {stats['malicious']} Susp: {stats['suspicious']} Rep: {rep}")

        # Формируем запись результата
        result = {
            "timestamp": datetime.now().isoformat(),
            "type": type_name,
            "query": name,
            "data": {
                "reputation": rep,
                "stats": stats
            }
        }
        self.all_results.append(result)

        # Если включены уведомления, вызываем функцию отправки
        if self.send_notifications:
            notify_vt_threat(result, {"reputation": rep}, stats)

    def check_ip(self, ip):
        """
        Проверяет IP-адрес через VirusTotal.

        Args:
            ip (str): IP-адрес для проверки.
        """
        # Открываем клиент (контекстный менеджер гарантирует закрытие соединения)
        with vt.Client(API_KEY) as client:
            try:
                self.check(f"/ip_addresses/{ip}", ip, "ip", client)
            except vt.error.APIError as e:
                # Обрабатываем специфичные ошибки API
                if e.code == "NotFoundError":
                    print(f'IP {ip} не найден')
                else:
                    print(f'Ошибка API: {e}')
            except Exception as e:
                print(f'Ошибка при проверке IP: {e}')

    def check_domain(self, domain):
        """
        Проверяет доменное имя через VirusTotal.

        Args:
            domain (str): Домен для проверки.
        """
        with vt.Client(API_KEY) as client:
            try:
                self.check(f"/domains/{domain}", domain, "domain", client)
            except vt.error.APIError as e:
                if e.code == "NotFoundError":
                    print(f'Домен {domain} не найден в базе VirusTotal')
                else:
                    print(f'Ошибка API VirusTotal: {e}')
            except Exception as e:
                print(f'Неожиданная ошибка при проверке домена: {e}')

    def check_file(self, path):
        """
        Проверяет файл по его SHA256-хешу через VirusTotal.

        Args:
            path (str): Путь к локальному файлу.
        """
        if not os.path.exists(path):
            print("Файл не найден")
            return

        # Вычисляем SHA256 хеш файла
        with open(path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        with vt.Client(API_KEY) as client:
            try:
                obj = client.get_object(f"/files/{file_hash}")
                stats = dict(obj.last_analysis_stats)
                print(f"\nФайл: {path}\n  Mal: {stats['malicious']}")
                result = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "file",
                    "query": path,
                    "data": {
                        "hash": file_hash,
                        "stats": stats
                    }
                }
                self.all_results.append(result)
                if self.send_notifications:
                    # Для файлов дополнительные атрибуты (репутация и т.п.) не передаём
                    notify_vt_threat(result, {}, stats)
            except vt.error.APIError:
                print("Файл не найден в VT")
            except Exception as e:
                print(f"Ошибка при проверке файла: {e}")

    def interactive_mode(self):
        """
        Запускает интерактивный режим, позволяющий пользователю последовательно
        вводить объекты для проверки, пока он не выберет сохранение или выход.
        """
        while True:
            # Показываем меню и количество уже проверенных объектов
            print(f"\n[{len(self.all_results)}] 1.IP | 2.Домен | 3.Файл |"
                  f" 4.Сохранить и выйти | 5.Выход без сохранения")
            choice = input("> ").strip()

            if choice == "1":
                ip = input("IP: ")
                self.check_ip(ip)
            elif choice == "2":
                domain = input("Домен: ")
                self.check_domain(domain)
            elif choice == "3":
                file_path = input("Путь: ").strip('"')  # Убираем кавычки, если пользователь их ввёл
                self.check_file(file_path)
            elif choice == "4":
                self.save_results()
                break
            elif choice == "5":
                break
            else:
                print("Неверный выбор, попробуйте снова.")