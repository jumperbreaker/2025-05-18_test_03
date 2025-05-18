# Система мониторинга сессий АРМ Linux и сбора системной информации

## Описание системы

### Система состоит из двух компонентов:
1. `install-session-monitor.sh` - устанавливает службу мониторинга сессий
2. `system-info-collector.sh` - собирает и отправляет детальную информацию о системе

## Полная инструкция по установке и настройке
### Установка зависимостей

Для RHEL/CentOS:

```bash
yum install -y jq curl dmidecode wget
``` 
Для Debian/Ubuntu:

```bash
apt-get install -y jq curl dmidecode wget
``` 

### Настройка скриптов
Перед запуском отредактируйте параметры в system-info-collector.sh:

```bash
SERVER="https://your-api.example.com/collect"  # Обязательно HTTPS!
API_TOKEN="your_very_long_and_secure_token"
DOMAIN="yourcompany"  # Домен
MAX_RETRIES=5         # Количество попыток отправки
RETRY_DELAY=10        # Задержка между попытками (сек)
```

Опубликуйте system-info-collector.sh на веб-сервере (COLLECTOR_URL)

### Установка службы
```bash
chmod 700 install-session-monitor.sh system-info-collector.sh
./install-session-monitor.sh
```

### Проверка работы
Проверка статуса:
```bash
systemctl status session-monitor
```

Просмотр логов:
```bash
journalctl -u session-monitor -f --lines=50
```

Проверка отправки данных:
```bash
grep "Отправка данных" /var/log/session-monitor.log
```

## Рекомендации по API серверу

### Требования к обработке данных

Аутентификация:
Обязательная проверка Bearer token
Реализация IP-фильтрации

Валидация:
Пример проверки на Python:
```bash
def validate_data(data):
    required_fields = ['hostname', 'mac_address', 'json_big_info']
    if not all(field in data for field in required_fields):
        raise ValueError("Missing required fields")
    
    if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", data['mac_address']):
        raise ValueError("Invalid MAC address")
```

### Хранение:
Раздельное хранение метаданных и полного дампа
Индексация по ключевым полям:

```bash
CREATE TABLE hosts (
    hostname VARCHAR(255) PRIMARY KEY,
    mac_address VARCHAR(17) UNIQUE,
    last_seen TIMESTAMP,
    os_info TEXT
);
```

### Оптимальная архитектура API
```bash
POST /api/v1/collect
Headers:
  Authorization: Bearer <token>
  Content-Type: application/json
  X-Client-Version: 1.1

Body:
  {
    "hostname": "string",
    "mac_address": "string",
    "ip_address": "string",
    "json_big_info": { ... }
  }

Response:
  200 OK - данные приняты
  401 Unauthorized - неверный токен
  400 Bad Request - ошибка валидации
  429 Too Many Requests - лимит запросов
Полное руководство по безопасности
```

## Защита данных
Всегда использовать HTTPS
Регулярно менять API токены
Шифровать чувствительные данные (MAC, серийные номера)

## Контроль доступа

Права на файлы:
```bash
chown root:root /usr/local/bin/session-monitor.sh
chmod 750 /usr/local/bin/session-monitor.sh
```

Права на логи:
```bash
chmod 640 /var/log/session-monitor.log
```

## Мониторинг
Пример alert-правил для Prometheus:

```bash
- alert: SessionMonitorDown
  expr: up{job="session-monitor"} == 0
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Session monitor down on {{ $labels.instance }}"

- alert: DataSendFailed
  expr: increase(session_monitor_send_errors_total[1h]) > 5
  labels:
    severity: warning
  annotations:
    description: "Failed to send data 5+ times in last hour"
```

## Расширенная диагностика
Логирование ошибок
Скрипт записывает все ошибки в:
Системный журнал (journalctl)
Файл /var/log/session-monitor.log

## Очистка системы
Для полного удаления:
```bash
systemctl stop session-monitor
systemctl disable session-monitor
rm -f /usr/local/bin/session-monitor.sh \
       /etc/systemd/system/session-monitor.service \
       /var/log/session-monitor.log
systemctl daemon-reload
```

## Полный перечень отправляемых данных (json)

```json
{
  "collector_version": "1.1",
  "system": {
    "hostname": "string",
    "os": "string",
    "kernel": "string",
    "uptime": "string",
    "users": number,
    "serial_number": "string",
    "bios_vendor": "string",
    "bios_version": "string",
    "bios_release_date": "string",
    "system_manufacturer": "string",
    "system_product_name": "string",
    "system_uuid": "string"
  },
  "user_sessions": [
    {
      "username": "string",
      "full_name": "string",
      "action_type": "login/logout",
      "action_time": "YYYY-MM-DD HH:MM:SS",
      "session_type": "ssh/gui",
      "client_ip": "string"
    }
  ],
  "hardware": {
    "cpu": {
      "model": "string",
      "cores": number,
      "frequency_ghz": "string"
    },
    "memory": {
      "total_gb": number,
      "used_gb": number
    },
    "storage": {
      "blockdevices": [
        {
          "name": "string",
          "size": "string",
          "type": "string",
          "mountpoint": "string",
          "fstype": "string"
        }
      ]
    },
    "pci_devices": [
      {
        "slot": "string",
        "description": "string"
      }
    ],
    "usb_devices": [
      {
        "bus": "string",
        "device": "string",
        "description": "string"
      }
    ],
    "monitors": [
      {
        "name": "string",
        "status": "string",
        "type": "string"
      }
    ],
    "printers": [
      {
        "name": "string",
        "device": "string"
      }
    ],
    "scanners": [
      {
        "device": "string",
        "description": "string"
      }
    ],
    "temperatures": [
      {
        "sensor": "string",
        "temperature": number,
        "unit": "C"
      }
    ]
  },
  "configs": {
    "sudoers_extra": ["string"],
    "hosts_entries": ["string"],
    "puppet_conf": ["string"]
  },
  "network": {
    "mac_address": "string",
    "ip_address": "string",
    "network_info": {
      "interfaces": [
        {
          "ifname": "string",
          "address": "string",
          "mtu": number
        }
      ],
      "ip_info": [
        {
          "ifindex": number,
          "ifname": "string",
          "addr_info": [
            {
              "local": "string",
              "prefixlen": number
            }
          ]
        }
      ]
    }
  },
  "filesystem": {
    "directory_structure": {
      "home": {
        "path": "/home",
        "type": "directory",
        "children": {
          "username": {
            "path": "string",
            "type": "directory",
            "permissions": "string",
            "owner": "string",
            "group": "string",
            "size": number,
            "modified": "string",
            "children": {
              "subdir": {
                "path": "string",
                "type": "directory",
                "permissions": "string",
                "owner": "string",
                "group": "string",
                "size": number,
                "modified": "string"
              }
            }
          }
        }
      }
    }
  },
  "software": {
    "services": {
      "service_name": {
        "load": "string",
        "active": "string",
        "sub": "string"
      }
    },
    "rpm_packages": ["string"]
  }
}
