#!/bin/bash

# Проверка прав root
if [ "$(id -u)" -ne 0 ]; then
    echo "Этот скрипт должен быть запущен с правами root!" >&2
    exit 1
fi

# Общая конфигурация
CONFIG=$(cat <<'EOC'
# Настройки
COLLECTOR_URL="http://server-ip/collector_script/system-info-collector.sh"
SERVICE_NAME="session-monitor"
SCRIPT_NAME="session-monitor.sh"
SCRIPT_PATH="/usr/local/bin/$SCRIPT_NAME"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME.service"
LOG_PATH="/var/log/$SERVICE_NAME.log"
COLLECTOR_SCRIPT="/tmp/system-info-collector.sh"

# Системные пользователи (исключения)
SYSTEM_USERS=("_ldm" "root" "lightdm")
EOC
)

# Загружаем конфигурацию
eval "$CONFIG"

# Разрешаем чтение DMI таблиц при загрузке
if [ ! -f /etc/cron.d/dmi_tables_readable ]; then
    echo "@reboot root chmod a+r /sys/firmware/dmi/tables/*" | tee /etc/cron.d/dmi_tables_readable >/dev/null
    echo "Добавлено правило cron для доступа к DMI таблицам"
    chmod 644 /etc/cron.d/dmi_tables_readable
fi

# Устанавливаем права на sudoers
if [ $(stat -c %a /etc/sudoers) -ne 444 ]; then
    chmod 444 /etc/sudoers
    echo "Установлены права на /etc/sudoers (444)"
fi

# Создаем основной скрипт с подстановкой переменных
cat > "$SCRIPT_PATH" <<EOF
#!/bin/bash

# Перенаправляем вывод в лог-файл
exec >> $LOG_PATH 2>&1

# Конфигурация
COLLECTOR_URL="$COLLECTOR_URL"
COLLECTOR_SCRIPT="$COLLECTOR_SCRIPT"
SYSTEM_USERS=(${SYSTEM_USERS[@]})

# Функция для скачивания скрипта-коллектора
download_collector_script() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Загрузка скрипта-коллектора..."
    rm -f "\$COLLECTOR_SCRIPT"
    if wget -q "\$COLLECTOR_URL" -O "\$COLLECTOR_SCRIPT"; then
        chmod +x "\$COLLECTOR_SCRIPT"
        echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Скрипт-коллектор успешно загружен"
        return 0
    else
        echo "[\$(date '+%Y-%m-%d %H:%M:%S')] ОШИБКА: Не удалось загрузить скрипт" >&2
        return 1
    fi
}

# Проверка системного пользователя
is_system_user() {
    local user="\$1"
    for system_user in "\${SYSTEM_USERS[@]}"; do
        [[ "\$user" == "\$system_user" ]] && return 0
    done
    return 1
}

# Глобальный массив активных сессий
declare -A ACTIVE_SESSIONS

# Отправка logout при выключении
send_logout_for_all() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Отправка logout для всех сессий..."
    for user in "\${!ACTIVE_SESSIONS[@]}"; do
        session_type="\${ACTIVE_SESSIONS["\$user"]}"
        "\$COLLECTOR_SCRIPT" "logout" "\$user" "localhost" "\$session_type" || true
    done
}

# Обработка SSH логов
process_ssh_log() {
    while read -r line; do
        if ([[ "\$line" == *"Accepted password for"* ]] || [[ "\$line" == *"Accepted publickey for"* ]]) && [[ "\$line" != *"tty=:0"* ]]; then
            user=\$(awk '{print \$9}' <<< "\$line")
            ip=\$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "\$line" | head -1)
            
            if ! is_system_user "\$user"; then
                ACTIVE_SESSIONS["\$user"]="ssh"
                "\$COLLECTOR_SCRIPT" "login" "\$user" "\$ip" "ssh" || true
            fi
        
        elif [[ "\$line" == *"USER_END"* ]] && [[ "\$line" != *"terminal=:0"* ]]; then
            user=\$(grep -oP 'acct="\\K[^"]+' <<< "\$line")
            ip=\$(grep -oP 'addr=\\K[0-9.]+' <<< "\$line")
            
            if [[ -n "\$user" ]] && ! is_system_user "\$user"; then
                unset ACTIVE_SESSIONS["\$user"]
                "\$COLLECTOR_SCRIPT" "logout" "\$user" "\${ip:-localhost}" "ssh" || true
            fi
        fi
    done
}

# Обработка GUI логов
process_gui_log() {
    while read -r line; do
        if [[ "\$line" == *"pam_sss(lightdm:auth): authentication success"* && "\$line" == *"tty=:0"* ]]; then
            user=\$(grep -oP 'user=\\K[^ ]+' <<< "\$line")
            
            if [[ -n "\$user" ]] && ! is_system_user "\$user" && [[ -z "\${ACTIVE_SESSIONS["\$user"]}" ]]; then
                ACTIVE_SESSIONS["\$user"]="gui"
                "\$COLLECTOR_SCRIPT" "login" "\$user" "localhost" "gui" || true
            fi
            
        elif [[ "\$line" == *"Stopped Session"*"of User"* ]] || 
             [[ "\$line" == *"USER_END"* && "\$line" == *"terminal=:0"* ]]; then
            user=\$( [[ "\$line" == *"acct="* ]] && grep -oP 'acct="\\K[^"]+' <<< "\$line" || awk '{print \$NF}' <<< "\$line" | tr -d '.')
            
            if [[ -n "\$user" ]] && ! is_system_user "\$user" && [[ -n "\${ACTIVE_SESSIONS["\$user"]}" ]]; then
                unset ACTIVE_SESSIONS["\$user"]
                "\$COLLECTOR_SCRIPT" "logout" "\$user" "localhost" "gui" || true
            fi
        fi
    done
}

# Обработка выключения
if [[ "\$1" == "--shutdown" ]]; then
    send_logout_for_all
    exit 0
fi

# Основной цикл
main() {
    download_collector_script || { [ -x "\$COLLECTOR_SCRIPT" ] || exit 1; }
    
    pkill -f "journalctl.*session-monitor" 2>/dev/null || true
    
    journalctl -f | grep --line-buffered -E "Accepted (password|publickey) for|USER_END" | process_ssh_log &
    SSH_PID=\$!
    
    journalctl -f | grep --line-buffered -E "pam_sss\\(lightdm:auth\\): authentication success.*tty=:0|Stopped Session.*of User|USER_END.*terminal=:0" | process_gui_log &
    GUI_PID=\$!
    
    trap 'send_logout_for_all; kill \$SSH_PID \$GUI_PID 2>/dev/null; exit 0' TERM INT EXIT
    wait
}

main
EOF

# Установка прав
chmod +x "$SCRIPT_PATH"
touch "$LOG_PATH"
chmod 644 "$LOG_PATH"

# Создание службы systemd
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Session Monitor Service
After=network.target syslog.target
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target

[Service]
Type=simple
ExecStart=$SCRIPT_PATH
ExecStop=$SCRIPT_PATH --shutdown
Restart=always
RestartSec=5
User=root
Group=root
StandardOutput=append:$LOG_PATH
StandardError=append:$LOG_PATH
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

# Активация службы
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# Проверка
echo "Установка завершена"
echo "Логи: tail -f $LOG_PATH"
echo "Управление: systemctl [start|stop|restart] $SERVICE_NAME"