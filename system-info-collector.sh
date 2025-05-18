#!/bin/bash

# Конфигурация
SERVER="http://server-ip/api/collector"
API_TOKEN="you_secret_token"
COLLECTOR_VERSION="1.1"
MAX_RETRIES=3
RETRY_DELAY=5
DOMAIN="YOU_DOMAIN"

# Параметры сессии (передаются при запуске)
ACTION_TYPE="${1:-}"  # login или logout
USER="${2:-}"
CLIENT_IP="${3:-}"
SESSION_TYPE="${4:-}"

# Функция для безопасного получения данных
safe_get() {
    local cmd="$1"
    local default="$2"
    local result
    result=$(eval "$cmd" 2>/dev/null)
    if [ -z "$result" ]; then
        echo "$default"
    else
        echo "$result"
    fi
}

# Функция получения полного имени пользователя
get_full_name() {
    local username="$1"
    local full_name
    full_name=$(getent passwd "$username" | cut -d: -f5 | cut -d, -f1)
    [ -z "$full_name" ] && full_name="$username"
    echo "$full_name"
}

# Функция получения данных о текущих сессиях
get_user_sessions() {
    local sessions=()
    
    if [ -n "$ACTION_TYPE" ] && [ -n "$USER" ] && [ -n "$CLIENT_IP" ]; then
        local full_name
        full_name=$(get_full_name "$USER")        
        
        sessions+=("{
            \"username\": \"$USER\",
            \"full_name\": \"$full_name\",
            \"action_type\": \"$ACTION_TYPE\",
            \"action_time\": \"$(date '+%Y-%m-%d %H:%M:%S')\",            
            \"session_type\": \"$SESSION_TYPE\",
            \"client_ip\": \"$CLIENT_IP\"            
        }")    
    fi
    
    if [[ ${#sessions[@]} -gt 0 ]]; then
        printf "%s\n" "${sessions[@]}" | jq -s .
    else
        echo "[]"
    fi
}

# Функция получения структуры каталогов
get_home_directory_structure() {
    local base_dir="/home"
    local corp_dir="/home/$DOMAIN"
    
    local home_dirs=$(find "$base_dir" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" 2>/dev/null | sort)
    local corp_dirs=""
    [ -d "$corp_dir" ] && corp_dirs=$(find "$corp_dir" -maxdepth 1 -mindepth 1 -type d -printf "%f\n" 2>/dev/null | sort)
    
    echo -n "{"
    echo -n "\"home\": {"
    echo -n "\"path\": \"$base_dir\","
    echo -n "\"type\": \"directory\","
    echo -n "\"children\": {"
    
    local first=1
    while IFS= read -r dir; do
        [ -z "$dir" ] && continue
        [ "$first" -eq 0 ] && echo -n ","
        first=0
        
        local dir_path="$base_dir/$dir"
        local stat_info=$(stat -c '%A %u %g %s %y' "$dir_path" 2>/dev/null)
        
        echo -n "\"$dir\": {"
        echo -n "\"path\": \"$dir_path\","
        echo -n "\"type\": \"directory\","
        echo -n "\"permissions\": \"$(echo "$stat_info" | awk '{print $1}')\","
        echo -n "\"owner\": \"$(echo "$stat_info" | awk '{print $2}')\","
        echo -n "\"group\": \"$(echo "$stat_info" | awk '{print $3}')\","
        echo -n "\"size\": $(echo "$stat_info" | awk '{print $4}'),"
        echo -n "\"modified\": \"$(echo "$stat_info" | awk '{print $5" "$6" "$7}')\""
        
        if [ "$dir" = "$DOMAIN" ] && [ -n "$corp_dirs" ]; then
            echo -n ",\"children\": {"
            local corp_first=1
            while IFS= read -r subdir; do
                [ -z "$subdir" ] && continue
                [ "$corp_first" -eq 0 ] && echo -n ","
                corp_first=0
                
                local subdir_path="$corp_dir/$subdir"
                local sub_stat_info=$(stat -c '%A %u %g %s %y' "$subdir_path" 2>/dev/null)
                
                echo -n "\"$subdir\": {"
                echo -n "\"path\": \"$subdir_path\","
                echo -n "\"type\": \"directory\","
                echo -n "\"permissions\": \"$(echo "$sub_stat_info" | awk '{print $1}')\","
                echo -n "\"owner\": \"$(echo "$sub_stat_info" | awk '{print $2}')\","
                echo -n "\"group\": \"$(echo "$sub_stat_info" | awk '{print $3}')\","
                echo -n "\"size\": $(echo "$sub_stat_info" | awk '{print $4}'),"
                echo -n "\"modified\": \"$(echo "$sub_stat_info" | awk '{print $5" "$6" "$7}')\""
                echo -n "}"
            done <<< "$corp_dirs"
            echo -n "}"
        fi
        
        echo -n "}"
    done <<< "$home_dirs"
    
    echo -n "}}"
    echo -n "}"
}

# Функция получения IP-адреса
get_ip_address() {
    local ip
    local ip_methods=(
        "hostname -I | awk '{print \$1}'"
        "ip route get 1 | awk '{print \$7;exit}'"
        "ip addr show | grep 'inet ' | grep -v '127.0.0.1' | head -n1 | awk '{print \$2}' | cut -d'/' -f1"
    )
    
    for method in "${ip_methods[@]}"; do
        ip=$(eval "$method" 2>/dev/null)
        [ -n "$ip" ] && { echo "$ip"; return; }
    done
    
    echo "0.0.0.0"
}

# Функция получения информации о дисках
get_disks_info() {
    if command -v lsblk &>/dev/null; then
        lsblk -J -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE 2>/dev/null || echo '{}'
    else
        echo '{}'
    fi
}

# Функция получения информации о сети
get_network_info() {
    echo "{\"interfaces\": $(ip -j link show 2>/dev/null || echo '[]'), \"ip_info\": $(ip -j addr show 2>/dev/null || echo '[]')}"
}

# Функция получения DMI информации
get_dmi_data() {
    local type="$1"
    local field="$2"
    local result
    if command -v dmidecode &>/dev/null; then
        result=$(dmidecode -t "$type" 2>/dev/null | grep -i "$field" | head -1 | cut -d':' -f2 | sed 's/^\s*//;s/\s*$//')
    fi
    echo "${result:-Неизвестно}"
}

# Функция получения содержимого sudoers
get_sudoers_content() {
    local sudoers_file="/etc/sudoers"
    local include_line="@includedir /etc/sudoers.d"
    
    [ ! -f "$sudoers_file" ] && { echo '[]'; return; }
    
    awk -v include_line="$include_line" '
        $0 ~ include_line { found=1; next }
        found { print }
    ' "$sudoers_file" | tr -cd '\11\12\15\40-\176' | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo '[]'
}

# Функция получения содержимого /etc/hosts
get_hosts_content() {
    local hosts_file="/etc/hosts"
    
    [ ! -f "$hosts_file" ] && { echo '[]'; return; }
    
    grep -v '^#' "$hosts_file" | grep -v '^$' | sed 's/\t/ /g' | awk '{$1=$1;print}' | tr -cd '\11\12\15\40-\176' | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo '[]'
}

# Функция получения содержимого puppet.conf
get_puppet_conf_content() {
    local puppet_file="/etc/puppet/puppet.conf"
    
    [ ! -f "$puppet_file" ] && { echo '[]'; return; }
    
    grep -v '^#' "$puppet_file" | grep -v '^$' | sed 's/\t/ /g' | awk '{$1=$1;print}' | tr -cd '\11\12\15\40-\176' | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo '[]'
}

# Функция получения информации о BIOS и системе
get_bios_system_info() {
    echo "{
    \"bios_vendor\": \"$(get_dmi_data bios 'Vendor')\",
    \"bios_version\": \"$(get_dmi_data bios 'Version')\",
    \"bios_release_date\": \"$(get_dmi_data bios 'Release Date')\",
    \"system_manufacturer\": \"$(get_dmi_data system 'Manufacturer')\",
    \"system_product_name\": \"$(get_dmi_data system 'Product Name')\",
    \"system_uuid\": \"$(get_dmi_data system 'UUID')\"
    }"
}

# Функция получения серийного номера системы
get_serial_number() {
    local serial
    serial=$(get_dmi_data system 'Serial Number')
    [ -z "$serial" ] && serial=$(grep -i 'serial' /proc/cpuinfo 2>/dev/null | head -n1 | awk -F': ' '{print $2}')
    echo "${serial:-Неизвестно}"
}

# Функция получения списка установленных RPM-пакетов
get_installed_rpms() {
    if command -v rpm &>/dev/null; then
        rpm -qa 2>/dev/null | head -c 100000 | tr -cd '\11\12\15\40-\176' | jq -R -s -c 'split("\n")[:-1]' || echo '[]'
    else
        echo '[]'
    fi
}

# Функция получения информации о службах
get_services_info() {
    local services='{}'
    
    # Попытка получить информацию через systemd (если доступен)
    if command -v systemctl >/dev/null 2>&1; then
        services=$(systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null | \
            awk '{print $1 "\t" $2 "\t" $3 "\t" $4}' | \
            tr -cd '\11\12\15\40-\176' | \
            jq -R -s 'split("\n") | map(select(length > 0)) | map(split("\t")) | map({
                (.[0]): {
                    "load": .[1],
                    "active": .[2],
                    "sub": .[3]
                }
            }) | add' 2>/dev/null || echo '{}')
        
        # Если не получили данные, пробуем альтернативный метод systemctl
        if [ "$(echo "$services" | tr -d '[:space:]')" = "{}" ]; then
            services=$(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | \
                awk '{print $1 "\t" $2}' | \
                tr -cd '\11\12\15\40-\176' | \
                jq -R -s 'split("\n") | map(select(length > 0)) | map(split("\t")) | map({
                    (.[0]): {
                        "load": .[1],
                        "active": "unknown",
                        "sub": "unknown"
                    }
                }) | add' 2>/dev/null || echo '{}')
        fi
    fi

    # Если systemd не дал результатов, пробуем классические init.d скрипты
    if [ "$services" = "{}" ] && [ -d /etc/init.d ]; then
        services=$(find /etc/init.d/ -executable -type f -printf "%f\n" 2>/dev/null | \
            while read -r service; do
                local status="unknown"
                # Безопасная проверка статуса сервиса
                if /etc/init.d/"$service" status >/dev/null 2>&1; then
                    if /etc/init.d/"$service" status 2>&1 | grep -q "running"; then
                        status="active"
                    else
                        status="inactive"
                    fi
                fi
                printf "%s\t%s\n" "$service" "$status"
            done | \
            tr -cd '\11\12\15\40-\176' | \
            jq -R -s 'split("\n") | map(select(length > 0)) | map(split("\t")) | map({
                (.[0]): {
                    "load": "unknown",
                    "active": .[1],
                    "sub": "unknown"
                }
            }) | add' 2>/dev/null || echo '{}')
    fi

    # Если всё ещё нет данных, просто перечислим доступные сервисы из init.d
    if [ "$services" = "{}" ] && [ -d /etc/init.d ]; then
        services=$(ls /etc/init.d/ 2>/dev/null | \
            jq -R -s 'split("\n") | map(select(length > 0)) | map({
                (.): {
                    "load": "unknown",
                    "active": "unknown",
                    "sub": "unknown"
                }
            }) | add' 2>/dev/null || echo '{}')
    fi
    
    echo "$services"
}

# Функция получения информации о процессоре (с частотой)
get_cpu_info() {
    local cpu_info="Неизвестно"
    local cpu_cores=0
    local cpu_freq="Неизвестно"
    
    if [ -f /proc/cpuinfo ]; then
        cpu_info=$(grep "model name" /proc/cpuinfo | cut -d':' -f2 | sed -e 's/^[ \t]*//;s/[ \t]*$//' | head -1)
        cpu_cores=$(nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo)
        cpu_freq=$(lscpu 2>/dev/null | grep "CPU max MHz" | awk '{printf "%.2f", $4/1000}')
        [ -z "$cpu_freq" ] && cpu_freq=$(grep "cpu MHz" /proc/cpuinfo | head -1 | awk '{printf "%.2f", $4/1000}')
    fi
    
    echo "{
        \"model\": \"$cpu_info\",
        \"cores\": $cpu_cores,
        \"frequency_ghz\": \"${cpu_freq:-Неизвестно}\"
    }"
}

# Функция получения информации о памяти (в Гб)
get_memory_info() {
    local mem_total_gb="Неизвестно"
    local mem_used_gb="Неизвестно"
    local mem_total_bytes=0
    local mem_used_bytes=0
    
    if command -v free &>/dev/null; then
        mem_total_bytes=$(free -b | grep Mem: | awk '{print $2}')
        mem_used_bytes=$(free -b | grep Mem: | awk '{print $3}')
        mem_total_gb=$(awk "BEGIN {printf \"%.2f\", $mem_total_bytes/1073741824}")
        mem_used_gb=$(awk "BEGIN {printf \"%.2f\", $mem_used_bytes/1073741824}")
    elif [ -f /proc/meminfo ]; then
        mem_total_bytes=$(grep MemTotal /proc/meminfo | awk '{print $2 * 1024}')
        mem_used_bytes=$((mem_total_bytes - $(grep MemAvailable /proc/meminfo | awk '{print $2 * 1024}')))
        mem_total_gb=$(awk "BEGIN {printf \"%.2f\", $mem_total_bytes/1073741824}")
        mem_used_gb=$(awk "BEGIN {printf \"%.2f\", $mem_used_bytes/1073741824}")
    fi
    
    echo "{
        \"total_gb\": $mem_total_gb,
        \"used_gb\": $mem_used_gb
    }"
}

# Функция получения информации о PCI устройствах (компактный формат)
get_pci_devices() {
    if command -v lspci &>/dev/null; then
        lspci 2>/dev/null | awk '{
            $1=$1;
            slot=$1;
            $1="";
            desc=$0;
            sub(/^[ \t]+/, "", desc);
            printf "{\"slot\":\"%s\",\"description\":\"%s\"}\n", slot, desc
        }' | tr -cd '\11\12\15\40-\176' | jq -s . 2>/dev/null || echo '[]'
    else
        echo '[]'
    fi
}

# Функция получения информации о USB устройствах (компактный формат)
get_usb_devices() {
    if command -v lsusb &>/dev/null; then
        lsusb 2>/dev/null | awk '{
            bus=$2;
            dev=$4;
            sub(/:$/, "", dev);
            $1=$2=$3=$4="";
            desc=$0;
            sub(/^[ \t]+/, "", desc);
            printf "{\"bus\":\"%s\",\"device\":\"%s\",\"description\":\"%s\"}\n", bus, dev, desc
        }' | tr -cd '\11\12\15\40-\176' | jq -s . 2>/dev/null || echo '[]'
    else
        echo '[]'
    fi
}

# Функция получения информации о мониторах
get_monitors_info() {
    if [ -d /sys/class/drm ]; then
        for connector in /sys/class/drm/*/status; do
            [ -e "$connector" ] || continue
            status=$(cat "$connector" 2>/dev/null)
            connector_name=$(basename "$(dirname "$connector")")
            [ "$status" = "disconnected" ] && continue
            echo "{
                \"name\": \"$connector_name\",
                \"status\": \"$status\",
                \"type\": \"$(echo "$connector_name" | cut -d'-' -f2-)\"
            }"
        done | tr -cd '\11\12\15\40-\176' | jq -s . 2>/dev/null || echo '[]'
    else
        echo '[]'
    fi
}

# Функция получения информации о принтерах
get_printers_info() {
    if command -v lpstat &>/dev/null; then
        lpstat -v 2>/dev/null | awk '{
            printer=substr($3, 1, length($3)-1);
            device=$4;
            printf "{\"name\":\"%s\",\"device\":\"%s\"}\n", printer, device
        }' | tr -cd '\11\12\15\40-\176' | jq -s . 2>/dev/null || echo '[]'
    else
        echo '[]'
    fi
}

# Функция получения информации о сканерах
get_scanners_info() {
    if command -v scanimage &>/dev/null; then
        scanimage -L 2>/dev/null | awk '{
            device=substr($2, 2, length($2)-2);
            desc=$0;
            sub(/^[^`]*`/, "", desc);
            sub(/\x27 is a .*$/, "", desc);
            printf "{\"device\":\"%s\",\"description\":\"%s\"}\n", device, desc
        }' | tr -cd '\11\12\15\40-\176' | jq -s . 2>/dev/null || echo '[]'
    else
        echo '[]'
    fi
}

# Функция получения информации о температурах
get_temperatures() {
    local temps=()
    local zone type temp
    
    # Получение данных из thermal zones (исправленный блок)
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        [ -f "$zone" ] || continue
        type=$(cat "${zone%/*}/type" 2>/dev/null)
        temp=$(cat "$zone" 2>/dev/null)
        [ -z "$temp" ] && continue
        temp=$((temp/1000))
        temps+=("{\"sensor\":\"$type\",\"temperature\":$temp,\"unit\":\"C\"}")
    done
    
    # Получение данных HDD через hddtemp
    if command -v hddtemp &>/dev/null; then
        hddtemp /dev/sd? 2>/dev/null | while read -r line; do
            device=$(echo "$line" | awk '{print $1}' | sed 's/\/dev\///')
            temp=$(echo "$line" | awk -F':' '{print $3}' | grep -o '[0-9]\+')
            [ -n "$temp" ] && temps+=("{\"sensor\":\"$device\",\"temperature\":$temp,\"unit\":\"C\"}")
        done
    fi
    
    # Получение данных HDD через smartctl
    if command -v smartctl &>/dev/null; then
        for disk in /dev/sd?; do
            temp=$(smartctl -A "$disk" 2>/dev/null | grep -i 'Temperature_Celsius' | awk '{print $10}')
            [ -n "$temp" ] && temps+=("{\"sensor\":\"${disk#/dev/}\",\"temperature\":$temp,\"unit\":\"C\"}")
        done
    fi
    
    # Форматирование результата
    if [ ${#temps[@]} -eq 0 ]; then
        echo '[]'
    else
        printf '%s\n' "${temps[@]}" | tr -cd '\11\12\15\40-\176' | jq -s .
    fi
}

# Функция получения информации о системе
get_system_info() {
    local hostname
    hostname=$(hostname -s 2>/dev/null || echo "неизвестный-хост")
    local mac
    mac=$(ip -o link show 2>/dev/null | awk '/ether/ {print $17; exit}' || echo "00:00:00:00:00:00")
    local ip
    ip=$(get_ip_address)
    
    local serial
    serial=$(get_serial_number)
    local collector_version=$COLLECTOR_VERSION
    local os_info
    
    if [ -f /etc/os-release ]; then
        os_info=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
    elif command -v lsb_release &>/dev/null; then
        os_info=$(lsb_release -d | cut -d':' -f2 | sed 's/^\s*//')
    else
        os_info="Неизвестно"
    fi
    
    cat <<EOF
{   
    "collector_version": "$COLLECTOR_VERSION",    
    "system": {
        "hostname": "$hostname",        
        "os": "$os_info",
        "kernel": "$(uname -r)",
        "uptime": "$(uptime -p | sed 's/^up //')",
        "users": $(who | wc -l),
        "serial_number": "$serial",
        $(get_bios_system_info | sed '1d;$d')
    },
    "user_sessions": $(get_user_sessions),
    "hardware": {
        "cpu": $(get_cpu_info),
        "memory": $(get_memory_info),
        "storage": $(get_disks_info),
        "pci_devices": $(get_pci_devices),
        "usb_devices": $(get_usb_devices),
        "monitors": $(get_monitors_info),
        "printers": $(get_printers_info),
        "scanners": $(get_scanners_info),
        "temperatures": $(get_temperatures)
    },
    "configs": {
        "sudoers_extra": $(get_sudoers_content),
        "hosts_entries": $(get_hosts_content),
        "puppet_conf": $(get_puppet_conf_content)
    },
    "network": {
        "mac_address": "$mac",
        "ip_address": "$ip",
        "network_info": $(get_network_info)
    },
    "filesystem": {
        "directory_structure": $(get_home_directory_structure)
    },    
    "software": {
        "services": $(get_services_info),
        "rpm_packages": $(get_installed_rpms)        
    }
}
EOF
}

# Функция отправки данных на сервер
send_data_to_server() {
    local system_info
    system_info=$(get_system_info | tr -cd '\11\12\15\40-\176')
    local basic_info
    basic_info=$(echo "$system_info" | jq -r '.network')    
    local hostname
    hostname=$(echo "$system_info" | jq -r '.system.hostname')
    local uppercase_hostname
    uppercase_hostname=$(echo "$hostname" | awk '{print toupper($0)}')
    local mac
    mac=$(echo "$basic_info" | jq -r '.mac_address' | tr -d '[:space:]')
    local ip
    ip=$(echo "$basic_info" | jq -r '.ip_address')
    
    # Валидация MAC-адреса
    if [[ ! "$mac" =~ ^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$ ]] && [[ ! "$mac" =~ ^([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})$ ]]; then
        # Альтернативные методы получения MAC
        mac=$(ip -json link show 2>/dev/null | jq -r '.[] | select(.link_type == "ether") | .address' | head -1)
        if [ -z "$mac" ]; then
            mac=$(cat /sys/class/net/$(ip route show default 2>/dev/null | awk '/default/ {print $5}' 2>/dev/null)/address 2>/dev/null)
        fi
        [ -z "$mac" ] && mac="00:00:00:00:00:00"
    fi
    
    [ "$hostname" = "неизвестный-хост" ] && { echo "Ошибка: Не удалось определить имя хоста"; return 1; }
    
    local json_payload=$(cat <<EOF
{
    "hostname": "$uppercase_hostname",
    "mac_address": "$mac",
    "ip_address": "$ip",
    "json_big_info": $system_info
}
EOF
    )

    echo "Отправка данных на сервер..."
    
    for ((i=1; i<=MAX_RETRIES; i++)); do
        echo "Попытка $i/$MAX_RETRIES"
        
        local temp_file
        temp_file=$(mktemp)
        local http_status
        http_status=$(curl -o "$temp_file" -s -w "%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $API_TOKEN" \
            -d "$json_payload" \
            "$SERVER/?api=1")
        
        echo "HTTP статус: $http_status"
        echo "Ответ сервера:"
        cat "$temp_file" | jq . 2>/dev/null || cat "$temp_file"
        echo ""
        
        if [[ "$http_status" =~ ^2[0-9]{2}$ ]]; then
            rm "$temp_file"
            echo "Успешно"
            return 0
        else
            echo "Ошибка HTTP: $http_status"
            [ -f "$temp_file" ] && rm "$temp_file"
            [ $i -lt $MAX_RETRIES ] && sleep $RETRY_DELAY
        fi
    done
    
    echo "Ошибка: Не удалось отправить данные после $MAX_RETRIES попыток"
    return 1
}

# Главный запуск
send_data_to_server