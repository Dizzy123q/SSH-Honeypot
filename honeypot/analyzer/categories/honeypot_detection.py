#!/usr/bin/env python3

import re
from .. import AttackCategory
from ..common import normalize_command

class HoneypotDetectionCategory(AttackCategory): 
    def __init__(self):
        super().__init__("honeypot_detection", "Comenzi folosite pentru a detecta natura de honeypot a sistemului")
        
        # tinem aici comenzile analizate ca sa le refolosim
        self.analyzed_commands = []
    
    # aici avem toate pattern-urile pentru diferite metode de detectare a containerizarii, anomaliilor si artefactelor de honeypot
    PATTERNS = {
        'container_detection': [
            r'docker(\s+.+)?',
            r'lxc-(\w+)',
            r'systemd-detect-virt',
            r'virt-what',
            r'ls\s+-la\s+/.dockerenv',
            r'find\s+/\s+-name\s+\.dockerenv',
            r'cat\s+/proc/1/cgroup',
            r'cat\s+/proc/self/cgroup',
            r'grep\s+docker\s+/proc/\d+/cgroup',
            r'grep\s+docker\s+/proc/self/cgroup',
            r'cat\s+/proc/self/environ',
            r'cat\s+/proc/\d+/environ',
            r'find\s+/\s+-name\s+\.dockerinit',
            r'grep\s+-r\s+docker\s+/proc',
            r'dmesg\s+\|\s+grep\s+(vbox|docker|lxc|kvm|qemu|vm|virt)'
        ],
        'system_anomaly_checks': [
            r'cat\s+/etc/mtab',
            r'df\s+(-[a-zA-Z]+\s+)?',
            r'mount',
            r'fdisk\s+-l',
            r'lsblk',
            r'ps\s+(auxww|aux|ef|efw)',
            r'ps\s+-[a-zA-Z]*',
            r'top\s+(\S+\s+)?',
            r'htop',
            r'lsof',
            r'netstat\s+-[a-zA-Z]+',
            r'ss\s+-[a-zA-Z]+',
            r'lsmod',
            r'modinfo\s+\S+',
            r'systemctl\s+list-(units|unit-files)',
            r'service\s+--status-all',
            r'cat\s+/proc/cpuinfo',
            r'cat\s+/proc/meminfo',
            r'free\s+(-[a-zA-Z]+\s+)?',
            r'lscpu',
            r'dmidecode',
            r'cat\s+/sys/devices/virtual/dmi/id/(board_vendor|sys_vendor|product_name)',
            r'uptime',
            r'last',
            r'lastlog',
            r'who\s+(\S+\s+)?',
            r'w\s+(\S+\s+)?',
            r'history'
        ],
        'artifact_detection': [
            r'ls\s+-la\s+(/usr/local/share/app-data/.config/credentials.txt|/etc/systemd/system.private.d/service-config.yaml|/var/cache/apt-archives/partial/.old/cache.db|/srv/data/.archive/customers_2023.csv|/var/local/backup-history/.system-backup.tar.gz|/usr/local/share/app-data/.ssh_backup|/opt/.maintenance/scripts/services.conf)',
            r'find\s+/\s+-name\s+"honeypot_\w+"',
            r'find\s+/\s+-name\s+"honey\w+"',
            r'find\s+/\s+-name\s+"\.honey\w+"',
            r'find\s+/\s+-name\s+"kippo\w+"',
            r'find\s+/\s+-name\s+"cowrie\w+"',
            r'grep\s+-r\s+"(honeypot|kippo|cowrie)"\s+/',
            r'ls\s+-la\s+(/usr/share/kippo|/usr/share/cowrie|/opt/honeypot)',
            r'cat\s+/etc/hostname',
            r'hostname',
            r'cat\s+/etc/hosts',
            r'ls\s+-la\s+(/var/log/audit)',
            r'cat\s+/etc/machine-id',
            r'ls\s+-la\s+/etc/ssh',
            r'crontab\s+-l',
            r'tail\s+/var/log/auth.log',
            r'ls\s+-la\s+/proc/net',
            r'cat\s+/etc/fstab',
            r'stat\s+/proc/1'
        ],
        'network_checks': [
            r'(ping|nslookup|host|dig|traceroute|tracepath)\s+(\S+\s+)?(-[a-zA-Z]+\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\S+\.\S+)',
            r'curl\s+(-[a-zA-Z]+\s+)?(https?://\S+)',
            r'wget\s+(-[a-zA-Z]+\s+)?(https?://\S+)',
            r'nc\s+(-[a-zA-Z]+\s+)?(\S+)\s+(\d+)',
            r'telnet\s+(\S+)\s+(\d+)',
            r'ssh\s+(-[a-zA-Z]+\s+)?(\S+)',
            r'route(\s+-n)?',
            r'ip\s+(a|addr|address)\s+show',
            r'ip\s+route\s+show',
            r'iptables\s+-L',
            r'tcpdump\s+(-[a-zA-Z]+\s+)?',
            r'ifconfig',
            r'arp\s+(-[a-zA-Z]+\s+)?'
        ],
        'file_system_checks': [
            r'find\s+/\s+-type\s+f\s+-perm\s+\d+\s+-user\s+root',
            r'ls\s+-la\s+/etc',
            r'ls\s+-la\s+/(bin|sbin|usr/bin|usr/sbin)',
            r'find\s+/\s+-type\s+f\s+-name\s+"\.\w+"',
            r'ls\s+-la\s+/var/log',
            r'ls\s+-la\s+/var/www',
            r'ls\s+-la\s+/home',
            r'ls\s+-la\s+/tmp',
            r'ls\s+-la\s+/dev',
            r'ls\s+-la\s+/proc/\d+',
            r'find\s+/proc\s+-name\s+\w+',
            r'find\s+/\s+-name\s+".bash_history"',
            r'find\s+/\s+-name\s+"authorized_keys"',
            r'ls\s+-la\s+/root',
            r'ls\s+-la\s+/root/\.ssh',
            r'ls\s+-la\s+/var/run',
            r'file\s+/bin/\w+'
        ]
    }
    
    def match(self, command):
        # vedem daca comanda se potriveste cu vreo tehnica de detectare honeypot
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    # adaugam comanda la lista analizata daca nu exista deja
                    if command not in self.analyzed_commands:
                        self.analyzed_commands.append(command)
                    return True
        
        return False
    
    def analyze_detection_technique(self, command):
        # incepem cu valorile de baza
        result = {
            'method': 'Unknown',
            'target': 'Unknown',
            'severity': self.get_severity(command),
            'description': ''
        }
        
        # cautam sa vedem ce metoda de detectare e
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    result['method'] = sub_category
                    break
            if result['method'] != 'Unknown':
                break
        
        # analizam specificul metodei de detectare
        if result['method'] == 'container_detection':
            # vedem daca sunt comenzi care verifica containerizarea
            docker_match = re.search(r'(docker|\.dockerenv|cgroup.*docker)', command, re.IGNORECASE)
            if docker_match:
                result['target'] = 'Docker container'
                result['description'] = "Verificare pentru semne de containerizare Docker"
            
            virt_match = re.search(r'(systemd-detect-virt|virt-what|kvm|qemu|vm|virt)', command, re.IGNORECASE)
            if virt_match:
                result['target'] = 'Virtualization environment'
                result['description'] = "Verificare pentru semne de virtualizare"
            
            lxc_match = re.search(r'lxc', command, re.IGNORECASE)
            if lxc_match:
                result['target'] = 'LXC container'
                result['description'] = "Verificare pentru semne de containerizare LXC"
            
            if not result['description']:
                result['description'] = "Verificare generală pentru containerizare"
        
        elif result['method'] == 'system_anomaly_checks':
            # vedem daca sunt comenzi care verifica anomalii de sistem
            process_match = re.search(r'(ps|top|htop)', command, re.IGNORECASE)
            if process_match:
                result['target'] = 'Process listing'
                result['description'] = "Verificare listă procese pentru anomalii"
            
            disk_match = re.search(r'(df|mount|fdisk|lsblk)', command, re.IGNORECASE)
            if disk_match:
                result['target'] = 'Disk/filesystem information'
                result['description'] = "Verificare sistem de fișiere și discuri pentru anomalii"
            
            hardware_match = re.search(r'(cpu|mem|dmi|board)', command, re.IGNORECASE)
            if hardware_match:
                result['target'] = 'Hardware information'
                result['description'] = "Verificare caracteristici hardware pentru anomalii"
            
            if not result['description']:
                result['description'] = "Verificare generală pentru anomalii de sistem"
        
        elif result['method'] == 'artifact_detection':
            # vedem daca sunt comenzi care cauta artefacte de honeypot
            honeypot_match = re.search(r'(honeypot|kippo|cowrie)', command, re.IGNORECASE)
            if honeypot_match:
                result['target'] = 'Honeypot software'
                result['description'] = "Căutare specifică pentru software de honeypot"
            
            trap_file_match = re.search(r'(/usr/local/share/app-data/\.config/credentials\.txt|/etc/systemd/system\.private\.d/service-config\.yaml|/var/cache/apt-archives/partial/\.old/cache\.db|/srv/data/\.archive/customers_2023\.csv|/var/local/backup-history/\.system-backup\.tar\.gz|/usr/local/share/app-data/\.ssh_backup|/opt/\.maintenance/scripts/services\.conf)', command, re.IGNORECASE)
            if trap_file_match:
                result['target'] = trap_file_match.group(1)
                result['description'] = f"Verificare existență fișier capcană {result['target']}"
            
            if not result['description']:
                result['description'] = "Căutare generală pentru artefacte specifice honeypot"
        
        elif result['method'] == 'network_checks':
            # vedem daca sunt comenzi care verifica conexiunile de retea
            conn_match = re.search(r'(ping|nslookup|host|dig|traceroute|tracepath|curl|wget|nc|telnet|ssh)\s+(\S+)', command, re.IGNORECASE)
            if conn_match:
                cmd = conn_match.group(1)
                target = conn_match.group(2)
                result['target'] = f"{cmd} to {target}"
                result['description'] = f"Verificare conectivitate rețea cu {cmd} către {target}"
            
            interface_match = re.search(r'(ifconfig|ip addr|ip address)', command, re.IGNORECASE)
            if interface_match:
                result['target'] = 'Network interfaces'
                result['description'] = "Verificare configurație interfețe rețea"
            
            if not result['description']:
                result['description'] = "Verificare generală pentru funcționalitatea rețelei"
        
        elif result['method'] == 'file_system_checks':
            # vedem daca sunt comenzi care exploreaza sistemul de fisiere
            path_match = re.search(r'(ls|find)\s+(\S+)', command, re.IGNORECASE)
            if path_match:
                cmd = path_match.group(1)
                path = path_match.group(2)
                result['target'] = path
                result['description'] = f"Explorare sistem fișiere la calea {path}"
            
            if not result['description']:
                result['description'] = "Explorare generală a sistemului de fișiere"
        
        # daca nu am reusit sa determinam detalii specifice, oferim o descriere generala
        if result['description'] == '':
            result['description'] = f"Posibilă încercare de detectare honeypot folosind metoda {result['method']}"
        
        # calculam un scor de incredere bazat pe cat de precisa este potrivirea
        confidence = 0.6  # scor implicit
        
        # daca avem o tinta specifica si o metoda clara, avem mai multa incredere
        if result['target'] != 'Unknown' and result['method'] != 'Unknown':
            confidence = 0.8
        elif result['method'] != 'Unknown':
            confidence = 0.7
        
        result['confidence'] = confidence
        
        return result
    
    def get_container_detection_attempts(self):
        return self._filter_commands_by_subcategory('container_detection')
    
    def get_system_anomaly_checks(self):
        return self._filter_commands_by_subcategory('system_anomaly_checks')
    
    def get_artifact_detection_attempts(self):
        return self._filter_commands_by_subcategory('artifact_detection')
    
    def _filter_commands_by_subcategory(self, subcategory):
        filtered_commands = []
        
        # verificam daca subcategoria exista
        if subcategory not in self.PATTERNS:
            return filtered_commands
        
        # luam pattern-urile pentru subcategorie
        patterns = self.PATTERNS[subcategory]
        
        # filtram comenzile
        for command in self.analyzed_commands:
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    filtered_commands.append(command)
                    break
        
        return filtered_commands
    
    def get_severity(self, command):
        # comenzile de detectare honeypot au severitate variabila in functie de specificitate
        
        # severitate implicita
        severity = 3
        
        # pattern-uri foarte specifice pentru detectare honeypot (7-9)
        specific_patterns = [
            r'systemd-detect-virt',
            r'virt-what',
            r'find\s+/\s+-name\s+\.dockerenv',
            r'cat\s+/proc/1/cgroup',
            r'grep\s+docker\s+/proc/\d+/cgroup',
            r'dmesg\s+\|\s+grep\s+(vbox|docker|lxc|kvm|qemu|vm|virt)',
            r'find\s+/\s+-name\s+"honeypot_\w+"',
            r'find\s+/\s+-name\s+"honey\w+"',
            r'find\s+/\s+-name\s+"kippo\w+"',
            r'find\s+/\s+-name\s+"cowrie\w+"',
            r'grep\s+-r\s+"(honeypot|kippo|cowrie)"\s+/',
            r'ls\s+-la\s+(/usr/share/kippo|/usr/share/cowrie|/opt/honeypot)',
            r'ls\s+-la\s+(/usr/local/share/app-data/.config/credentials.txt|/etc/systemd/system.private.d/service-config.yaml|/var/cache/apt-archives/partial/.old/cache.db|/srv/data/.archive/customers_2023.csv|/var/local/backup-history/.system-backup.tar.gz|/usr/local/share/app-data/.ssh_backup|/opt/.maintenance/scripts/services.conf)'
        ]
        
        # verificam pattern-urile foarte specifice
        for pattern in specific_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # avansati (poate automat) care cauta specific honeypot-uri
                return 8  # severitate mare
        
        # pattern-uri moderat specifice (4-6)
        moderate_patterns = [
            r'docker(\s+.+)?',
            r'lxc-(\w+)',
            r'cat\s+/proc/self/environ',
            r'cat\s+/proc/\d+/environ',
            r'find\s+/\s+-name\s+\.dockerinit',
            r'dmidecode',
            r'cat\s+/sys/devices/virtual/dmi/id/(board_vendor|sys_vendor|product_name)',
            r'ss\s+-[a-zA-Z]+',
            r'lscpu',
            r'cat\s+/etc/machine-id',
            r'stat\s+/proc/1',
            r'find\s+/proc\s+-name\s+\w+'
        ]
        
        # verificam pattern-urile moderat specifice
        for pattern in moderate_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # incercari moderate de a detecta un mediu neobisnuit
                return 5  # severitate medie
        
        # pattern-uri comune, mai putin specifice (1-3)
        common_patterns = [
            r'ps\s+(auxww|aux|ef|efw)',
            r'top\s+(\S+\s+)?',
            r'netstat\s+-[a-zA-Z]+',
            r'cat\s+/proc/cpuinfo',
            r'cat\s+/proc/meminfo',
            r'free\s+(-[a-zA-Z]+\s+)?',
            r'df\s+(-[a-zA-Z]+\s+)?',
            r'mount',
            r'uptime',
            r'uname\s+-[a-zA-Z]+',
            r'hostname',
            r'cat\s+/etc/hosts',
            r'ifconfig',
            r'ip\s+(a|addr|address)\s+show'
        ]
        
        # verificam pattern-urile comune
        for pattern in common_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # comenzi obisnuite care pot fi folosite pentru detectare, dar sunt mai putin specifice
                return 3  # severitate scazuta
        
        return severity