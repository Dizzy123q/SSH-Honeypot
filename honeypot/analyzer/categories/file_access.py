#!/usr/bin/env python3

import re
from .. import AttackCategory
from ..common import normalize_command

class FileAccessCategory(AttackCategory):
  
    def __init__(self):
        super().__init__("file_access", "Comenzi folosite pentru accesarea fișierelor capcană și sensibile")
        
        # tinem aici comenzile analizate ca sa le refolosim
        self.analyzed_commands = []
    
    # toate pattern-urile pentru diferite tipuri de accesari de fisiere
    PATTERNS = {
        'trap_files': [
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/usr/local/share/app-data/.config/credentials.txt)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/systemd/system.private.d/service-config.yaml)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/var/cache/apt-archives/partial/.old/cache.db)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/srv/data/.archive/customers_2023.csv)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/var/local/backup-history/.system-backup.tar.gz)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/usr/local/share/app-data/.ssh_backup)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/opt/.maintenance/scripts/services.conf)'
        ],
        'credentials_files': [
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*password.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*credential.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.htpasswd)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.netrc)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*id_rsa)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.ssh/authorized_keys)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.ssh/id_.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/shadow)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/passwd)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/gshadow)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/ssh/ssh_host.*key)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.key)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.pem)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.crt)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*auth\.log)'
        ],
        'config_files': [
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.conf$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.config$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.cfg$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.ini$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.env$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.properties$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.xml$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.yml$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.yaml$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.json$)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/.*\.conf)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/ssh/sshd_config)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/.*\.d/.*\.conf)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/sudoers)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/hosts)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/resolv.conf)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/fstab)'
        ],
        'user_data_files': [
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.csv)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.xlsx?)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.db)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.sqlite)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.bak)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*backup.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.log)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.sql)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.dump)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*customer.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*user.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*client.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*account.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.tar\.gz)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.zip)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.tgz)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(.*\.history)'
        ],
        'system_files': [
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/proc/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/sys/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/dev/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/var/log/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/cron.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/rc.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/init.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/lib/systemd/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/systemd/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/boot/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/ld.so.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/security/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/pam.d/.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/profile.*)',
            r'(cat|less|more|vim|vi|nano|head|tail|grep)\s+(/etc/bash.*)'
        ]
    }
    
    def match(self, command):
        # vedem daca comanda se potriveste cu vreo tehnica de acces fisiere
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    # adaugam comanda la lista analizata daca nu exista deja
                    if command not in self.analyzed_commands:
                        self.analyzed_commands.append(command)
                    return True
        
        return False
    
    def analyze_file_access(self, command):
        # incepem cu valorile de baza
        result = {
            'method': 'Unknown',
            'file_path': 'Unknown',
            'access_type': 'Unknown',
            'severity': self.get_severity(command),
            'description': ''
        }
        
        # cautam sa vedem ce categoria de fisier e
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, command, re.IGNORECASE)
                if match:
                    result['method'] = sub_category
                    
                    # extragem tipul de acces si calea
                    if len(match.groups()) >= 2:
                        access_command = match.group(1)
                        file_path = match.group(2)
                        
                        result['file_path'] = file_path
                        
                        # determinam tipul de acces
                        read_commands = ['cat', 'less', 'more', 'head', 'tail', 'grep']
                        edit_commands = ['vim', 'vi', 'nano', 'gedit', 'emacs']
                        
                        if access_command in read_commands:
                            result['access_type'] = 'read'
                        elif access_command in edit_commands:
                            result['access_type'] = 'edit'
                        else:
                            result['access_type'] = 'unknown'
                    
                    break
            if result['method'] != 'Unknown':
                break
        
        # analizam specificul accesului
        if result['method'] == 'trap_files':
            # verificare pentru fisier capcana specific
            trap_file_descriptions = {
                '/usr/local/share/app-data/.config/credentials.txt': 'Fișier capcană cu credențiale false',
                '/etc/systemd/system.private.d/service-config.yaml': 'Fișier capcană cu configurație serviciu',
                '/var/cache/apt-archives/partial/.old/cache.db': 'Fișier capcană cu cache bază de date',
                '/srv/data/.archive/customers_2023.csv': 'Fișier capcană cu date clienți false',
                '/var/local/backup-history/.system-backup.tar.gz': 'Fișier capcană cu backup fals',
                '/usr/local/share/app-data/.ssh_backup': 'Fișier capcană cu backup SSH fals',
                '/opt/.maintenance/scripts/services.conf': 'Fișier capcană cu configurație servicii'
            }
            
            if result['file_path'] in trap_file_descriptions:
                result['description'] = trap_file_descriptions[result['file_path']]
                if result['access_type'] == 'read':
                    result['description'] += " - acces citire"
                elif result['access_type'] == 'edit':
                    result['description'] += " - acces editare"
            else:
                result['description'] = f"Acces la fișier capcană: {result['file_path']}"
        
        elif result['method'] == 'credentials_files':
            if '/etc/shadow' in result['file_path']:
                result['description'] = "Acces la fișierul shadow cu hash-uri parole"
            elif '/etc/passwd' in result['file_path']:
                result['description'] = "Acces la fișierul passwd cu informații utilizatori"
            elif 'authorized_keys' in result['file_path']:
                result['description'] = "Acces la fișierul de chei SSH autorizate"
            elif 'id_rsa' in result['file_path'] or '.ssh/id_' in result['file_path']:
                result['description'] = "Acces la chei SSH private"
            elif '.pem' in result['file_path'] or '.key' in result['file_path'] or '.crt' in result['file_path']:
                result['description'] = "Acces la certificate sau chei de criptare"
            else:
                result['description'] = f"Acces la fișier cu potențiale credențiale: {result['file_path']}"
        
        elif result['method'] == 'config_files':
            if '/etc/ssh/sshd_config' in result['file_path']:
                result['description'] = "Acces la configurația serverului SSH"
            elif '/etc/sudoers' in result['file_path']:
                result['description'] = "Acces la configurația sudo"
            elif '.env' in result['file_path']:
                result['description'] = "Acces la fișier environment cu potențiale secrete"
            else:
                result['description'] = f"Acces la fișier de configurare: {result['file_path']}"
        
        elif result['method'] == 'user_data_files':
            if '.csv' in result['file_path'] or '.xls' in result['file_path']:
                result['description'] = "Acces la fișier cu date structurate (potențial date utilizator)"
            elif '.db' in result['file_path'] or '.sqlite' in result['file_path'] or '.sql' in result['file_path']:
                result['description'] = "Acces la fișier bază de date"
            elif '.bak' in result['file_path'] or 'backup' in result['file_path'] or '.tar.gz' in result['file_path'] or '.zip' in result['file_path']:
                result['description'] = "Acces la fișier de backup"
            else:
                result['description'] = f"Acces la fișier cu date utilizator: {result['file_path']}"
        
        elif result['method'] == 'system_files':
            if '/proc/' in result['file_path']:
                result['description'] = "Acces la fișier informații sistem din /proc"
            elif '/var/log/' in result['file_path']:
                result['description'] = "Acces la fișier log sistem"
            elif '/etc/cron' in result['file_path']:
                result['description'] = "Acces la configurație cron job"
            else:
                result['description'] = f"Acces la fișier sistem: {result['file_path']}"
        
        # daca nu am reusit sa determinam detalii specifice, oferim o descriere generala
        if result['description'] == '':
            result['description'] = f"Acces la fișier sensibil: {result['file_path']}"
            if result['access_type'] != 'Unknown':
                result['description'] += f", tip acces: {result['access_type']}"
        
        # calculam un scor de incredere bazat pe cat de precisa este potrivirea
        confidence = 0.7  # scor implicit
        
        # daca avem o cale specifica si un tip de acces clar, avem mai multa incredere
        if result['file_path'] != 'Unknown' and result['access_type'] != 'Unknown':
            confidence = 0.9
        elif result['file_path'] != 'Unknown':
            confidence = 0.8
        
        result['confidence'] = confidence
        
        return result
    
    def get_sensitive_file_access(self):
        sensitive_files = []
        
        # combinam fisierele capcana si cele cu credentiale
        sensitive_files.extend(self._filter_commands_by_subcategory('trap_files'))
        sensitive_files.extend(self._filter_commands_by_subcategory('credentials_files'))
        
        # eliminam duplicatele
        return list(set(sensitive_files))
    
    def get_configuration_file_access(self):
        return self._filter_commands_by_subcategory('config_files')
    
    def get_user_data_access(self):
        return self._filter_commands_by_subcategory('user_data_files')
    
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
        # severitate implicita pentru acces fisiere
        severity = 6
        
        # pattern-uri critice (fisiere cu informatii extrem de sensibile) (9-10)
        critical_patterns = [
            r'cat\s+/etc/shadow',
            r'cat\s+/etc/gshadow',
            r'cat\s+.*\.ssh/id_rsa',
            r'cat\s+/etc/ssh/ssh_host.*key',
            r'cat\s+.*\.pem',
            r'cat\s+.*\.(key|crt)',
            r'cat\s+/etc/sudoers',
            r'cat\s+/usr/local/share/app-data/\.config/credentials\.txt',
            r'cat\s+/usr/local/share/app-data/\.ssh_backup',
            r'cat\s+/var/cache/apt-archives/partial/\.old/cache\.db',
            r'cat\s+/srv/data/\.archive/customers_2023\.csv',
            r'cat\s+.*password.*',
            r'cat\s+.*credential.*',
            r'cat\s+.*\.env',
            r'vim\s+/etc/shadow',
            r'vim\s+/etc/ssh/ssh_host.*key'
        ]
        
        # verificam pattern-urile critice
        for pattern in critical_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # acces la fisiere cu informatii extrem de sensibile
                return 10  # severitate maxima
        
        # pattern-uri cu severitate mare (7-8)
        high_patterns = [
            r'cat\s+/etc/passwd',
            r'cat\s+/etc/ssh/sshd_config',
            r'cat\s+.*\.netrc',
            r'cat\s+.*\.htpasswd',
            r'cat\s+.*\.ssh/authorized_keys',
            r'cat\s+.*config\.yaml',
            r'cat\s+.*\.conf',
            r'cat\s+/etc/systemd/system\.private\.d/service-config\.yaml',
            r'cat\s+/opt/\.maintenance/scripts/services\.conf',
            r'cat\s+/etc/cron',
            r'cat\s+/etc/rc\.',
            r'cat\s+/var/local/backup-history/\.system-backup\.tar\.gz',
            r'cat\s+/var/log/auth\.log',
            r'vim\s+/etc/passwd',
            r'vim\s+/etc/ssh/sshd_config',
            r'vim\s+.*\.ssh/authorized_keys'
        ]
        
        # verificam pattern-urile cu severitate mare
        for pattern in high_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # acces la fisiere importante pentru configuratia sistemului
                return 8
        
        # pattern-uri cu severitate medie (5-6)
        medium_patterns = [
            r'cat\s+/proc/',
            r'cat\s+/sys/',
            r'cat\s+/etc/hosts',
            r'cat\s+/etc/resolv\.conf',
            r'cat\s+/etc/fstab',
            r'cat\s+/etc/profile',
            r'cat\s+/var/log/',
            r'cat\s+.*\.log',
            r'cat\s+.*\.xml',
            r'cat\s+.*\.json',
            r'cat\s+.*\.db',
            r'cat\s+.*\.bak',
            r'cat\s+.*\.csv'
        ]
        
        # verificam pattern-urile cu severitate medie
        for pattern in medium_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # acces la fisiere cu date mai putin sensibile sau fisiere de configurare standard
                return 6
        
        # pattern-uri cu severitate scazuta (3-4)
        low_patterns = [
            r'cat\s+/etc/motd',
            r'cat\s+/etc/issue',
            r'cat\s+/proc/version',
            r'cat\s+/proc/cpuinfo',
            r'cat\s+/proc/meminfo',
            r'cat\s+/etc/hostname',
            r'cat\s+/etc/timezone'
        ]
        
        # verificam pattern-urile cu severitate scazuta
        for pattern in low_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # acces la fisiere informative standard, fara date sensibile
                return 4
        
        return severity