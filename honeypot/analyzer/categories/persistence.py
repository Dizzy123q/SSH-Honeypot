#!/usr/bin/env python3
import re
from .. import AttackCategory
from ..common import normalize_command

class PersistenceCategory(AttackCategory):
    def __init__(self):
        super().__init__("persistence", "comenzi folosite ca sa ramana pe sistem")
        
        # pastram comenzile pe care le-am vazut ca sa le refolosim
        self.analyzed_commands = []
    
    # patterns-uri regex pentru diferite metode de a ramane pe sistem
    PATTERNS = {
        'cron_jobs': [
            r'crontab\s+(-[a-zA-Z]+\s+)?(-e|-l)',
            r'echo\s+.*\s*>>\s*(/etc/crontab|/var/spool/cron/\S+|/etc/cron\.(d|daily|hourly|monthly|weekly)/\S+)',
            r'cat\s+>\s*(/etc/crontab|/var/spool/cron/\S+|/etc/cron\.(d|daily|hourly|monthly|weekly)/\S+)',
            r'(cp|mv)\s+\S+\s+(/etc/cron\.(d|daily|hourly|monthly|weekly)/\S+)',
            r'system-config-date\s+--set-cron',
            r'touch\s+(/etc/cron\.(d|daily|hourly|monthly|weekly)/\S+)',
            r'nano\s+(/etc/crontab|/var/spool/cron/\S+|/etc/cron\.(d|daily|hourly|monthly|weekly)/\S+)',
            r'vi\s+(/etc/crontab|/var/spool/cron/\S+|/etc/cron\.(d|daily|hourly|monthly|weekly)/\S+)',
            r'vim\s+(/etc/crontab|/var/spool/cron/\S+|/etc/cron\.(d|daily|hourly|monthly|weekly)/\S+)',
            r'at\s+\d{1,2}:\d{1,2}',
            r'batch\s+\d{1,2}:\d{1,2}'
        ],
        'service_creation': [
            r'systemctl\s+(enable|start|status|stop)\s+\S+',
            r'service\s+\S+\s+(start|stop|status|enable|disable)',
            r'chkconfig\s+\S+\s+(on|off)',
            r'update-rc\.d\s+\S+\s+(defaults|enable|disable)',
            r'echo\s+.*\s*>\s*(/etc/systemd/system/\S+\.service|/lib/systemd/system/\S+\.service|/usr/lib/systemd/system/\S+\.service)',
            r'cat\s+>\s*(/etc/systemd/system/\S+\.service|/lib/systemd/system/\S+\.service|/usr/lib/systemd/system/\S+\.service)',
            r'(cp|mv)\s+\S+\s+(/etc/systemd/system/\S+\.service|/lib/systemd/system/\S+\.service|/usr/lib/systemd/system/\S+\.service)',
            r'systemctl\s+daemon-reload',
            r'init\.d\s+\S+\s+(start|stop|restart|status)',
            r'/etc/init\.d/\S+\s+(start|stop|restart|status)',
            r'nano\s+(/etc/systemd/system/\S+\.service|/lib/systemd/system/\S+\.service|/usr/lib/systemd/system/\S+\.service)',
            r'vi\s+(/etc/systemd/system/\S+\.service|/lib/systemd/system/\S+\.service|/usr/lib/systemd/system/\S+\.service)',
            r'vim\s+(/etc/systemd/system/\S+\.service|/lib/systemd/system/\S+\.service|/usr/lib/systemd/system/\S+\.service)'
        ],
        'startup_scripts': [
            r'echo\s+.*\s*>>\s*/etc/rc\.local',
            r'echo\s+.*\s*>>\s*/etc/rc\.(d|S|K)/\S+',
            r'cat\s+>\s*/etc/rc\.local',
            r'(cp|mv)\s+\S+\s+/etc/rc\.(d|S|K)/\S+',
            r'chmod\s+\+x\s+/etc/rc\.local',
            r'chmod\s+\+x\s+/etc/rc\.(d|S|K)/\S+',
            r'nano\s+/etc/rc\.local',
            r'vi\s+/etc/rc\.local',
            r'vim\s+/etc/rc\.local'
        ],
        'profile_modification': [
            r'echo\s+.*\s*>>\s*(/etc/profile|/etc/bash\.bashrc|/etc/zsh/zshrc|/etc/environment)',
            r'echo\s+.*\s*>>\s*(/root/\.(bashrc|bash_profile|profile|zshrc)|/home/\S+/\.(bashrc|bash_profile|profile|zshrc))',
            r'cat\s+>\s*(/etc/profile|/etc/bash\.bashrc|/etc/zsh/zshrc|/etc/environment)',
            r'cat\s+>\s*(/root/\.(bashrc|bash_profile|profile|zshrc)|/home/\S+/\.(bashrc|bash_profile|profile|zshrc))',
            r'nano\s+(/etc/profile|/etc/bash\.bashrc|/etc/zsh/zshrc|/etc/environment)',
            r'nano\s+(/root/\.(bashrc|bash_profile|profile|zshrc)|/home/\S+/\.(bashrc|bash_profile|profile|zshrc))',
            r'vi\s+(/etc/profile|/etc/bash\.bashrc|/etc/zsh/zshrc|/etc/environment)',
            r'vi\s+(/root/\.(bashrc|bash_profile|profile|zshrc)|/home/\S+/\.(bashrc|bash_profile|profile|zshrc))',
            r'vim\s+(/etc/profile|/etc/bash\.bashrc|/etc/zsh/zshrc|/etc/environment)',
            r'vim\s+(/root/\.(bashrc|bash_profile|profile|zshrc)|/home/\S+/\.(bashrc|bash_profile|profile|zshrc))'
        ],
        'ssh_keys': [
            r'echo\s+.*\s*>>\s*(/root/\.ssh/authorized_keys|/home/\S+/\.ssh/authorized_keys)',
            r'cat\s+>\s*(/root/\.ssh/authorized_keys|/home/\S+/\.ssh/authorized_keys)',
            r'(cp|mv)\s+\S+\s+(/root/\.ssh/authorized_keys|/home/\S+/\.ssh/authorized_keys)',
            r'ssh-keygen\s+.*',
            r'mkdir\s+-p\s+\S*/\.ssh',
            r'cat\s+\S*/\.ssh/id_rsa\.pub\s+>>\s*\S*/\.ssh/authorized_keys',
            r'cat\s+>>\s*/\.ssh/authorized_keys',
            r'chmod\s+[0-7]*\s+\S*/\.ssh/authorized_keys',
            r'nano\s+(/root/\.ssh/authorized_keys|/home/\S+/\.ssh/authorized_keys)',
            r'vi\s+(/root/\.ssh/authorized_keys|/home/\S+/\.ssh/authorized_keys)',
            r'vim\s+(/root/\.ssh/authorized_keys|/home/\S+/\.ssh/authorized_keys)'
        ],
        'backdoor_shells': [
            r'nc\s+-[a-zA-Z]*\s*-?[a-zA-Z]*e\s+.*/bin/(sh|bash)',
            r'ncat\s+.*\s+-e\s+.*/bin/(sh|bash)',
            r'socat\s+.*\s+exec:.*/bin/(sh|bash)',
            r'perl\s+-e\s+.*socket.*open.*exec.*sh',
            r'python(\d)?\s+-c\s+.*socket.*subprocess',
            r'php\s+-r\s+.*fsockopen.*exec.*sh',
            r'ruby\s+-e\s+.*socket.*open.*exec.*sh',
            r'lua\s+-e\s+.*socket.*os\.execute.*sh',
            r'openssl\s+s_client.*\|\s*sh',
            r'mkfifo\s+.*\|\s*sh',
            r'/bin/(bash|sh)\s+-i',
            r'telnetd\s+.*',
            r'bash\s+-c\s+.*\{.*bash.*>&.*\}',
            r'stty\s+raw\s+-echo'
        ],
        'webshells': [
            r'echo\s+.*\s*>\s*(/var/www/\S+\.php|/var/www/html/\S+\.php)',
            r'cat\s+>\s*(/var/www/\S+\.php|/var/www/html/\S+\.php)',
            r'(cp|mv)\s+\S+\s+(/var/www/\S+\.php|/var/www/html/\S+\.php)',
            r'touch\s+(/var/www/\S+\.php|/var/www/html/\S+\.php)',
            r'nano\s+(/var/www/\S+\.php|/var/www/html/\S+\.php)',
            r'vi\s+(/var/www/\S+\.php|/var/www/html/\S+\.php)',
            r'vim\s+(/var/www/\S+\.php|/var/www/html/\S+\.php)',
            r'echo\s+.*passthru.*REQUEST.*\s*>\s*.*\.php',
            r'echo\s+.*shell_exec.*REQUEST.*\s*>\s*.*\.php',
            r'echo\s+.*eval.*REQUEST.*\s*>\s*.*\.php',
            r'echo\s+.*exec.*REQUEST.*\s*>\s*.*\.php'
        ],
        'kernel_modules': [
            r'insmod\s+\S+',
            r'modprobe\s+\S+',
            r'lsmod',
            r'rmmod\s+\S+',
            r'modinfo\s+\S+',
            r'echo\s+.*\s*>\s*/etc/modules-load\.d/\S+\.conf',
            r'cat\s+>\s*/etc/modules-load\.d/\S+\.conf',
            r'(cp|mv)\s+\S+\s+/etc/modules-load\.d/\S+\.conf',
            r'nano\s+/etc/modules-load\.d/\S+\.conf',
            r'vi\s+/etc/modules-load\.d/\S+\.conf',
            r'vim\s+/etc/modules-load\.d/\S+\.conf'
        ]
    }
    
    def match(self, command):
        # verificam daca comanda se potriveste cu vreun pattern de persistenta
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    # adaugam comanda la lista daca nu e deja acolo
                    if command not in self.analyzed_commands:
                        self.analyzed_commands.append(command)
                    return True
        
        return False
    
    def analyze_persistence_mechanism(self, command):
        # setam valorile de start
        result = {
            'method': 'Unknown',
            'target': 'Unknown',
            'severity': self.get_severity(command),
            'description': ''
        }
        
        # vedem ce metoda de persistenta se foloseste
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    result['method'] = sub_category
                    break
            if result['method'] != 'Unknown':
                break
        
        # vedem care e tinta mecanismului de persistenta
        if result['method'] == 'cron_jobs':
            # cautam editare sau modificare fisiere cron
            cron_file_match = re.search(r'(crontab\s+-e|echo\s+.*>\s*(/etc/crontab|/var/spool/cron/\S+|/etc/cron\.[^/]+/\S+))', command)
            if cron_file_match:
                if 'crontab -e' in command:
                    result['target'] = 'user crontab'
                    result['description'] = "editeaza crontab-ul utilizatorului pentru task-uri programate"
                else:
                    result['target'] = cron_file_match.group(2) if cron_file_match.group(2) else 'cron file'
                    result['description'] = f"modifica fisierul cron {result['target']} pentru task-uri programate"
        
        elif result['method'] == 'service_creation':
            # cautam creare sau activare serviciu
            service_match = re.search(r'(systemctl\s+(enable|start)\s+(\S+)|echo\s+.*>\s*(/etc/systemd/system/(\S+)\.service|/lib/systemd/system/(\S+)\.service|/usr/lib/systemd/system/(\S+)\.service))', command)
            if service_match:
                if service_match.group(3):
                    result['target'] = service_match.group(3)
                elif service_match.group(5):
                    result['target'] = service_match.group(5)
                elif service_match.group(6):
                    result['target'] = service_match.group(6)
                elif service_match.group(7):
                    result['target'] = service_match.group(7)
                else:
                    result['target'] = 'systemd service'
                    
                result['description'] = f"creeaza sau activeaza serviciul {result['target']} pentru persistenta"
        
        elif result['method'] == 'startup_scripts':
            # cautam modificare script-uri de startup
            startup_match = re.search(r'(echo\s+.*>\s*/etc/rc\.local|echo\s+.*>\s*/etc/rc\.[^/]+/(\S+))', command)
            if startup_match:
                if startup_match.group(2):
                    result['target'] = startup_match.group(2)
                else:
                    result['target'] = 'rc.local'
                    
                result['description'] = f"modifica script-ul de startup {result['target']} ca sa ruleze la pornirea sistemului"
        
        elif result['method'] == 'profile_modification':
            # cautam modificare fisiere profil shell
            profile_match = re.search(r'(echo\s+.*>\s*(/etc/profile|/etc/bash\.bashrc|/etc/zsh/zshrc|/etc/environment|/root/\.bashrc|/home/(\S+)/\.bashrc))', command)
            if profile_match:
                if profile_match.group(3):
                    result['target'] = f"user {profile_match.group(3)}"
                else:
                    result['target'] = profile_match.group(2)
                    
                result['description'] = f"modifica profilul {result['target']} ca sa ruleze la login"
        
        elif result['method'] == 'ssh_keys':
            # cautam manipulare chei ssh
            ssh_match = re.search(r'(echo\s+.*>\s*(/root/\.ssh/authorized_keys|/home/(\S+)/\.ssh/authorized_keys))', command)
            if ssh_match:
                if ssh_match.group(3):
                    result['target'] = f"user {ssh_match.group(3)}"
                else:
                    result['target'] = 'root'
                    
                result['description'] = f"adauga cheie ssh pentru acces permanent la contul {result['target']}"
        
        elif result['method'] == 'backdoor_shells':
            # cautam instalare backdoor shell
            if 'nc' in command or 'ncat' in command:
                port_match = re.search(r'(nc|ncat)\s+.*\s+(\d+)', command)
                if port_match:
                    result['target'] = f"port {port_match.group(2)}"
                    result['description'] = f"instaleaza backdoor netcat pe {result['target']}"
            elif 'socat' in command:
                port_match = re.search(r'socat\s+.*:(\d+)', command)
                if port_match:
                    result['target'] = f"port {port_match.group(1)}"
                    result['description'] = f"instaleaza backdoor socat pe {result['target']}"
            else:
                result['description'] = "instaleaza backdoor pentru acces la shell"
        
        elif result['method'] == 'webshells':
            # cautam instalare webshell
            webshell_match = re.search(r'(echo\s+.*>\s*(/var/www/(\S+)\.php|/var/www/html/(\S+)\.php))', command)
            if webshell_match:
                if webshell_match.group(3):
                    result['target'] = webshell_match.group(3) + ".php"
                elif webshell_match.group(4):
                    result['target'] = webshell_match.group(4) + ".php"
                else:
                    result['target'] = 'PHP file'
                    
                result['description'] = f"instaleaza webshell {result['target']} pentru acces web persistent"
        
        elif result['method'] == 'kernel_modules':
            # cautam manipulare module kernel
            module_match = re.search(r'(insmod|modprobe)\s+(\S+)', command)
            if module_match:
                result['target'] = module_match.group(2)
                result['description'] = f"incarca modulul kernel {result['target']} pentru posibila persistenta la nivel kernel"
        
        # daca nu am gasit detalii specifice, dam o descriere generala
        if result['description'] == '':
            result['description'] = f"posibila instalare mecanism de persistenta folosind metoda {result['method']}"
        
        # calculam cat de siguri suntem de rezultat
        confidence = 0.7  # valoare de start
        
        # daca avem o tinta specifica si o metoda clara, suntem mai siguri
        if result['target'] != 'Unknown' and result['method'] != 'Unknown':
            confidence = 0.9
        elif result['method'] != 'Unknown':
            confidence = 0.8
        
        result['confidence'] = confidence
        
        return result
    
    def get_cron_job_attempts(self):
        return self._filter_commands_by_subcategory('cron_jobs')
    
    def get_service_creation_attempts(self):
        return self._filter_commands_by_subcategory('service_creation')
    
    def get_startup_modification_attempts(self):
        # combinam mai multe categorii pentru modificari startup
        startup_commands = []
        
        startup_commands.extend(self._filter_commands_by_subcategory('startup_scripts'))
        startup_commands.extend(self._filter_commands_by_subcategory('profile_modification'))
        
        # scoatem duplicatele
        return list(set(startup_commands))
    
    def get_backdoor_installation_attempts(self):

        # combinam mai multe categorii pentru backdoor-uri
        backdoor_commands = []
        
        backdoor_commands.extend(self._filter_commands_by_subcategory('backdoor_shells'))
        backdoor_commands.extend(self._filter_commands_by_subcategory('webshells'))
        backdoor_commands.extend(self._filter_commands_by_subcategory('ssh_keys'))
        
        # scoatem duplicatele
        return list(set(backdoor_commands))
    
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
        # comenzile de persistenta au in general severitate mare
        
        # severitate de baza
        severity = 8
        
        # patterns cu severitate critica (9-10)
        critical_patterns = [
            r'echo\s+.*nc\s+.*>\s*/etc/rc\.local',
            r'echo\s+.*bash\s+-i.*>\s*/etc/rc\.local',
            r'echo\s+.*>\s*/root/\.ssh/authorized_keys',
            r'echo\s+.*>\s*/home/\S+/\.ssh/authorized_keys',
            r'echo\s+.*passthru.*REQUEST.*\s*>\s*.*\.php',
            r'echo\s+.*shell_exec.*REQUEST.*\s*>\s*.*\.php',
            r'echo\s+.*eval.*REQUEST.*\s*>\s*.*\.php',
            r'echo\s+.*exec.*REQUEST.*\s*>\s*.*\.php',
            r'cat\s+>\s*/etc/systemd/system/\S+\.service',
            r'nc\s+-[a-zA-Z]*\s*-?[a-zA-Z]*e\s+.*/bin/(sh|bash)',
            r'ncat\s+.*\s+-e\s+.*/bin/(sh|bash)',
            r'echo\s+.*\s*>>\s*/etc/sudoers',
            r'echo\s+.*\|\s*crontab',
            r'insmod\s+\S+\.ko'
        ]
        
        # verificam patterns-urile critice (mecanisme foarte ascunse sau la nivel de sistem)
        for pattern in critical_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 10  # severitate maxima pentru mecanisme critice de persistenta
        
        # patterns cu severitate mare (8-9)
        high_patterns = [
            r'crontab\s+-e',
            r'echo\s+.*>\s*/etc/crontab',
            r'echo\s+.*>\s*/var/spool/cron/\S+',
            r'systemctl\s+enable\s+\S+',
            r'update-rc\.d\s+\S+\s+defaults',
            r'echo\s+.*>\s*/etc/profile',
            r'echo\s+.*>\s*/etc/bash\.bashrc',
            r'echo\s+.*>\s*/root/\.bashrc',
            r'echo\s+.*>\s*/home/\S+/\.bashrc',
            r'socat\s+.*\s+exec:.*/bin/(sh|bash)',
            r'perl\s+-e\s+.*socket.*open.*exec.*sh',
            r'python(\d)?\s+-c\s+.*socket.*subprocess',
            r'mkfifo\s+.*\|\s*sh',
            r'bash\s+-c\s+.*\{.*bash.*>&.*\}'
        ]
        
        # verificam patterns-urile cu severitate mare
        for pattern in high_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 9
        
        # patterns cu severitate medie (6-7)
        medium_patterns = [
            r'cat\s+>\s*/etc/rc\.local',
            r'chmod\s+\+x\s+/etc/rc\.local',
            r'chmod\s+\+x\s+/etc/rc\.(d|S|K)/\S+',
            r'nano\s+/etc/rc\.local',
            r'vi\s+/etc/rc\.local',
            r'vim\s+/etc/rc\.local',
            r'ssh-keygen\s+.*',
            r'chmod\s+[0-7]*\s+\S*/\.ssh/authorized_keys',
            r'telnetd\s+.*',
            r'service\s+\S+\s+(start|stop|status|enable|disable)',
            r'chkconfig\s+\S+\s+(on|off)',
            r'modprobe\s+\S+'
        ]
        
        # verificam patterns-urile cu severitate medie
        for pattern in medium_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 7
        
        # patterns cu severitate mica (5)
        low_patterns = [
            r'crontab\s+-l',
            r'systemctl\s+status\s+\S+',
            r'service\s+\S+\s+status',
            r'lsmod',
            r'modinfo\s+\S+'
        ]
        
        # verificam patterns-urile cu severitate mica
        for pattern in low_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 5
        
        return severity