#!/usr/bin/env python3

import re
from .. import AttackCategory
from ..common import normalize_command

class PrivilegeEscalationCategory(AttackCategory):
    def __init__(self):
        super().__init__("privilege_escalation", "comenzi folosite pentru a obtine drepturi mai mari")
        
        # pastram comenzile pe care le-am vazut ca sa le refolosim
        self.analyzed_commands = []
    
    # patterns regex pentru diferite metode de a obtine drepturi mai mari
    PATTERNS = {
        'sudo_su': [
            r'sudo(\s+-[a-zA-Z]+)?(\s+.*)?',
            r'su(\s+-[a-zA-Z]+)?(\s+.*)?',
            r'pkexec(\s+.*)?',
            r'doas(\s+.*)?',
            r'sudo\s+su',
            r'sudo\s+-i',
            r'sudo\s+bash',
            r'sudo\s+sh',
            r'sudo\s+-s'
        ],
        'suid_sgid': [
            r'chmod(\s+-[a-zA-Z]+)?\s+[0-7]*[4567][0-7][0-7]',
            r'chmod(\s+-[a-zA-Z]+)?\s+[ug]\+s',
            r'find\s+.*\s+-perm\s+-[0-7]*[4567][0-7][0-7]',
            r'find\s+.*\s+-perm\s+/[0-7]*[4567][0-7][0-7]',
            r'find\s+.*\s+-perm\s+/[us]',
            r'find\s+.*\s+-type\s+f\s+-perm',
            r'cp\s+(\S+\s+)?(/bin/bash|/bin/sh)'
        ],
        'kernel_exploits': [
            r'gcc\s+.*exploit',
            r'uname\s+-[a-z]*r',
            r'gcc\s+.*\.c(\s+.*)?',
            r'\.\/(\S+exploit\S*|poc|CVE-\d+-\d+)',
            r'curl\s+.*exploit',
            r'wget\s+.*exploit',
            r'apt(-get)?\s+install\s+.*exploit',
            r'\.\/\S+\s+(\S+\s+)*root',
            r'make(\s+.*)?exploit'
        ],
        'capability_abuse': [
            r'getcap',
            r'setcap',
            r'capsh',
            r'getpcaps',
            r'capabilities'
        ],
        'container_escape': [
            r'docker(\s+.*)?\s+run(\s+.*)?',
            r'mount(\s+.*)?',
            r'umount(\s+.*)?',
            r'chroot',
            r'pivot_root',
            r'unshare',
            r'nsenter',
            r'lxc(\s+.*)?',
            r'runc(\s+.*)?'
        ],
        'password_manipulation': [
            r'passwd(\s+.*)?',
            r'chpasswd',
            r'usermod\s+-p',
            r'echo\s+.*\s+\|\s+passwd',
            r'echo\s+.*:.*\s+\|\s+chpasswd',
            r'openssl\s+passwd',
            r'htpasswd'
        ],
        'sudo_abuse': [
            r'sudo\s+-l',
            r'sudo\s+--list',
            r'cat\s+/etc/sudoers',
            r'visudo',
            r'echo\s+.*\s+>>\s+/etc/sudoers',
            r'chmod\s+.*\s+/etc/sudoers',
            r'SUDO_ASKPASS'
        ],
        'cron_abuse': [
            r'crontab\s+-e',
            r'crontab\s+-l',
            r'cat\s+/etc/crontab',
            r'cat\s+/var/spool/cron',
            r'echo\s+.*\s+>>\s+/etc/crontab',
            r'echo\s+.*\s+>>\s+/var/spool/cron',
            r'echo\s+.*\s+>>\s+/etc/cron\.d/'
        ]
    }
    
    def match(self, command):
        # verificam daca comanda se potriveste cu vreun pattern de escaladare drepturi
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    # adaugam comanda la lista daca nu e deja acolo
                    if command not in self.analyzed_commands:
                        self.analyzed_commands.append(command)
                    return True
        
        return False
    
    def analyze_escalation_attempt(self, command):
        # setam valorile de start
        result = {
            'method': 'Unknown',
            'target': 'Unknown',
            'severity': self.get_severity(command),
            'description': ''
        }
        
        # vedem ce metoda de escaladare se foloseste
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    result['method'] = sub_category
                    break
            if result['method'] != 'Unknown':
                break
        
        # vedem care e tinta escaladarii (utilizator sau proces)
        if result['method'] == 'sudo_su':
            # cautam sudo sau su cu utilizator
            su_match = re.search(r'su(\s+-[a-zA-Z]+)?\s+(\S+)', command)
            sudo_match = re.search(r'sudo(\s+-[a-zA-Z]+)?\s+-u\s+(\S+)', command)
            
            if su_match and len(su_match.groups()) >= 2:
                result['target'] = su_match.group(2)
                result['description'] = f"incearca sa devina utilizatorul {result['target']} folosind su"
            elif sudo_match and len(sudo_match.groups()) >= 2:
                result['target'] = sudo_match.group(2)
                result['description'] = f"incearca sa execute comanda ca utilizator {result['target']} folosind sudo"
            else:
                result['target'] = 'root'  # presupunem root daca nu avem alte informatii
                result['description'] = "incearca sa obtina drepturi de root"
        
        elif result['method'] == 'suid_sgid':
            # vedem daca chmod e folosit pentru a seta bit suid/sgid
            chmod_match = re.search(r'chmod(\s+-[a-zA-Z]+)?\s+([0-7]*[4567][0-7][0-7]|\+[ug]s)\s+(\S+)', command)
            if chmod_match and len(chmod_match.groups()) >= 3:
                result['target'] = chmod_match.group(3)
                result['description'] = f"incearca sa seteze bit suid/sgid pentru {result['target']}"
            else:
                # vedem daca cauta fisiere suid/sgid
                find_match = re.search(r'find\s+(\S+)\s+', command)
                if find_match:
                    result['target'] = find_match.group(1)
                    result['description'] = f"cauta fisiere suid/sgid in {result['target']}"
                else:
                    result['description'] = "manipuleaza permisiuni suid/sgid"
        
        elif result['method'] == 'kernel_exploits':
            # cautam nume de exploit sau cve specific
            exploit_match = re.search(r'(CVE-\d+-\d+|\S*exploit\S*|poc)', command, re.IGNORECASE)
            if exploit_match:
                result['target'] = exploit_match.group(1)
                result['description'] = f"posibila folosire a exploit-ului {result['target']}"
            else:
                result['description'] = "posibila compilare sau folosire exploit kernel"
        
        elif result['method'] == 'password_manipulation':
            # vedem utilizatorul pentru care se modifica parola
            passwd_match = re.search(r'passwd\s+(\S+)', command)
            if passwd_match:
                result['target'] = passwd_match.group(1)
                result['description'] = f"modifica parola pentru utilizatorul {result['target']}"
            else:
                result['description'] = "manipuleaza parole sistem"
        
        elif result['method'] == 'cron_abuse':
            result['description'] = "posibila manipulare job-uri cron pentru escaladare drepturi"
        
        elif result['method'] == 'sudo_abuse':
            result['description'] = "manipuleaza configuratia sudo"
        
        elif result['method'] == 'capability_abuse':
            result['description'] = "manipuleaza capabilities linux"
        
        elif result['method'] == 'container_escape':
            result['description'] = "posibila incercare de evadare din container"
        
        # calculam cat de siguri suntem de rezultat
        confidence = 0.7  # valoare de start
        
        # daca avem o tinta specifica si o metoda clara, suntem mai siguri
        if result['target'] != 'Unknown' and result['method'] != 'Unknown':
            confidence = 0.9
        
        result['confidence'] = confidence
        
        return result
    
    def get_sudo_attempts(self):
        return self._filter_commands_by_subcategory('sudo_su')
    
    def get_suid_attempts(self):
        return self._filter_commands_by_subcategory('suid_sgid')
    
    def get_kernel_exploit_attempts(self):
        return self._filter_commands_by_subcategory('kernel_exploits')
    
    def get_service_exploit_attempts(self):
        # aceasta functie va capta incercari combinand diverse subcategorii relevante
        service_commands = []
        
        # cautam comenzi care pot fi legate de exploatare servicii
        relevant_subcategories = ['sudo_abuse', 'cron_abuse', 'container_escape']
        
        for subcategory in relevant_subcategories:
            service_commands.extend(self._filter_commands_by_subcategory(subcategory))
        
        # scoatem comenzile duplicate
        return list(set(service_commands))
    
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
        # comenzile de escaladare drepturi au in general severitate mare
        
        # severitate de baza
        severity = 7
        
        # patterns cu severitate critica (9-10)
        critical_patterns = [
            r'\.\/(\S+exploit\S*|poc|CVE-\d+-\d+)',
            r'sudo\s+su',
            r'sudo\s+-i',
            r'sudo\s+bash',
            r'sudo\s+sh',
            r'sudo\s+-s',
            r'chmod\s+.*\s+[0-7]*4[0-7][0-7]',
            r'chmod\s+.*\s+u\+s',
            r'gcc\s+.*exploit',
            r'echo\s+.*\s+>>\s+/etc/sudoers',
            r'openssl\s+passwd\s+.*\s+>>\s+/etc/shadow',
            r'echo\s+.*\s+>>\s+/etc/shadow',
            r'mount(\s+.*)?/proc',
            r'mount(\s+.*)?/sys',
            r'mount(\s+.*)?/dev',
            r'docker\s+run\s+.*--privileged',
            r'docker\s+run\s+.*-v\s+/:/host',
            r'lxc\s+exec\s+.*\s+--\s+/bin/bash'
        ]
        
        # verificam patterns-urile critice
        for pattern in critical_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # calculam probabilitatea sa fie rau intentionat (ca sa nu dam scor maxim la false positive)
                # de exemplu, un simplu sudo ls nu e la fel de grav ca un exploit kernel
                if 'exploit' in command.lower() or 'CVE-' in command:
                    return 10  # exploituri cunoscute - severitate maxima
                
                return 9  # alte comenzi critice
        
        # patterns cu severitate mare (8)
        high_patterns = [
            r'sudo\s+.*(-u\s+\S+)?',
            r'su\s+\S+',
            r'passwd\s+\S+',
            r'chmod\s+.*\s+[0-7]*[67][0-7][0-7]',
            r'chmod\s+.*\s+g\+s',
            r'crontab\s+-e',
            r'echo\s+.*\s+>>\s+/etc/crontab',
            r'pkexec(\s+.*)?',
            r'setcap\s+.*\s+cap_setuid'
        ]
        
        # verificam patterns-urile cu severitate mare
        for pattern in high_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 8
        
        # patterns cu severitate medie (6-7)
        medium_patterns = [
            r'sudo\s+-l',
            r'sudo\s+--list',
            r'crontab\s+-l',
            r'cat\s+/etc/sudoers',
            r'cat\s+/etc/crontab',
            r'find\s+.*\s+-perm',
            r'getcap(\s+.*)?',
            r'getpcaps(\s+.*)?',
            r'cat\s+/etc/passwd',
            r'cat\s+/etc/shadow'
        ]
        
        # verificam patterns-urile cu severitate medie
        for pattern in medium_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 6
        
        return severity