#!/usr/bin/env python3
import re
from .. import AttackCategory
from ..common import normalize_command

class SystemReconCategory(AttackCategory):  
    def __init__(self):
        super().__init__("system_recon", "comenzi folosite pentru a colecta informatii despre sistem")
        
        # pastram comenzile pe care le-am vazut ca sa le refolosim
        self.analyzed_commands = []
    
    # patterns regex pentru diferite tipuri de comenzi de recunoastere
    PATTERNS = {
        'system_info': [
            r'uname(\s+-[a-z]+)?',
            r'hostname',
            r'lsb_release',
            r'cat\s+/etc/(issue|release|os-release)',
            r'cat\s+/proc/version',
            r'dmesg',
            r'uptime',
            r'hostnamectl'
        ],
        'user_info': [
            r'whoami',
            r'id(\s+-[a-z]+)?',
            r'who',
            r'w\b',
            r'last',
            r'lastlog',
            r'finger',
            r'cat\s+/etc/passwd',
            r'cat\s+/etc/shadow',
            r'cat\s+/etc/group',
            r'getent\s+passwd',
            r'getent\s+group',
            r'groups'
        ],
        'process_info': [
            r'ps(\s+-[a-zA-Z]+)?',
            r'top',
            r'htop',
            r'pstree',
            r'lsof',
            r'fuser',
            r'strace'
        ],
        'network_info': [
            r'ifconfig',
            r'ip(\s+[a-z]+)?',
            r'netstat(\s+-[a-zA-Z]+)?',
            r'ss(\s+-[a-zA-Z]+)?',
            r'arp(\s+-[a-z]+)?',
            r'route',
            r'iptables(\s+-[a-zA-Z]+)?',
            r'nft',
            r'tcpdump',
            r'cat\s+/etc/hosts',
            r'cat\s+/etc/resolv.conf',
            r'cat\s+/etc/network/'
        ],
        'file_system': [
            r'ls(\s+-[a-zA-Z]+)?',
            r'find(\s+\S+)?',
            r'locate',
            r'which',
            r'whereis',
            r'type',
            r'file',
            r'stat',
            r'du(\s+-[a-zA-Z]+)?',
            r'df(\s+-[a-zA-Z]+)?',
            r'mount'
        ],
        'config_info': [
            r'cat\s+/etc/\S+',
            r'less\s+/etc/\S+',
            r'more\s+/etc/\S+',
            r'grep\s+.+\s+/etc/\S+',
            r'cat\s+\S*conf\b',
            r'cat\s+\S*config\b',
            r'cat\s+\S*\.ini\b',
            r'cat\s+\S*\.conf\b',
            r'cat\s+\S*\.yaml\b',
            r'cat\s+\S*\.json\b'
        ],
        'service_info': [
            r'service(\s+\S+)?',
            r'systemctl(\s+\S+)?',
            r'/etc/init.d/\S+',
            r'chkconfig',
            r'rc-update',
            r'crontab',
            r'cat\s+/etc/crontab',
            r'cat\s+/etc/cron\S+'
        ]
    }
    
    def match(self, command):
        # facem comanda mai uniforma ca sa evitam mici diferente
        normalized_cmd = normalize_command(command)
        
        # verificam daca comanda se potriveste cu vreun pattern de recunoastere
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    # adaugam comanda la lista daca nu e deja acolo
                    if command not in self.analyzed_commands:
                        self.analyzed_commands.append(command)
                    return True
        
        return False
    
    def analyze_reconnaissance_depth(self, commands):
        if not isinstance(commands, list):
            commands = [commands]
        
        # pornim contorul pentru subcategorii
        subcategory_counts = {subcategory: 0 for subcategory in self.PATTERNS.keys()}
        matched_commands = []
        
        # analizam fiecare comanda
        for command in commands:
            matched_subcategories = []
            
            # verificam potrivirea cu fiecare subcategorie
            for subcategory, patterns in self.PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, command, re.IGNORECASE):
                        subcategory_counts[subcategory] += 1
                        matched_subcategories.append(subcategory)
                        matched_commands.append(command)
                        break  # trecem la urmatoarea subcategorie cand gasim o potrivire
            
        # calculam cat de adanc e recunoasterea (1-10)
        # factori: numarul de comenzi, diversitatea subcategoriilor
        total_commands = len(matched_commands)
        unique_subcategories = sum(1 for count in subcategory_counts.values() if count > 0)
        
        # calculam scoruri pe bucati
        command_score = min(5, total_commands / 3)  # max 5 puncte la 15 comenzi
        diversity_score = min(5, unique_subcategories)  # max 5 puncte pentru toate 7 subcategoriile
        
        # scorul final
        depth_score = command_score + diversity_score
        
        return {
            'score': depth_score,
            'command_count': total_commands,
            'unique_subcategories': unique_subcategories,
            'subcategory_counts': subcategory_counts,
            'level': self._get_depth_level(depth_score)
        }
    
    def _get_depth_level(self, score):
        if score < 3:
            return "Superficial"
        elif score < 5:
            return "Limitat"
        elif score < 7:
            return "Moderat"
        elif score < 9:
            return "Aprofundat"
        else:
            return "Exhaustiv"
    
    def get_system_info_commands(self):
        return self._filter_commands_by_subcategory('system_info')
    
    def get_user_info_commands(self):
        return self._filter_commands_by_subcategory('user_info')
    
    def get_network_info_commands(self):
        return self._filter_commands_by_subcategory('network_info')
    
    def get_file_system_commands(self):
        return self._filter_commands_by_subcategory('file_system')
    
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
        # comenzile de recunoastere sistem au in general severitate mica
        # cand sunt folosite individual, dar pot indica intentii rele
        # cand sunt folosite in combinatie
        
        # severitate de baza
        severity = 2
        
        # unele comenzi au severitate mai mare pentru ca pot dezvalui informatii sensibile
        high_severity_patterns = [
            r'cat\s+/etc/shadow',
            r'cat\s+.*(\.conf|password|credential)',
            r'cat\s+.*\.ssh/.*',
            r'find\s+.*\s+-perm\s+.*777',
            r'find\s+.*\s+-user\s+root',
            r'find\s+.*\s+-name\s+.*password',
            r'lsof',
            r'cat\s+/proc/\d+/maps',
            r'strace\s+.*',
            r'cat\s+/etc/sudoers'
        ]
        
        # verificam patterns-urile de severitate mare
        for pattern in high_severity_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 6  # acestea au severitate mai mare
        
        # patterns de severitate medie
        medium_severity_patterns = [
            r'cat\s+/etc/passwd',
            r'getent\s+passwd',
            r'cat\s+/etc/(issue|release)',
            r'cat\s+/proc/version',
            r'groups',
            r'ps\s+-ef',
            r'ps\s+aux',
            r'netstat\s+-[a-z]*p',
            r'ss\s+-[a-z]*p',
            r'id',
            r'last'
        ]
        
        # verificam patterns-urile de severitate medie
        for pattern in medium_severity_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 4  # acestea au severitate medie
        
        return severity