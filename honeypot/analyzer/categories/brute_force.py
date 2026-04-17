#!/usr/bin/env python3

import re
from .. import AttackCategory
from ..common import normalize_command

class BruteForceCategory(AttackCategory):
  
    
    def __init__(self):
        super().__init__("brute_force", "Comenzi folosite pentru atacuri brute force pe servicii și credențiale")
        
        # tinem aici comenzile analizate ca sa le refolosim
        self.analyzed_commands = []
    
    # aici avem toate pattern-urile pentru diferite tipuri de brute force
    PATTERNS = {
        'password_cracking': [
            r'hydra\s+(-[a-zA-Z0-9]+\s+)?(\S+)\s+(\S+)',
            r'medusa\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'ncrack\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'patator\s+(\S+)',
            r'john\s+(\S+)',
            r'hashcat\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'thc-hydra\s+(\S+)',
            r'crackmapexec\s+(\S+)',
            r'aircrack-ng\s+(\S+)',
            r'ophcrack\s+(\S+)',
            r'for\s+.*\s*in\s+.*\s*do\s*.*passwd.*\s*done',
            r'for\s+.*\s*in\s+.*\s*do\s*.*ssh.*\s*done',
            r'ssh\s+.*\s*-f\s+.*'
        ],
        'dictionary_attacks': [
            r'(hydra|john|hashcat|medusa|ncrack|patator)\s+.*\s*-P\s+(\S+)',
            r'(hydra|john|hashcat|medusa|ncrack|patator)\s+.*\s*--p(ass)?list=(\S+)',
            r'john\s+.*--wordlist=(\S+)',
            r'hashcat\s+.*-a\s+[0-7]',
            r'hashcat\s+.*\s*-m\s+\d+',
            r'john\s+.*\s*--rules',
            r'grep\s+.*\s*rockyou',
            r'cat\s+.*\s*\|\s*grep\s+.*pass',
            r'for\s+.*\s*in\s+\$\(cat\s+(\S+)\).*\s*done',
            r'while\s+read\s+.*\s*from\s+(\S+).*\s*done',
            r'crunch\s+\d+\s+\d+\s+\S+',
            r'cewl\s+.*\s+-w\s+(\S+)',
            r'python\s+.*pwlist\S*\.py'
        ],
        'credential_stuffing': [
            r'(hydra|medusa|ncrack|patator)\s+.*\s*-C\s+(\S+)',
            r'(hydra|medusa|ncrack|patator)\s+.*\s*--comb(o)?=(\S+)',
            r'(hydra|medusa|ncrack|patator)\s+.*\s*-L\s+(\S+)\s+.*\s*-P\s+(\S+)',
            r'(hydra|medusa|ncrack|patator)\s+.*\s*--user=(\S+)\s+.*\s*--pass=(\S+)',
            r'for\s+.*\s*in\s+\$\(cat\s+users\.txt\).*\$\(cat\s+pass\.txt\).*\s*done',
            r'while\s+read\s+.*\s*;\s*do\s+.*\s*;\s*done\s+<\s+creds\.txt',
            r'python\s+.*brute\S*\.py.*\s*-u\s+.*\s*-p\s+',
            r'python\s+.*credstuff\S*\.py',
            r'python\s+.*cred.?spray\S*\.py',
            r'wfuzz\s+.*\s*-z\s+file,(\S+)\s+.*\s*-z\s+file,(\S+)',
            r'if.*grep.*administrator.*then'
        ],
        'online_service_attacks': [
            r'hydra\s+.*\s*-s\s+(\d+)\s+.*\s*ssh',
            r'hydra\s+.*\s*-s\s+(\d+)\s+.*\s*ftp',
            r'hydra\s+.*\s*-s\s+(\d+)\s+.*\s*telnet',
            r'hydra\s+.*\s*-s\s+(\d+)\s+.*\s*smb',
            r'hydra\s+.*\s*-s\s+(\d+)\s+.*\s*http-post',
            r'hydra\s+.*\s*-s\s+(\d+)\s+.*\s*http-form',
            r'medusa\s+.*\s*-M\s+(ssh|ftp|http|telnet|smb)',
            r'ncrack\s+.*\s*(ssh|ftp|telnet)',
            r'patator\s+(ssh|ftp|telnet|smb|http)_login',
            r'wpscan\s+.*\s*--usernames\s+.*\s*--passwords',
            r'sqlmap\s+.*\s*--forms\s+.*\s*--passwords',
            r'python.*\s+brutespray\.py',
            r'python.*\s+brute\S*ssh\.py'
        ],
        'local_password_attacks': [
            r'unshadow\s+(\S+)\s+(\S+)',
            r'john\s+.*\/etc\/shadow',
            r'john\s+.*\/etc\/passwd',
            r'john\s+.*shadow.txt',
            r'cat\s+\/etc\/shadow',
            r'hashcat\s+.*shadow',
            r'hashcat\s+.*-m\s+1800',
            r'openssl\s+passwd',
            r'mkpasswd',
            r'gpg2john',
            r'zip2john',
            r'rar2john',
            r'office2john',
            r'ssh2john',
            r'pdf2john',
            r'keepass2john'
        ]
    }
    
    def match(self, command):
        # vedem daca comanda se potriveste cu vreo tehnica de brute force
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    # adaugam comanda la lista analizata daca nu exista deja
                    if command not in self.analyzed_commands:
                        self.analyzed_commands.append(command)
                    return True
        
        return False
    
    def analyze_brute_force_technique(self, command):
        # incepem cu valorile de baza
        result = {
            'method': 'Unknown',
            'target': 'Unknown',
            'wordlist': 'Unknown',
            'tool': 'Unknown',
            'service': 'Unknown',
            'severity': self.get_severity(command),
            'description': ''
        }
        
        # cautam sa vedem ce fel de brute force e
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    result['method'] = sub_category
                    break
            if result['method'] != 'Unknown':
                break
        
        # analizam specificitatile metodei de brute force
        if result['method'] == 'password_cracking':
            # detectam tool-ul folosit
            if 'hydra' in command:
                result['tool'] = 'Hydra'
                
                # incercam sa identificam serviciul si tinta
                service_match = re.search(r'hydra\s+(?:-[a-zA-Z0-9]+\s+)?(?:-s\s+\d+\s+)?(\S+)\s+(\S+)', command, re.IGNORECASE)
                if service_match:
                    result['target'] = service_match.group(1)
                    result['service'] = service_match.group(2)
                
                # cautam liste de parole
                wordlist_match = re.search(r'-P\s+(\S+)', command, re.IGNORECASE)
                if wordlist_match:
                    result['wordlist'] = wordlist_match.group(1)
                
                result['description'] = f"Atac brute force cu Hydra către {result['target']} folosind protocolul {result['service']}"
                if result['wordlist'] != 'Unknown':
                    result['description'] += f" cu lista de parole {result['wordlist']}"
            
            elif 'john' in command:
                result['tool'] = 'John the Ripper'
                
                # incercam sa identificam tinta
                target_match = re.search(r'john\s+(?:-[a-zA-Z0-9]+\s+)?(\S+)', command, re.IGNORECASE)
                if target_match:
                    result['target'] = target_match.group(1)
                
                # cautam liste de cuvinte
                wordlist_match = re.search(r'--wordlist=(\S+)', command, re.IGNORECASE)
                if wordlist_match:
                    result['wordlist'] = wordlist_match.group(1)
                
                result['description'] = f"Spargere parole cu John the Ripper pentru {result['target']}"
                if result['wordlist'] != 'Unknown':
                    result['description'] += f" folosind dictionarul {result['wordlist']}"
            
            elif 'hashcat' in command:
                result['tool'] = 'Hashcat'
                
                # incercam sa identificam tinta
                target_match = re.search(r'hashcat\s+(?:-[a-zA-Z0-9]+\s+)?(\S+)', command, re.IGNORECASE)
                if target_match:
                    result['target'] = target_match.group(1)
                
                # identificam metoda de atac
                attack_match = re.search(r'-a\s+(\d)', command, re.IGNORECASE)
                attack_type = "Unknown"
                if attack_match:
                    attack_id = attack_match.group(1)
                    if attack_id == '0':
                        attack_type = "Dictionary"
                    elif attack_id == '1':
                        attack_type = "Combination"
                    elif attack_id == '3':
                        attack_type = "Mask/Brute-Force"
                    else:
                        attack_type = f"Type {attack_id}"
                
                result['description'] = f"Spargere hash-uri cu Hashcat pentru {result['target']} folosind atac de tip {attack_type}"
            
            elif 'for' in command and ('passwd' in command or 'ssh' in command):
                result['tool'] = 'Custom script'
                
                # incercam sa detectam tinta din buclele for
                if 'ssh' in command:
                    target_match = re.search(r'ssh\s+\S+@(\S+)', command, re.IGNORECASE)
                    if target_match:
                        result['target'] = target_match.group(1)
                        result['service'] = 'SSH'
                
                result['description'] = f"Script personalizat pentru brute force"
                if result['target'] != 'Unknown' and result['service'] != 'Unknown':
                    result['description'] += f" către serviciul {result['service']} pe {result['target']}"
        
        elif result['method'] == 'dictionary_attacks':
            # detectam tool-ul si lista de cuvinte
            if re.search(r'(hydra|john|hashcat|medusa|ncrack|patator)', command, re.IGNORECASE):
                tool_match = re.search(r'(hydra|john|hashcat|medusa|ncrack|patator)', command, re.IGNORECASE)
                if tool_match:
                    result['tool'] = tool_match.group(1).capitalize()
                
                # cautam lista de cuvinte
                wordlist_match = re.search(r'(-P\s+|--p(?:ass)?list=|--wordlist=)(\S+)', command, re.IGNORECASE)
                if wordlist_match:
                    result['wordlist'] = wordlist_match.group(2)
                
                # identificam serviciul si tinta pentru unele tool-uri
                if 'hydra' in command.lower():
                    service_match = re.search(r'hydra\s+(?:-[a-zA-Z0-9]+\s+)?(?:-s\s+\d+\s+)?(\S+)\s+(\S+)', command, re.IGNORECASE)
                    if service_match:
                        result['target'] = service_match.group(1)
                        result['service'] = service_match.group(2)
            
            elif 'crunch' in command:
                result['tool'] = 'Crunch'
                
                # captam parametrii pentru generare
                crunch_match = re.search(r'crunch\s+(\d+)\s+(\d+)\s+(\S+)', command, re.IGNORECASE)
                if crunch_match:
                    min_len = crunch_match.group(1)
                    max_len = crunch_match.group(2)
                    charset = crunch_match.group(3)
                    
                    result['description'] = f"Generare listă de parole cu Crunch pentru lungimi între {min_len} și {max_len} caractere"
                else:
                    result['description'] = "Generare listă de parole cu Crunch"
            
            elif 'for' in command and 'cat' in command:
                result['tool'] = 'Custom script'
                
                # incercam sa identificam fisierul cu parole
                wordlist_match = re.search(r'cat\s+(\S+)', command, re.IGNORECASE)
                if wordlist_match:
                    result['wordlist'] = wordlist_match.group(1)
                
                result['description'] = "Script personalizat pentru atac de tip dictionary"
                if result['wordlist'] != 'Unknown':
                    result['description'] += f" folosind lista {result['wordlist']}"
            
            # descriere generala daca nu avem informatii specifice
            if result['description'] == '':
                result['description'] = f"Atac de tip dictionary cu {result['tool']}"
                if result['wordlist'] != 'Unknown':
                    result['description'] += f" folosind lista {result['wordlist']}"
        
        elif result['method'] == 'credential_stuffing':
            # detectam tool-ul si lista de combinatii
            if re.search(r'(hydra|medusa|ncrack|patator)', command, re.IGNORECASE):
                tool_match = re.search(r'(hydra|medusa|ncrack|patator)', command, re.IGNORECASE)
                if tool_match:
                    result['tool'] = tool_match.group(1).capitalize()
                
                # cautam lista de combinatii
                combo_match = re.search(r'-C\s+(\S+)|--comb(?:o)?=(\S+)', command, re.IGNORECASE)
                if combo_match:
                    combo_list = combo_match.group(1) if combo_match.group(1) else combo_match.group(2)
                    result['wordlist'] = combo_list
                
                # sau cautam liste separate de utilizatori si parole
                user_list_match = re.search(r'-L\s+(\S+)|--user(?:name)?s?=(\S+)', command, re.IGNORECASE)
                pass_list_match = re.search(r'-P\s+(\S+)|--pass(?:word)?s?=(\S+)', command, re.IGNORECASE)
                
                if user_list_match and pass_list_match:
                    user_list = user_list_match.group(1) if user_list_match.group(1) else user_list_match.group(2)
                    pass_list = pass_list_match.group(1) if pass_list_match.group(1) else pass_list_match.group(2)
                    result['wordlist'] = f"Users: {user_list}, Passwords: {pass_list}"
                
                # identificam serviciul si tinta pentru unele tool-uri
                if 'hydra' in command.lower():
                    service_match = re.search(r'hydra\s+(?:-[a-zA-Z0-9]+\s+)?(?:-s\s+\d+\s+)?(\S+)\s+(\S+)', command, re.IGNORECASE)
                    if service_match:
                        result['target'] = service_match.group(1)
                        result['service'] = service_match.group(2)
            
            elif 'python' in command and re.search(r'(brute|credstuff|cred.?spray)', command, re.IGNORECASE):
                result['tool'] = 'Python script'
                
                # incercam sa identificam lista de credentiale si tinta
                user_match = re.search(r'-u\s+(\S+)', command, re.IGNORECASE)
                pass_match = re.search(r'-p\s+(\S+)', command, re.IGNORECASE)
                
                if user_match and pass_match:
                    result['wordlist'] = f"Users: {user_match.group(1)}, Passwords: {pass_match.group(1)}"
                
                result['description'] = f"Script Python pentru credential stuffing"
                if result['wordlist'] != 'Unknown':
                    result['description'] += f" folosind {result['wordlist']}"
            
            # descriere generala daca nu avem informatii specifice
            if result['description'] == '':
                result['description'] = f"Atac de tip credential stuffing cu {result['tool']}"
                if result['wordlist'] != 'Unknown':
                    result['description'] += f" folosind {result['wordlist']}"
                if result['target'] != 'Unknown' and result['service'] != 'Unknown':
                    result['description'] += f" către serviciul {result['service']} pe {result['target']}"
        
        elif result['method'] == 'online_service_attacks':
            # detectam tool-ul, serviciul si tinta
            if 'hydra' in command:
                result['tool'] = 'Hydra'
                
                # identificam serviciul
                service_matches = [
                    (r'ssh', 'SSH'),
                    (r'ftp', 'FTP'),
                    (r'telnet', 'Telnet'),
                    (r'smb', 'SMB'),
                    (r'http-post', 'HTTP POST'),
                    (r'http-form', 'HTTP Form'),
                    (r'http-get', 'HTTP GET')
                ]
                
                for pattern, service_name in service_matches:
                    if re.search(pattern, command, re.IGNORECASE):
                        result['service'] = service_name
                        break
                
                # identificam tinta
                target_match = re.search(r'hydra\s+(?:-[a-zA-Z0-9]+\s+)?(?:-s\s+\d+\s+)?(\S+)', command, re.IGNORECASE)
                if target_match:
                    result['target'] = target_match.group(1)
                
                # cautam lista de parole
                wordlist_match = re.search(r'-P\s+(\S+)', command, re.IGNORECASE)
                if wordlist_match:
                    result['wordlist'] = wordlist_match.group(1)
            
            elif 'medusa' in command:
                result['tool'] = 'Medusa'
                
                # identificam serviciul
                service_match = re.search(r'-M\s+(\S+)', command, re.IGNORECASE)
                if service_match:
                    result['service'] = service_match.group(1).upper()
                
                # identificam tinta
                target_match = re.search(r'-h\s+(\S+)', command, re.IGNORECASE)
                if target_match:
                    result['target'] = target_match.group(1)
            
            elif 'wpscan' in command:
                result['tool'] = 'WPScan'
                result['service'] = 'WordPress'
                
                # identificam tinta
                target_match = re.search(r'wpscan\s+.*--url\s+(\S+)', command, re.IGNORECASE)
                if target_match:
                    result['target'] = target_match.group(1)
            
            # descriere generala
            if result['description'] == '':
                result['description'] = f"Atac brute force online către serviciul {result['service']}"
                if result['target'] != 'Unknown':
                    result['description'] += f" pe {result['target']}"
                if result['tool'] != 'Unknown':
                    result['description'] += f" folosind {result['tool']}"
        
        elif result['method'] == 'local_password_attacks':
            # detectam tool-ul si tinta
            if 'john' in command:
                result['tool'] = 'John the Ripper'
                
                # identificam tipul de fisier tinta
                if '/etc/shadow' in command:
                    result['target'] = '/etc/shadow'
                    result['description'] = "Spargere parole sistem din fișierul shadow"
                elif '/etc/passwd' in command:
                    result['target'] = '/etc/passwd'
                    result['description'] = "Spargere parole sistem din fișierul passwd"
                else:
                    target_match = re.search(r'john\s+(?:-[a-zA-Z0-9]+\s+)?(\S+)', command, re.IGNORECASE)
                    if target_match:
                        result['target'] = target_match.group(1)
                        result['description'] = f"Spargere parole din fișierul {result['target']}"
            
            elif 'unshadow' in command:
                result['tool'] = 'Unshadow'
                
                # identificam fisierele passwd si shadow
                files_match = re.search(r'unshadow\s+(\S+)\s+(\S+)', command, re.IGNORECASE)
                if files_match:
                    passwd_file = files_match.group(1)
                    shadow_file = files_match.group(2)
                    result['target'] = f"{passwd_file} + {shadow_file}"
                    result['description'] = f"Combinare fișiere passwd și shadow pentru spargere parole"
            
            elif 'hashcat' in command and 'shadow' in command:
                result['tool'] = 'Hashcat'
                result['target'] = 'shadow'
                result['description'] = "Spargere hash-uri din fișierul shadow cu Hashcat"
            
            elif re.search(r'\w+2john', command, re.IGNORECASE):
                tool_match = re.search(r'(\w+)2john', command, re.IGNORECASE)
                if tool_match:
                    format_name = tool_match.group(1)
                    result['tool'] = f"{format_name}2john"
                    
                    # identificam tinta
                    target_match = re.search(r'\w+2john\s+(\S+)', command, re.IGNORECASE)
                    if target_match:
                        result['target'] = target_match.group(1)
                    
                    result['description'] = f"Convertire parole {format_name} în format pentru John the Ripper"
            
            # descriere generala daca nu avem informatii specifice
            if result['description'] == '':
                result['description'] = f"Atac local pentru spargerea parolelor"
                if result['target'] != 'Unknown':
                    result['description'] += f" din {result['target']}"
                if result['tool'] != 'Unknown':
                    result['description'] += f" folosind {result['tool']}"
        
        # daca nu am reusit sa determinam detalii specifice, oferim o descriere generala
        if result['description'] == '':
            result['description'] = f"Posibil atac brute force de tip {result['method']}"
            if result['tool'] != 'Unknown':
                result['description'] += f" folosind {result['tool']}"
        
        # calculam un scor de incredere bazat pe cat de precisa este potrivirea
        confidence = 0.7  # scor implicit
        
        # daca avem o tinta specifica, un tool si o metoda clara, avem mai multa incredere
        if result['target'] != 'Unknown' and result['tool'] != 'Unknown' and result['method'] != 'Unknown':
            confidence = 0.9
        elif (result['target'] != 'Unknown' or result['wordlist'] != 'Unknown') and result['method'] != 'Unknown':
            confidence = 0.8
        
        result['confidence'] = confidence
        
        return result
    
    def get_password_cracking_attempts(self):
        return self._filter_commands_by_subcategory('password_cracking')
    
    def get_dictionary_attack_attempts(self):
        return self._filter_commands_by_subcategory('dictionary_attacks')
    
    def get_credential_stuffing_attempts(self):
        # combinam credential stuffing si online service attacks
        credential_stuffing = self._filter_commands_by_subcategory('credential_stuffing')
        online_attacks = self._filter_commands_by_subcategory('online_service_attacks')
        
        # eliminam duplicatele
        return list(set(credential_stuffing + online_attacks))
    
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
        # comenzile de brute force au in general severitate ridicata
        
        # severitate implicita
        severity = 7
        
        # pattern-uri de atac foarte agresive sau periculoase (9-10)
        aggressive_patterns = [
            r'hydra\s+.*\s+-t\s+\d{2,}',  # multe thread-uri
            r'medusa\s+.*\s+-T\s+\d{2,}',
            r'hashcat\s+.*\s+-w\s+[34]',  # workload ridicat
            r'hydra\s+.*\s+-e\s+nsr',
            r'john\s+.*--fork=\d{2,}',
            r'for\s+.*\s*in\s+.*\s*do\s*ssh\s+.*\s*done',
            r'hydra\s+.*ssh',
            r'hydra\s+.*telnet',
            r'brutespray',
            r'crackmapexec\s+.*\s+-u\s+.*\s+-p',
            r'unshadow\s+/etc/passwd\s+/etc/shadow',
            r'john\s+/etc/shadow',
            r'hashcat\s+.*\s+-a\s+3',  # atac brute-force pur
            r'hydra\s+.*http-post'
        ]
        
        # verificam pattern-urile foarte agresive
        for pattern in aggressive_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # atacuri foarte aggressive sau tintind servicii critice
                return 10  # severitate maxima
        
        # pattern-uri cu severitate mare (7-8)
        high_patterns = [
            r'hydra\s+',
            r'medusa\s+',
            r'ncrack\s+',
            r'john\s+.*--wordlist',
            r'hashcat\s+.*\s+-a\s+[01]',  # atacuri dictionary sau combinator
            r'hashcat\s+.*\s+-m\s+\d+',
            r'wpscan\s+.*\s+--usernames\s+.*\s+--passwords',
            r'patator\s+(ssh|ftp|telnet|smb|http)_login',
            r'for\s+.*\s*in\s+\$\(cat\s+(\S+)\).*\s*done',
            r'while\s+read\s+.*\s*;\s*do\s+.*\s*;\s*done\s+<\s+creds\.txt'
        ]
        
        # verificam pattern-urile cu severitate mare
        for pattern in high_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # atacuri cu instrumente specializate, dar mai putin agresive
                return 8
        
        # pattern-uri cu severitate medie (5-6)
        medium_patterns = [
            r'john\s+',
            r'crunch\s+',
            r'cewl\s+',
            r'fcrackzip\s+',
            r'pdfcrack\s+',
            r'zip2john\s+',
            r'rar2john\s+',
            r'gpg2john\s+',
            r'ssh2john\s+',
            r'pdf2john\s+',
            r'keepass2john\s+',
            r'grep\s+.*\s*rockyou',
            r'cat\s+.*\s*\|\s*grep\s+.*pass'
        ]
        
        # verificam pattern-urile cu severitate medie
        for pattern in medium_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # atacuri sau pregatire pentru atacuri, cu potential mediu de pericol
                return 6
        
        # pattern-uri cu severitate scazuta (3-4)
        low_patterns = [
            r'openssl\s+passwd',
            r'mkpasswd',
            r'makepasswd',
            r'lastpass2john',
            r'cat\s+\/etc\/shadow',
            r'cat\s+\/etc\/passwd'
        ]
        
        # verificam pattern-urile cu severitate scazuta
        for pattern in low_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # investigatii locale, fara atac activ
                return 4
        
        return severity