#!/usr/bin/env python3

import re
from .. import AttackCategory
from ..common import normalize_command

class DataExfiltrationCategory(AttackCategory):

    def __init__(self):
        super().__init__("data_exfiltration", "Comenzi folosite pentru extragerea datelor din sistem")
        
        # tinem aici comenzile analizate ca sa le refolosim
        self.analyzed_commands = []
    
    # aici avem toate pattern-urile pentru diferite tipuri de exfiltrare
    PATTERNS = {
        'file_transfer': [
            r'scp\s+(\S+)\s+(\S+@\S+):(\S+)',
            r'sftp\s+(\S+@\S+)',
            r'ftp\s+(\S+)',
            r'rsync\s+(-[a-zA-Z]+\s+)?(\S+)\s+(\S+@\S+):(\S+)',
            r'rcp\s+(\S+)\s+(\S+@\S+):(\S+)',
            r'pscp\s+(\S+)\s+(\S+@\S+):(\S+)',
            r'tftp\s+(\S+)'
        ],
        'encoding': [
            r'base64\s+(\S+)',
            r'xxd\s+(\S+)',
            r'hexdump\s+(\S+)',
            r'openssl\s+enc\s+(-[a-zA-Z0-9]+)\s+(-in\s+)?(\S+)',
            r'uuencode\s+(\S+)',
            r'echo.*\|\s*base64',
            r'cat\s+(\S+)\s*\|\s*base64',
            r'base64\s+-d',
            r'iconv\s+(-[a-zA-Z0-9]+\s+)?(-o\s+)?(\S+)',
            r'od\s+(-[a-zA-Z0-9]+\s+)?(\S+)'
        ],
        'compression': [
            r'zip\s+(-[a-zA-Z0-9]+\s+)?(\S+)\s+(\S+)',
            r'tar\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'gzip\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'bzip2\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'xz\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'7z\s+[a|x]\s+(\S+)',
            r'rar\s+[a|x]\s+(\S+)',
            r'tar\s+.*\s*\|\s*gzip',
            r'tar\s+.*\s*\|\s*xz',
            r'tar\s+.*\s*\|\s*bzip2'
        ],
        'network_transfer': [
            r'nc\s+(\S+)\s+(\d+)(\s*[<>].*)?',
            r'netcat\s+(\S+)\s+(\d+)(\s*[<>].*)?',
            r'ncat\s+(\S+)\s+(\d+)(\s*[<>].*)?',
            r'curl\s+(-[a-zA-Z0-9]+\s+)?(-o\s+)?(-d\s+)?(\S+)',
            r'wget\s+(-[a-zA-Z0-9]+\s+)?(-O\s+)?(-P\s+)?(\S+)',
            r'socat\s+(\S+)\s+(\S+)',
            r'telnet\s+(\S+)\s+(\d+)',
            r'ssh\s+(\S+@\S+)\s+.*\s*cat\s+',
            r'curl\s+.*\s+--upload-file\s+(\S+)',
            r'curl\s+.*\s+-T\s+(\S+)',
            r'curl\s+.*\s+--data\s+\@(\S+)',
            r'nc\s+.*>\s+(\S+)',
            r'netcat\s+.*>\s+(\S+)',
            r'wget\s+.*--post-file=(\S+)'
        ],
        'clipboard_history': [
            r'xclip\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'pbcopy\s+(<\s+)?(\S+)',
            r'xsel\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'clip\s+(<\s+)?(\S+)',
            r'cat\s+.*\s*\|\s*xclip',
            r'cat\s+.*\s*\|\s*pbcopy',
            r'cat\s+.*\s*\|\s*xsel',
            r'cat\s+.*\s*\|\s*clip'
        ],
        'email_exfiltration': [
            r'mail\s+(-[a-zA-Z0-9]+\s+)?(\S+@\S+)',
            r'mailx\s+(-[a-zA-Z0-9]+\s+)?(\S+@\S+)',
            r'sendmail\s+(-[a-zA-Z0-9]+\s+)?(\S+@\S+)',
            r'mutt\s+(-[a-zA-Z0-9]+\s+)?(\S+@\S+)',
            r'msmtp\s+(-[a-zA-Z0-9]+\s+)?(\S+@\S+)',
            r'echo\s+.*\s*\|\s*mail\s+.*(\S+@\S+)',
            r'cat\s+.*\s*\|\s*mail\s+.*(\S+@\S+)'
        ],
        'dns_exfiltration': [
            r'dig\s+(\S+)\.(\S+)',
            r'host\s+(\S+)\.(\S+)',
            r'nslookup\s+(\S+)\.(\S+)',
            r'ping\s+(\S+)\.(\S+)',
            r'for\s+.*\s*dig\s+.*(\S+)\.(\S+)',
            r'for\s+.*\s*host\s+.*(\S+)\.(\S+)',
            r'for\s+.*\s*nslookup\s+.*(\S+)\.(\S+)'
        ],
        'image_steganography': [
            r'steghide\s+(\S+)\s+(\S+)',
            r'outguess\s+(-[a-zA-Z0-9]+\s+)?(\S+)\s+(\S+)',
            r'openstego\s+(\S+)\s+(\S+)',
            r'stegsnow\s+(-[a-zA-Z0-9]+\s+)?(\S+)\s+(\S+)',
            r'jsteg\s+(\S+)\s+(\S+)',
            r'steganography\s+(\S+)\s+(\S+)',
            r'stegosuite\s+(\S+)\s+(\S+)'
        ]
    }
    
    def match(self, command):
        # vedem daca comanda se potriveste cu vreo tehnica de exfiltrare
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    # adaugam comanda la lista analizata daca nu exista deja
                    if command not in self.analyzed_commands:
                        self.analyzed_commands.append(command)
                    return True
        
        return False
    
    def analyze_exfiltration_method(self, command):
        # incepem cu valorile de baza
        result = {
            'method': 'Unknown',
            'channel': 'Unknown',
            'target': 'Unknown',
            'source': 'Unknown',
            'severity': self.get_severity(command),
            'description': ''
        }
        
        # cautam sa vedem ce fel de exfiltrare e
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    result['method'] = sub_category
                    break
            if result['method'] != 'Unknown':
                break
        
        # extragem detalii specifice in functie de metoda identificata
        if result['method'] == 'file_transfer':
            # analizam comenzi de transfer fisiere
            scp_match = re.search(r'scp\s+(\S+)\s+(\S+@\S+):(\S+)', command)
            if scp_match:
                result['source'] = scp_match.group(1)
                result['target'] = f"{scp_match.group(2)}:{scp_match.group(3)}"
                result['channel'] = 'SCP'
                result['description'] = f"Transfer de fișier de la {result['source']} către {result['target']} via SCP"
            
            rsync_match = re.search(r'rsync\s+(-[a-zA-Z]+\s+)?(\S+)\s+(\S+@\S+):(\S+)', command)
            if rsync_match:
                result['source'] = rsync_match.group(2)
                result['target'] = f"{rsync_match.group(3)}:{rsync_match.group(4)}"
                result['channel'] = 'RSYNC'
                result['description'] = f"Transfer de fișier de la {result['source']} către {result['target']} via RSYNC"
            
            sftp_match = re.search(r'sftp\s+(\S+@\S+)', command)
            if sftp_match:
                result['target'] = sftp_match.group(1)
                result['channel'] = 'SFTP'
                result['description'] = f"Posibil transfer interactiv de fișiere către {result['target']} via SFTP"
        
        elif result['method'] == 'network_transfer':
            # analizam comenzi de transfer retea
            nc_match = re.search(r'nc\s+(\S+)\s+(\d+)(\s*[<>]\s*(\S+))?', command)
            if nc_match:
                result['target'] = f"{nc_match.group(1)}:{nc_match.group(2)}"
                result['channel'] = 'Netcat'
                
                # verificam daca este specificat un fisier
                if nc_match.group(3) and nc_match.group(4):
                    if '<' in nc_match.group(3):
                        result['source'] = nc_match.group(4)
                        result['description'] = f"Transfer de fișier {result['source']} către {result['target']} via Netcat"
                    elif '>' in nc_match.group(3):
                        result['source'] = nc_match.group(4)
                        result['description'] = f"Primire date în fișierul {result['source']} de la {result['target']} via Netcat"
                else:
                    result['description'] = f"Posibilă comunicare interactivă sau transfer de date cu {result['target']} via Netcat"
            
            curl_upload_match = re.search(r'curl\s+.*(-T|--upload-file)\s+(\S+)\s+(\S+)', command)
            if curl_upload_match:
                result['source'] = curl_upload_match.group(2)
                result['target'] = curl_upload_match.group(3)
                result['channel'] = 'HTTP/HTTPS'
                result['description'] = f"Încărcare fișier {result['source']} către {result['target']} via cURL"
        
        elif result['method'] == 'encoding':
            # analizam comenzi de codificare
            base64_match = re.search(r'base64\s+(\S+)', command)
            if base64_match:
                result['source'] = base64_match.group(1)
                result['channel'] = 'Text encoding'
                result['description'] = f"Codificare Base64 a fișierului {result['source']}"
            
            cat_base64_match = re.search(r'cat\s+(\S+)\s*\|\s*base64', command)
            if cat_base64_match:
                result['source'] = cat_base64_match.group(1)
                result['channel'] = 'Text encoding'
                result['description'] = f"Codificare Base64 a fișierului {result['source']}"
        
        elif result['method'] == 'compression':
            # analizam comenzi de compresie
            tar_match = re.search(r'tar\s+(-[a-zA-Z0-9]+)\s+(\S+)\s+(\S+)', command)
            if tar_match:
                result['source'] = tar_match.group(3)
                result['target'] = tar_match.group(2)
                result['channel'] = 'Archive'
                result['description'] = f"Compresie fișier(e) {result['source']} în arhiva {result['target']}"
        
        elif result['method'] == 'dns_exfiltration':
            # analizam comenzi de exfiltrare dns
            dns_match = re.search(r'(dig|host|nslookup)\s+(\S+)\.(\S+)', command)
            if dns_match:
                result['source'] = dns_match.group(2)
                result['target'] = dns_match.group(3)
                result['channel'] = 'DNS'
                result['description'] = f"Posibilă exfiltrare date via DNS de la {result['source']} către {result['target']}"
        
        # daca nu am reusit sa determinam detalii specifice, oferim o descriere generala
        if result['description'] == '':
            result['description'] = f"Posibilă exfiltrare de date folosind metoda {result['method']}"
        
        # calculam un scor de incredere bazat pe cat de precisa este potrivirea
        confidence = 0.6  # scor implicit
        
        # daca avem detalii specifice despre sursa si tinta, avem mai multa incredere
        if result['source'] != 'Unknown' and result['target'] != 'Unknown':
            confidence = 0.8
        elif result['source'] != 'Unknown' or result['target'] != 'Unknown':
            confidence = 0.7
        
        result['confidence'] = confidence
        
        return result
    
    def get_file_transfer_commands(self):
        return self._filter_commands_by_subcategory('file_transfer')
    
    def get_data_encoding_commands(self):
        return self._filter_commands_by_subcategory('encoding')
    
    def get_compression_commands(self):
        return self._filter_commands_by_subcategory('compression')
    
    def get_network_exfiltration_commands(self):
        return self._filter_commands_by_subcategory('network_transfer')
    
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
        # comenzile de exfiltrare date au in general severitate ridicata
        # severitatea implicita
        severity = 8
        
        # pattern-uri cu severitate critica (9-10)
        critical_patterns = [
            r'nc\s+(\S+)\s+(\d+)\s*<\s*(/etc/passwd|/etc/shadow|\S*password\S*|\S*secret\S*|\S*credential\S*)',
            r'cat\s+(/etc/passwd|/etc/shadow|\S*password\S*|\S*secret\S*|\S*credential\S*)\s*\|\s*base64',
            r'scp\s+(/etc/passwd|/etc/shadow|\S*password\S*|\S*secret\S*|\S*credential\S*)',
            r'tar\s+.*(/etc/passwd|/etc/shadow|\S*password\S*|\S*secret\S*|\S*credential\S*)',
            r'zip\s+.*(/etc/passwd|/etc/shadow|\S*password\S*|\S*secret\S*|\S*credential\S*)',
            r'for\s+.*\s*dig\s+.*\S+\.\S+',
            r'mail\s+.*(\S+@\S+)\s*<\s*(/etc/passwd|/etc/shadow|\S*password\S*)'
        ]
        
        # verificam pattern-urile critice (exfiltrare date sensibile)
        for pattern in critical_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 10  # severitate maxima pentru exfiltrarea datelor sensibile
        
        # pattern-uri cu severitate ridicata (8-9)
        high_patterns = [
            r'nc\s+(\S+)\s+(\d+)\s*<\s*(\S+)',
            r'curl\s+.*(-T|--upload-file)\s+(\S+)',
            r'wget\s+.*--post-file=(\S+)',
            r'ssh\s+(\S+@\S+)\s+.*\s*cat\s+',
            r'scp\s+(\S+)\s+(\S+@\S+):(\S+)',
            r'rsync\s+(-[a-zA-Z]+\s+)?(\S+)\s+(\S+@\S+):(\S+)',
            r'tar\s+.*\s*\|\s*nc\s+',
            r'cat\s+\S+\s*\|\s*base64\s*\|\s*(nc|curl|ssh)'
        ]
        
        # verificam pattern-urile cu severitate ridicata
        for pattern in high_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 9
        
        # pattern-uri cu severitate medie (7)
        medium_patterns = [
            r'base64\s+(\S+)',
            r'cat\s+(\S+)\s*\|\s*base64',
            r'zip\s+(-[a-zA-Z0-9]+\s+)?(\S+)\s+(\S+)',
            r'tar\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'ftp\s+(\S+)',
            r'sftp\s+(\S+@\S+)',
            r'mail\s+(\S+@\S+)',
            r'hexdump\s+(\S+)'
        ]
        
        # verificam pattern-urile cu severitate medie
        for pattern in medium_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 7
        
        # pattern-uri cu severitate scazuta (5-6)
        low_patterns = [
            r'dig\s+(\S+)\.(\S+)',
            r'host\s+(\S+)\.(\S+)',
            r'xclip\s+(\S+)',
            r'pbcopy\s+(\S+)',
            r'iconv\s+(\S+)'
        ]
        
        # verificam pattern-urile cu severitate scazuta
        for pattern in low_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return 6
        
        return severity