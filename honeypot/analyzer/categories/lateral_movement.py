#!/usr/bin/env python3

import re
import logging
from ..common import normalize_command
from . import AttackCategory

logger = logging.getLogger('honeypot.analyzer.categories')

class LateralMovementCategory(AttackCategory):  
    def __init__(self):
        super().__init__(
            name="lateral_movement", 
            description="Detectarea tehnicilor de mișcare laterală în rețea"
        )
        
        # aici avem pattern-urile pentru detectarea miscarii laterale
        self.PATTERNS = {
            'ssh_connection': [
                r'ssh\s+(-[a-zA-Z0-9]*\s+)*\S+@\S+',
                r'ssh\s+(-[a-zA-Z0-9]*\s+)*(?:[0-9]{1,3}\.){3}[0-9]{1,3}',
                r'ssh\s+(-[a-zA-Z0-9]*\s+)*[a-zA-Z0-9_-]+',
                r'ssh-copy-id\s+\S+'
            ],
            'credential_harvesting': [
                r'find\s+/\s+-name\s+\.ssh',
                r'cat\s+.*\.ssh/.*',
                r'cat\s+/etc/passwd',
                r'cat\s+/etc/shadow',
                r'grep\s+-[a-zA-Z]*\s+pass',
                r'find\s+/\s+-name\s+\*config\*',
                r'find\s+/home\s+-name\s+\*\.(hist|bash_history)',
                r'cat\s+.*\.bash_history'
            ],
            'internal_network_scan': [
                r'ping\s+-[a-zA-Z]*c\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}',
                r'ping\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}',
                r'nmap\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}',
                r'nmap\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}',
                r'for.*?ping.*?(?:[0-9]{1,3}\.){3}[0-9]{1,3}',
                r'nc\s+-[a-zA-Z]*v\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+[0-9]{1,5}',
                r'telnet\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+[0-9]{1,5}'
            ],
            'remote_access_tools': [
                r'rdesktop\s+\S+',
                r'xfreerdp\s+\S+',
                r'vnc\S*\s+\S+',
                r'remmina\s+\S+',
                r'ssh\s+-[a-zA-Z]*L',
                r'ssh\s+-[a-zA-Z]*R',
                r'ssh\s+-[a-zA-Z]*D',
                r'proxychains\s+\S+'
            ],
            'pivoting': [
                r'proxy\S*\s+\S+',
                r'socat\s+\S+',
                r'chisel\s+\S+',
                r'sshuttle\s+\S+',
                r'ssh\s+-[a-zA-Z]*[fNnTW]'
            ]
        }
    
    def match(self, command):
        try:
            # vedem fiecare categorie de pattern-uri
            for category, patterns in self.PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, command, re.IGNORECASE):
                        logger.debug(f"Comandă de mișcare laterală detectată: {command} (pattern: {pattern})")
                        return True
            
            return False
        except Exception as e:
            logger.error(f"Eroare la verificarea comenzii pentru mișcare laterală: {str(e)}")
            return False
    
    def analyze_lateral_movement_technique(self, command):
        result = {
            'type': 'unknown',
            'target': None,
            'protocol': None,
            'description': None
        }
        
        try:
            # cautam sa vedem ce tip de miscare laterala e
            if any(re.search(pattern, command, re.IGNORECASE) for pattern in self.PATTERNS['ssh_connection']):
                result['type'] = 'ssh_connection'
                result['protocol'] = 'ssh'
                
                # scoatem tinta conexiunii ssh
                ssh_match = re.search(r'ssh\s+(?:-[a-zA-Z0-9]*\s+)*(?:([a-zA-Z0-9_-]+)@)?([a-zA-Z0-9_.-]+|\d+\.\d+\.\d+\.\d+)', command)
                if ssh_match:
                    if ssh_match.group(1):  # avem un username
                        result['username'] = ssh_match.group(1)
                    result['target'] = ssh_match.group(2)
                    result['description'] = f"Conexiune SSH către {result['target']}"
                
            elif any(re.search(pattern, command, re.IGNORECASE) for pattern in self.PATTERNS['credential_harvesting']):
                result['type'] = 'credential_harvesting'
                
                if 'find' in command and '.ssh' in command:
                    result['description'] = "Căutare fișiere SSH"
                    result['target'] = "SSH keys"
                elif 'cat' in command and '.ssh' in command:
                    result['description'] = "Accesare fișiere SSH"
                    result['target'] = "SSH keys"
                elif '/etc/passwd' in command:
                    result['description'] = "Accesare listă utilizatori"
                    result['target'] = "User accounts"
                elif '/etc/shadow' in command:
                    result['description'] = "Accesare hash-uri parole"
                    result['target'] = "Password hashes"
                elif 'history' in command:
                    result['description'] = "Accesare istoric comenzi"
                    result['target'] = "Command history"
                else:
                    result['description'] = "Colectare credențiale"
            
            elif any(re.search(pattern, command, re.IGNORECASE) for pattern in self.PATTERNS['internal_network_scan']):
                result['type'] = 'internal_network_scan'
                
                # scoatem tinta scanarii
                ip_match = re.search(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?)', command)
                if ip_match:
                    result['target'] = ip_match.group(1)
                    
                if 'nmap' in command:
                    result['protocol'] = 'nmap'
                    result['description'] = f"Scanare porturi cu nmap către {result['target'] if result['target'] else 'rețeaua internă'}"
                elif 'ping' in command:
                    result['protocol'] = 'icmp'
                    result['description'] = f"Verificare disponibilitate host {result['target'] if result['target'] else 'în rețeaua internă'}"
                elif 'nc' in command or 'telnet' in command:
                    result['protocol'] = 'tcp' if 'nc' in command else 'telnet'
                    port_match = re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+([0-9]{1,5})', command)
                    if port_match:
                        result['port'] = port_match.group(1)
                        result['description'] = f"Verificare port {result['port']} pe {result['target'] if result['target'] else 'host'}"
            
            elif any(re.search(pattern, command, re.IGNORECASE) for pattern in self.PATTERNS['remote_access_tools']):
                result['type'] = 'remote_access'
                
                if 'rdesktop' in command or 'xfreerdp' in command:
                    result['protocol'] = 'rdp'
                    result['description'] = "Conexiune Remote Desktop"
                elif 'vnc' in command:
                    result['protocol'] = 'vnc'
                    result['description'] = "Conexiune VNC"
                elif 'ssh -L' in command:
                    result['protocol'] = 'ssh_local_forward'
                    result['description'] = "Tunnel SSH cu forwarding local"
                elif 'ssh -R' in command:
                    result['protocol'] = 'ssh_remote_forward'
                    result['description'] = "Tunnel SSH cu forwarding remote"
                elif 'ssh -D' in command:
                    result['protocol'] = 'ssh_dynamic_forward'
                    result['description'] = "Proxy SOCKS via SSH"
                elif 'proxychains' in command:
                    result['protocol'] = 'proxy'
                    result['description'] = "Rulare comandă prin proxy chain"
                    
                # scoatem tinta din comanda
                host_match = re.search(r'(?:vnc\S*|rdesktop|xfreerdp|remmina)\s+([a-zA-Z0-9_.-]+|\d+\.\d+\.\d+\.\d+)', command)
                if host_match:
                    result['target'] = host_match.group(1)
            
            elif any(re.search(pattern, command, re.IGNORECASE) for pattern in self.PATTERNS['pivoting']):
                result['type'] = 'pivoting'
                
                if 'socat' in command:
                    result['protocol'] = 'socat'
                    result['description'] = "Redirecționare port cu socat"
                elif 'chisel' in command:
                    result['protocol'] = 'chisel'
                    result['description'] = "Tunel TCP cu chisel"
                elif 'sshuttle' in command:
                    result['protocol'] = 'sshuttle'
                    result['description'] = "VPN transparent cu sshuttle"
                else:
                    result['description'] = "Tehnică de pivotare în rețea"
            
            return result
        
        except Exception as e:
            logger.error(f"Eroare la analiza tehnicii de mișcare laterală: {str(e)}")
            return result
    
    def get_ssh_connection_attempts(self, commands):
        ssh_commands = []
        
        try:
            for cmd in commands:
                if any(re.search(pattern, cmd, re.IGNORECASE) for pattern in self.PATTERNS['ssh_connection']):
                    ssh_commands.append(cmd)
            
            return ssh_commands
        
        except Exception as e:
            logger.error(f"Eroare la obținerea încercărilor de conexiune SSH: {str(e)}")
            return ssh_commands
    
    def get_credential_harvesting_attempts(self, commands):
        harvest_commands = []
        
        try:
            for cmd in commands:
                if any(re.search(pattern, cmd, re.IGNORECASE) for pattern in self.PATTERNS['credential_harvesting']):
                    harvest_commands.append(cmd)
            
            return harvest_commands
        
        except Exception as e:
            logger.error(f"Eroare la obținerea încercărilor de colectare credențiale: {str(e)}")
            return harvest_commands
    
    def get_internal_network_scan_attempts(self, commands):
        scan_commands = []
        
        try:
            for cmd in commands:
                if any(re.search(pattern, cmd, re.IGNORECASE) for pattern in self.PATTERNS['internal_network_scan']):
                    scan_commands.append(cmd)
            
            return scan_commands
        
        except Exception as e:
            logger.error(f"Eroare la obținerea încercărilor de scanare a rețelei interne: {str(e)}")
            return scan_commands
    
    def get_severity(self, command):
        try:
            # scor initial
            severity = 5
            
            # analizam tehnica de miscare laterala
            movement_info = self.analyze_lateral_movement_technique(command)
            
            # ajustam scorul in functie de tipul de tehnica
            if movement_info['type'] == 'ssh_connection':
                severity += 2  # conexiunile ssh sunt comune in atacuri
                
                # vedem daca sunt utilizatori privilegiati
                if movement_info.get('username') in ['root', 'admin', 'administrator']:
                    severity += 1
            
            elif movement_info['type'] == 'credential_harvesting':
                severity += 3  # colectarea de credentiale e un pas critic in atacuri
                
                # daca se acceseaza shadow, e foarte grav
                if '/etc/shadow' in command:
                    severity += 2
            
            elif movement_info['type'] == 'internal_network_scan':
                # scanarile sunt periculoase doar daca sunt extensive
                if 'nmap' in command:
                    severity += 2
                elif 'for' in command and 'ping' in command:  # loop de ping
                    severity += 1
            
            elif movement_info['type'] == 'remote_access':
                severity += 2  # acces remote pe alte masini
                
                # forwarding de porturi e mai grav
                if movement_info['protocol'] in ['ssh_remote_forward', 'ssh_dynamic_forward']:
                    severity += 2
            
            elif movement_info['type'] == 'pivoting':
                severity += 3  # pivotarea e o tehnica avansata
                
                # tunneling mai complex e mai grav
                if movement_info['protocol'] in ['sshuttle', 'chisel']:
                    severity += 1
            
            # vedem daca sunt adrese ip sau subneturi multiple
            ip_count = len(re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', command))
            if ip_count > 1:
                severity += min(ip_count - 1, 3)  # maxim +3 pentru multi-target
            
            # vedem daca sunt combinatii de tehnici
            technique_count = 0
            for category in self.PATTERNS:
                if any(re.search(pattern, command, re.IGNORECASE) for pattern in self.PATTERNS[category]):
                    technique_count += 1
            
            if technique_count > 1:
                severity += 1  # combinarea tehnicilor indica un atac avansat
            
            # limitam scorul la 1-10
            return max(1, min(severity, 10))
            
        except Exception as e:
            logger.error(f"Eroare la calcularea severității pentru mișcare laterală: {str(e)}")
            return 5  # valoare implicita in caz de eroare