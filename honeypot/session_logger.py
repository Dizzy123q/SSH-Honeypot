import os
import logging
import datetime
import json
import subprocess
import socket
import re
import requests
import ipaddress
from pathlib import Path
from .config import CONFIG

logger = logging.getLogger('honeypot')

class SessionLogger:
    
    def __init__(self, client_ip, log_filename, container_id):
        self.client_ip = client_ip
        self.container_id = container_id
        self.start_time = datetime.datetime.now()
        
        # creeaza directorul pentru loguri
        self.log_dir = Path(CONFIG.get('logs_dir', '../logs'))
        self.log_dir.mkdir(exist_ok=True)
        
        # creeaza directorul pentru carantina
        self.quarantine_dir = Path(CONFIG.get('quarantine_dir', '../quarantine'))
        self.quarantine_dir.mkdir(exist_ok=True)
        
        # fisierul de log pentru aceasta sesiune
        self.log_file = self.log_dir / log_filename
        
        # initializam jurnalul sesiunii
        self.session_log = {
            'client_ip': client_ip,
            'container_id': container_id,
            'start_time': self.start_time.isoformat(),
            'commands': [],
            'uploaded_files': [],
            'trap_files_accessed': [],
            'attacker_info': {}
        }
        
        # scriem header-ul in fisierul de log
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(f"=== SSH Honeypot Session Log ===\n")
            f.write(f"Client IP: {client_ip}\n")
            f.write(f"Container ID: {container_id}\n")
            f.write(f"Start Time: {self.start_time}\n")
            f.write(f"=================================\n\n")
        
        logger.info(f"Sesiune înregistrată inițializată pentru {client_ip} în {log_filename}")
        
        # incearca sa obtina informatii initiale despre atacator
        self._get_initial_attacker_info()
    
    def _get_initial_attacker_info(self):
        try:
            # informatii de baza
            hostname = None
            try:
                hostname = socket.gethostbyaddr(self.client_ip)[0]
            except:
                hostname = "Unknown"
            
            # verifica daca este o adresa ip locala
            is_local_ip = False
            try:
                ip_obj = ipaddress.ip_address(self.client_ip)
                is_local_ip = ip_obj.is_private or ip_obj.is_loopback
            except:
                pass
            
            # informatii initiale despre atacator
            attacker_info = {
                'ip': self.client_ip,
                'hostname': hostname
            }
            
            # verifica daca este activata colectarea de informatii geografice
            if CONFIG.get('enable_geo_ip', False) and not is_local_ip:
                try:
                    # incercam ipinfo.io
                    response = requests.get(f"https://ipinfo.io/{self.client_ip}/json", timeout=3)
                    if response.status_code == 200:
                        geo_data = response.json()
                        attacker_info.update({
                            'country': geo_data.get('country', 'Unknown'),
                            'region': geo_data.get('region', 'Unknown'),
                            'city': geo_data.get('city', 'Unknown'),
                            'org': geo_data.get('org', 'Unknown'),
                            'location': geo_data.get('loc', 'Unknown')
                        })
                except Exception as e:
                    logger.warning(f"Nu s-au putut obține informații geografice: {str(e)}")
            
            # memoreaza informatiile in jurnalul sesiunii
            self.session_log['attacker_info'] = attacker_info
            
            # inregistreaza informatiile în log
            with open(self.log_file, 'a') as f:
                f.write(f"Attacker Info:\n")
                for key, value in self.session_log['attacker_info'].items():
                    f.write(f"  {key}: {value}\n")
                f.write("\n")
            
        except Exception as e:
            logger.error(f"Eroare la obținerea informațiilor despre atacator {self.client_ip}: {str(e)}")
            # setăm ip-ul
            self.session_log['attacker_info'] = {'ip': self.client_ip}
    
    def _sanitize_for_log(self, text):
        # sanitizeaza text pentru a fi sigur să scrie în log
        if not text:
            return ""
        
        # incearca sa decodeze daca e bytes
        if isinstance(text, bytes):
            try:
                text = text.decode('utf-8', errors='replace')
            except:
                text = str(text)
        
        # curata caracterele problematice
        text = str(text).strip()
        
        # elimina caractere de control periculoase
        forbidden_chars = ['\x00', '\x08', '\x0b', '\x0c', '\x0e', '\x0f']
        for char in forbidden_chars:
            text = text.replace(char, '')
        
        # limiteaza lungimea
        if len(text) > 2000:
            text = text[:1997] + "..."
        
        return text

    def _clean_command(self, command):
        # curata comanda de caractere nedorite
        if not command:
            return ""
        
        # Elimina caractere de control si caractere speciale problematice
        cleaned = command.strip()
        
        # elimina backticks de la sfarsit
        cleaned = cleaned.rstrip('`')
        
        # elimina caractere de control
        cleaned = cleaned.replace('\n', '').replace('\t', ' ').replace('\r', '')
        
        # inlocuieste caractere non-printabile cu spatiu
        cleaned = ''.join(char if char.isprintable() or char.isspace() else ' ' for char in cleaned)
        
        # elimina spatiile multiple
        cleaned = ' '.join(cleaned.split())
        
        return cleaned

    def log_command(self, command):
        timestamp = datetime.datetime.now().isoformat()
        
        # curata comanda de caractere ciudate
        cleaned_command = self._clean_command(command)
        
        # inregistreaza comanda in jurnalul sesiunii
        cmd_entry = {
            'timestamp': timestamp,
            'command': cleaned_command
        }
        self.session_log['commands'].append(cmd_entry)
        
        # scrie comanda in fisierul de log cu encoding explicit
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] Command: {cleaned_command}\n")
        
        logger.info(f"Comandă înregistrată de la {self.client_ip}: {cleaned_command}")
        
        # verifica daca comanda incearca sa incarce un fisier
        self._check_file_upload(cleaned_command)
    
    def _check_file_upload(self, command):
        # Patternuri comune pentru upload de fisiere
        upload_patterns = [
            r'wget\s+(https?://\S+)',
            r'curl\s+.*\s+-o\s+(\S+)\s+(https?://\S+)',
            r'curl\s+.*\s+(https?://\S+)\s+.*-o\s+(\S+)',
            r'scp\s+(\S+)\s+(\S+@\S+):(\S+)'
        ]
        
        for pattern in upload_patterns:
            match = re.search(pattern, command)
            if match:
                # am detectat o posibila incercare de upload
                logger.warning(f"Posibilă încercare de upload detectată de la {self.client_ip}: {command}")
                
                # salveaza informatiile despre incercare
                upload_info = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'command': command,
                    'pattern_matched': pattern
                }
                
                self.session_log['uploaded_files'].append(upload_info)
                
                # inregistreaza in fisierul de log
                with open(self.log_file, 'a') as f:
                    f.write(f"[{upload_info['timestamp']}] Încercare upload: {command}\n")
                
                # in situatia wget sau curl, incercam sa obținem fisierul pentru carantina
                if 'wget' in command or 'curl' in command:
                    url = match.group(1)
                    filename = url.split('/')[-1]
                    
                    # creaza un subdirector specific pentru aceasta sesiune in carantina
                    quarantine_subdir = self.quarantine_dir / f"{self.client_ip}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    quarantine_subdir.mkdir(exist_ok=True)
                    
                    # incearca sa descarce fisierul direct în carantina
                    try:
                        download_cmd = ['curl', '-L', '-s', '-o', str(quarantine_subdir / filename), url]
                        subprocess.run(download_cmd, timeout=30)
                        logger.info(f"Fișier descărcat în carantină: {url} -> {quarantine_subdir / filename}")
                    except Exception as e:
                        logger.error(f"Eroare la descărcarea fișierului {url}: {str(e)}")
    
    def log_trap_accessed(self, filename, command=None):
        timestamp = datetime.datetime.now().isoformat()
        
        # inregistreaza in jurnalul sesiunii
        trap_entry = {
            'timestamp': timestamp,
            'filename': filename
        }
        
        # adauga comanda daca este furnizata
        if command:
            trap_entry['command'] = command
            
        self.session_log['trap_files_accessed'].append(trap_entry)
        
        # scrie in fisierul de log
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] ALERT: Fișier capcană accesat: {filename}\n")
            if command:
                f.write(f"  Comandă: {command}\n")
        
        logger.warning(f"Fișier capcană accesat de {self.client_ip}: {filename}")
    
    def log_attacker_info(self):
        timestamp = datetime.datetime.now().isoformat()
        
        # obtine informatii suplimentare despre sesiune
        duration = datetime.datetime.now() - self.start_time
        self.session_log['duration'] = str(duration)
        self.session_log['end_time'] = timestamp
        
        # adauga informatii despre comenzile executate
        command_count = len(self.session_log['commands'])
        self.session_log['command_count'] = command_count
        
        # scrie un sumar in fisierul de log
        with open(self.log_file, 'a') as f:
            f.write(f"\n=== Session Summary ===\n")
            f.write(f"End Time: {timestamp}\n")
            f.write(f"Duration: {duration}\n")
            f.write(f"Total Commands: {command_count}\n")
            f.write(f"Trap Files Accessed: {len(self.session_log['trap_files_accessed'])}\n")
            f.write(f"Files Uploaded: {len(self.session_log['uploaded_files'])}\n")
            
            # listeaza fisierele capcana accesate
            if self.session_log['trap_files_accessed']:
                f.write(f"Trap Files List:\n")
                for trap in self.session_log['trap_files_accessed']:
                    f.write(f"  [{trap['timestamp']}] {trap['filename']}\n")
            
            f.write(f"=======================\n")
        
        logger.info(f"Sesiune finalizata pentru {self.client_ip}. Durată: {duration}, Comenzi: {command_count}")
        
        # notifica despre aceasta activitate
        if CONFIG.get('enable_notifications', False):
            self._send_notification()
    
   
    def save_uploaded_file(self, source_path, original_filename):
        # salveaza fisier încarcat folosind docker cp
        try:
            import subprocess
            
            # creeaza un subdirector specific pentru aceasta sesiune in carantina
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_subdir = self.quarantine_dir / f"{self.client_ip}_{timestamp}_upload"
            quarantine_subdir.mkdir(exist_ok=True, parents=True)
            
            # determina destinatia pe host
            dest_path = quarantine_subdir / original_filename
            
            if isinstance(source_path, bytes):
                with open(dest_path, 'wb') as f:
                    f.write(source_path)
                logger.info(f"Fișier salvat direct în carantină: {dest_path}")
            else:
                # fisierul e in container - folosim docker cp
                copy_cmd = ['docker', 'cp', f"{self.container_id}:{source_path}", str(dest_path)]
                process = subprocess.run(copy_cmd, capture_output=True, text=True)
                
                if process.returncode != 0:
                    logger.error(f"Eroare la copierea fișierului din container: {process.stderr}")
                    return None
                
                logger.info(f"Fișier încărcat salvat în carantină: {source_path} -> {dest_path}")
                
                # Opțional: șterge fișierul temporar din container
                if source_path.startswith('/tmp/'):
                    cleanup_cmd = ['docker', 'exec', self.container_id, 'rm', '-f', source_path]
                    subprocess.run(cleanup_cmd, check=False)
            
            # inregistreaza in jurnal
            upload_info = {
                'timestamp': datetime.datetime.now().isoformat(),
                'original_path': str(source_path),
                'filename': original_filename,
                'quarantine_path': str(dest_path)
            }
            
            self.session_log['uploaded_files'].append(upload_info)
            
            # inregistreaza in fisierul de log
            with open(self.log_file, 'a') as f:
                f.write(f"[{upload_info['timestamp']}] Fișier încărcat: {original_filename}\n")
                f.write(f"  Container path: {source_path}\n")
                f.write(f"  Quarantine: {dest_path}\n")
            
            return str(dest_path)
            
        except Exception as e:
            logger.error(f"Eroare la salvarea fișierului încărcat: {str(e)}")
            return None