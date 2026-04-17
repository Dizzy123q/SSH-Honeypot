#!/usr/bin/env python3

import os
import logging
import threading
import datetime
import time
import socket
import paramiko
import docker
from pathlib import Path

from ..config import CONFIG
from ..container_manager import ContainerManager
from ..session_logger import SessionLogger
from .scp_handler import _capture_scp_upload, _handle_scp_download, _capture_general_data

logger = logging.getLogger('honeypot')

class SSHHoneypot(paramiko.ServerInterface):
    
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.container_manager = ContainerManager()
        self.container_id = None
        self.session_logger = None
        self.username = None
        self.event = threading.Event()
        self.monitored_files = CONFIG.get('monitored_files', [])
        
    def check_auth_password(self, username, password):
        self.username = username
        logger.info(f"Încercare de autentificare: {self.client_ip} - Username: {username}, Password: {password}")
        
        # verifica credentialele
        valid_login = False
        for cred in CONFIG.get('valid_credentials', []):
            if cred['username'] == username and cred['password'] == password:
                valid_login = True
                break
        
        if not valid_login:
            logger.warning(f"Autentificare eșuată: {self.client_ip} - Username: {username}")
            return paramiko.AUTH_FAILED
        
        # continua cu crearea containerului doar daca autentificarea a reusit
        container_name = f"honeypot-{self.client_ip.replace('.', '-')}-{int(time.time())}"
        self.container_id = self.container_manager.create_container(container_name)
        
        if not self.container_id:
            logger.error(f"Nu s-a putut crea containerul pentru {self.client_ip}")
            return paramiko.AUTH_FAILED
        
        # initializare logger pentru sesiune
        log_filename = f"{self.client_ip}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.log"
        self.session_logger = SessionLogger(self.client_ip, log_filename, self.container_id)
        
        logger.info(f"Container creat pentru {self.client_ip}: {self.container_id}")
        logger.info(f"Autentificare reușită: {self.client_ip} - Username: {username}")
        return paramiko.AUTH_SUCCESSFUL
        
    def check_channel_request(self, kind, chanid):
        logger.info(f"Cerere canal de la {self.client_ip}: {kind}")
        return paramiko.OPEN_SUCCEEDED
    
    def check_channel_shell_request(self, channel):
        logger.info(f"Cerere shell de la {self.client_ip}")
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        logger.info(f"Cerere PTY de la {self.client_ip}: {term} {width}x{height}")
        return True
    
    def check_channel_exec_request(self, channel, command):
        cmd_str = command.decode('utf-8')
        logger.info(f"Cerere exec de la {self.client_ip}: {cmd_str}")
        
        if self.session_logger:
            # detectam transferul de fisiere inainte de logare
            transfer_keywords = ['scp ', 'rsync ']
            is_transfer = any(keyword in cmd_str for keyword in transfer_keywords)
            
            # logam doar daca nu este transfer
            if not is_transfer:
                self.session_logger.log_command(cmd_str)
            
            # verificam daca este transfer
            if is_transfer:
                logger.info(f"Comandă de transfer fișiere detectată: {cmd_str}")
                
                # creare director pentru carantina
                quarantine_dir = Path(CONFIG.get('quarantine_dir', '../quarantine'))
                session_dir = quarantine_dir / f"{self.client_ip}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_transfer"
                
                # tratam special comenzile SCP
                if 'scp ' in cmd_str:
                    if ' -t ' in cmd_str:  # Upload
                        threading.Thread(target=_capture_scp_upload, 
                                        args=(channel, session_dir, self.session_logger)).start()
                        return True
                    elif ' -f ' in cmd_str:  # Download
                        threading.Thread(target=_handle_scp_download, 
                                        args=(channel, session_dir, self.session_logger)).start()
                        return True
                
                # pentru orice alta comanda de transfer, capturam datele
                threading.Thread(target=_capture_general_data, 
                                args=(channel, session_dir, self.session_logger)).start()
                return True
            
            # verificam fisierele capcana
            for monitored_file in self.monitored_files:
                if monitored_file in cmd_str:
                    logger.warning(f"Fișier capcană accesat de {self.client_ip}: {monitored_file}")
                    self.session_logger.log_trap_accessed(monitored_file)
                    
                    # executam comanda si apoi terminam sesiunea
                    output = self.container_manager.exec_command(self.container_id, cmd_str)
                    if output:
                        channel.send(output.encode('utf-8'))
                    
                    # terminam sesiunea dupa o mica intarziere
                    threading.Timer(2.0, self.terminate_session, args=[channel]).start()
                    return True
            
            # pentru comenzi normale, le executam în container
            output = self.container_manager.exec_command(self.container_id, cmd_str)
            if output:
                channel.send(output.encode('utf-8'))
            channel.send_exit_status(0)
            
        return True
    
    def terminate_session(self, channel):
        logger.info(f"Terminare sesiune pentru {self.client_ip} după accesarea fișierului capcană")
        
        # colecteaza informatii despre atacator inainte de terminare
        if self.session_logger:
            self.session_logger.log_attacker_info()
        
        # trimite mesaj de eroare si inchide canalul
        error_msg = "Connection reset by peer\r\n"
        try:
            channel.send(error_msg.encode('utf-8'))
            channel.close()
        except:
            pass
        
        # opreste containerul dupa o scurta intarziere
        if self.container_id:
            threading.Timer(1.0, self.container_manager.stop_container, args=[self.container_id]).start()
    
    def get_allowed_auths(self, username):
        return 'password'

def setup_container_environment(ssh_server):
    # obtine hostname-ul din container
    hostname = ssh_server.container_manager.exec_command(
        ssh_server.container_id, 
        "/bin/hostname"
    ).strip()
    
    return hostname or "srv-web-03"

def send_welcome_message(channel, ssh_server):
    # foloseste un mesaj implicit
    welcome_cmd = "cat /etc/motd 2>/dev/null || echo 'Debian GNU/Linux 12 (bookworm)'"
    welcome = ssh_server.container_manager.exec_command(ssh_server.container_id, welcome_cmd)
    
    if not welcome:
        welcome = "Debian GNU/Linux 12 (bookworm)"
    
    channel.send(welcome.encode('utf-8') + b"\r\n\r\n")

def execute_command(ssh_server, command, channel, client_address):
    # adaugam informatii despre sesiunea curenta
    current_ip = client_address[0]
    current_container = ssh_server.container_id[:12]
    
    # verificam daca comanda acceseaza fisiere monitorizate
    for monitored_file in ssh_server.monitored_files:
        if monitored_file in command:
            logger.warning(f"Fișier capcană accesat de {current_ip} (Container: {current_container}): {monitored_file}")
            ssh_server.session_logger.log_trap_accessed(monitored_file, command=command)
            
            # executam comanda pentru a parea natural
            cmd_output = ssh_server.container_manager.exec_command(
                ssh_server.container_id, 
                command
            )
            
            if cmd_output and channel.active:
                try:
                    channel.send(cmd_output.encode('utf-8') + b"\r\n")
                except Exception:
                    pass
            
            # termina sesiunea dupa o mica intarziere
            threading.Timer(2.0, ssh_server.terminate_session, args=[channel]).start()
            return True
    
    # executam comanda normala
    cmd_output = ssh_server.container_manager.exec_command(
        ssh_server.container_id, 
        command
    )
    
    if cmd_output and channel.active:
        try:
            channel.send(cmd_output.encode('utf-8') + b"\r\n")
        except Exception:
            pass
    
    return False

def filtreaza_secvente_control(text):
    import re
    
    # elimina secventele bracketed paste
    text = re.sub(r'\[200~|\[201~', '', text)
    
    # elimina secventele de control cursor
    text = re.sub(r'\[[ABCD]', '', text)
    
    # elimina secventele de deplasare complexe
    text = re.sub(r'\[[ABCD](\[[ABCD])+', '', text)
    
    # elimina alte secvente ANSI comune
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    
    return text.strip()

def monitor_bash_history(ssh_server, client_address):
    # monitorizeaza comenzile prin .bash_history - toate comenzile inclusiv duplicate
    import subprocess
    import time
    
    current_ip = client_address[0]
    container_id = ssh_server.container_id
    
    # determina fisierul de istoric
    history_file = '/root/.bash_history' if ssh_server.username == 'root' else f'/home/{ssh_server.username}/.bash_history'
    
    # obtine numarul de linii initiale
    last_line_count = 0
    try:
        result = subprocess.run(
            ['docker', 'exec', container_id, 'wc', '-l', history_file],
            capture_output=True, text=True, check=False
        )
        
        if result.returncode == 0:
            last_line_count = int(result.stdout.strip().split()[0])
            logger.info(f"Istoric inițial ignorat: {last_line_count} linii preexistente")
    except Exception as e:
        logger.error(f"Eroare la citirea istoricului inițial: {str(e)}")
    
    # monitorizeaza crescerea fisierului
    while True:
        try:
            # verifica numarul curent de linii
            result = subprocess.run(
                ['docker', 'exec', container_id, 'wc', '-l', history_file],
                capture_output=True, text=True, check=False
            )
            
            if result.returncode == 0:
                current_line_count = int(result.stdout.strip().split()[0])
                
                # daca au fost adaugate linii noi
                if current_line_count > last_line_count:
                    # Citeste doar liniile noi
                    lines_to_read = current_line_count - last_line_count
                    result = subprocess.run(
                        ['docker', 'exec', container_id, 'tail', f'-{lines_to_read}', history_file],
                        capture_output=True, text=True, check=False
                    )
                    
                    if result.returncode == 0:
                        new_lines = result.stdout.strip().split('\n')
                        
                        # proceseaza toate liniile noi
                        for line in new_lines:
                            if line:  # ignora liniile goale
                                # comanda noua gasita
                                logger.info(f"Comandă executată de {current_ip}: {line}")
                                
                                # verifica fisierele capcana
                                for monitored_file in ssh_server.monitored_files:
                                    if monitored_file in line:
                                        logger.warning(f"Fișier capcană accesat: {monitored_file}")
                                        ssh_server.session_logger.log_trap_accessed(monitored_file, command=line)
                                
                                # logam comanda
                                ssh_server.session_logger.log_command(line)
                    
                    # actualizeaza pozitia
                    last_line_count = current_line_count
            
            time.sleep(0.5)  # verifica de 2 ori pe secunda
            
        except Exception as e:
            logger.error(f"Eroare monitorizare istoric: {str(e)}")
            time.sleep(2)

def interactive_shell_session(transport, channel, ssh_server, client_address):
    try:
        logger.info(f"Shell interactiv stabilit pentru {client_address[0]}")
        
        import subprocess
        import select
        import fcntl
        import os
        import pty
        import threading
        
        # bash history este deja configurat în Dockerfile nu mai trebuie setup
        
        # determină directorul home corect in functie de utilizator
        home_dir = '/root' if ssh_server.username == 'root' else f'/home/{ssh_server.username}'
        
        # cream un pseudo-TTY pentru o experienta mai buna
        master, slave = pty.openpty()
    
        # porneste un shell in container cu alocarea unui TTY
        process = subprocess.Popen(
            ['docker', 'exec', '-it', '-u', ssh_server.username, 
             '-w', home_dir,
             ssh_server.container_id, 
             '/bin/bash', '-i'],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=os.setsid,
            close_fds=True
        )
        
        # inchidem slave fd in procesul parinte
        os.close(slave)
        
        # setam master ca non-blocking
        fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
        
        # porneste monitorizarea istoricului in thread separat
        monitor_thread = threading.Thread(
            target=monitor_bash_history, 
            args=(ssh_server, client_address)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # bucla principala de comunicare
        while True:
            # setam canalele pentru select
            readable, _, _ = select.select([channel, master], [], [], 0.1)
            
            # date de la clientul SSH catre container
            if channel in readable:
                data = channel.recv(1024)
                if not data:
                    # conexiunea SSH s-a inchis
                    break
                
                # Trimite datele către container (fără logging aici)
                os.write(master, data)
            
            # date de la container catre clientul SSH
            if master in readable:
                try:
                    output = os.read(master, 1024)
                    if output:
                        channel.send(output)
                except:
                    pass
            
            # verificare daca procesul s-a incheiat
            if process.poll() is not None:
                break
        
    except Exception as e:
        logger.error(f"Eroare în gestionarea shell-ului interactiv: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        # curatare
        if 'process' in locals() and process.poll() is None:
            try:
                process.terminate()
            except:
                pass
        
        if 'master' in locals():
            try:
                os.close(master)
            except:
                pass
        
        cleanup_session(ssh_server)
        
def cleanup_session(ssh_server):
    # colecteaza informatii despre atacator inainte de terminare
    if ssh_server and ssh_server.session_logger:
        ssh_server.session_logger.log_attacker_info()
    
    # opreste containerul
    if ssh_server and ssh_server.container_id:
        ssh_server.container_manager.stop_container(ssh_server.container_id)