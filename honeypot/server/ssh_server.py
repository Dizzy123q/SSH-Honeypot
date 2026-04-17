#!/usr/bin/env python3

import socket
import threading
import logging
import paramiko
from pathlib import Path
from honeypot.config import CONFIG
from honeypot.server.shell_handler import SSHHoneypot, interactive_shell_session

# Asigură-te că directoarele necesare există
Path('logs').mkdir(exist_ok=True)
Path('keys').mkdir(exist_ok=True)

# Configurare logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('honeypot')

# Variabile globale pentru limitarea conexiunilor
active_connections = 0
connection_lock = threading.Lock()

def get_max_connections():
    """Obține numărul maxim de conexiuni din configurație"""
    return CONFIG.get('server', {}).get('max_connections', 50)

def increment_connections():
    """Incrementează counterul de conexiuni active"""
    global active_connections
    
    with connection_lock:
        active_connections += 1
        logger.info(f"Conexiuni active: {active_connections}/{get_max_connections()}")
        return active_connections

def decrement_connections():
    """Decrementează counterul de conexiuni active"""
    global active_connections
    
    with connection_lock:
        if active_connections > 0:
            active_connections -= 1
        logger.info(f"Conexiuni active: {active_connections}/{get_max_connections()}")

def get_active_connections():
    """Returnează numărul curent de conexiuni active"""
    global active_connections
    with connection_lock:
        return active_connections

def interactive_shell_session(transport, channel, ssh_server, client_address):
    """Gestionează sesiunea shell interactivă"""
    try:
        logger.info(f"Sesiune shell activă pentru {client_address[0]}")
        
        while True:
            if not channel.recv_ready():
                continue
                
            command = channel.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if not command:
                continue
                
            if command.lower() in ['exit', 'logout', 'quit']:
                channel.send("Connection closed by foreign host.\r\n")
                break
                
            # Logare comandă
            logger.info(f"Comandă de la {client_address[0]}: {command}")
            
            # Simulare răspuns
            if command == 'whoami':
                channel.send("root\r\n")
            elif command == 'pwd':
                channel.send("/root\r\n")
            elif command.startswith('ls'):
                channel.send("bin  boot  dev  etc  home  lib  root  tmp  usr  var\r\n")
            elif command == 'id':
                channel.send("uid=0(root) gid=0(root) groups=0(root)\r\n")
            else:
                channel.send(f"bash: {command}: command not found\r\n")
            
            channel.send("# ")
            
    except Exception as e:
        logger.error(f"Eroare în sesiunea shell pentru {client_address[0]}: {str(e)}")
    finally:
        logger.info(f"Sesiune shell închisă pentru {client_address[0]}")

def handle_client(client_socket, client_address):
    """Gestionează un client conectat"""
    
    # Verifică limita de conexiuni înainte de procesare
    current_count = increment_connections()
    max_conn = get_max_connections()
    
    if current_count > max_conn:
        logger.warning(f"Conexiune refuzată de la {client_address[0]} - limită atinsă ({current_count-1}/{max_conn})")
        decrement_connections()
        client_socket.close()
        return
    
    try:
        logger.info(f"Conexiune acceptată de la {client_address[0]}:{client_address[1]}")
        
        # Încărcarea cheii serverului
        key_path = Path('keys/ssh_host_rsa_key')
        if not key_path.exists():
            logger.error(f"Cheia serverului SSH nu există la: {key_path}")
            logger.info("Generez cheia SSH...")
            import subprocess
            subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', '2048', '-f', str(key_path), '-N', ''], check=True)
            logger.info("Cheia SSH generată cu succes")
            
        host_key = paramiko.RSAKey(filename=str(key_path))
        
        # Crearea transportului SSH
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        
        # Configurarea serverului SSH
        ssh_server = SSHHoneypot(client_address[0])
        transport.set_subsystem_handler('sftp', paramiko.SFTPServer)
        
        # Pornirea serverului SSH
        transport.start_server(server=ssh_server)
        
        # Așteptare canal
        channel = transport.accept(20)
        if channel is None:
            logger.warning(f"Nu s-a putut stabili canalul pentru {client_address[0]}")
            return
        
        # Așteptare cerere shell
        ssh_server.event.wait(10)
        if not ssh_server.event.is_set():
            logger.warning(f"Nu s-a cerut shell pentru {client_address[0]}")
            return
            
        # Continuă cu shell interactiv dacă containerul există
        if hasattr(ssh_server, 'container_id') and ssh_server.container_id:
            # Folosește funcția din shell_handler
            from honeypot.server.shell_handler import interactive_shell_session as shell_session
            shell_session(transport, channel, ssh_server, client_address)
        else:
            # Fallback - shell simplu
            interactive_shell_session(transport, channel, ssh_server, client_address)
        
    except Exception as e:
        logger.error(f"Eroare în gestionarea clientului {client_address[0]}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        # Decrementează counterul la sfârșit
        decrement_connections()
        
        logger.info(f"Închidere conexiune pentru {client_address[0]}")
        try:
            if 'transport' in locals():
                transport.close()
        except:
            pass

def main():
    """Funcția principală a serverului"""
    # Crearea socket-ului pentru server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Configurare din fișier
    host = CONFIG.get('server', {}).get('host', '0.0.0.0')
    port = CONFIG.get('server', {}).get('port', 2222)
    max_conn = get_max_connections()
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(20)  # Coadă de așteptare redusă
        
        logger.info(f"Server SSH Honeypot pornit pe {host}:{port}")
        logger.info(f"Limită conexiuni simultane: {max_conn}")
        
        # Acceptare conexiuni 
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                
                # Creează thread pentru client (verificarea limitei se face în handle_client)
                client_thread = threading.Thread(
                    target=handle_client, 
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                logger.error(f"Eroare la acceptarea conexiunii: {str(e)}")
            
    except Exception as e:
        logger.error(f"Eroare la pornirea serverului: {str(e)}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    logger.info("Inițializare SSH Honeypot cu limitare conexiuni")
    main()