#!/usr/bin/env python3

import logging
import time
import os
import datetime
from pathlib import Path
from ..config import CONFIG

logger = logging.getLogger('honeypot')

def _delete_transfer_log(session_logger):
    if session_logger and hasattr(session_logger, 'log_file'):
        try:
            import os
            log_path = str(session_logger.log_file)
            
            # verifica daca fisierul exista
            if os.path.exists(log_path):
                # incearca sa stearga direct
                os.remove(log_path)
                logger.info(f"Fișier log șters pentru transfer: {log_path}")
            else:
                logger.info(f"Fișierul log nu există deja: {log_path}")
                
        except Exception as e:
            logger.error(f"Eroare la ștergerea log-ului: {str(e)}")
            # incearca alternativ
            try:
                import subprocess
                subprocess.run(['rm', '-f', str(session_logger.log_file)], check=False)
                logger.info(f"Fișier log șters cu rm: {session_logger.log_file}")
            except:
                logger.error(f"Nu s-a putut șterge fișierul log: {session_logger.log_file}")

def _capture_scp_upload(channel, session_dir, session_logger):
    try:
        logger.info("Interceptare upload SCP direct în carantină")
        
        # 1. trimitem primul ACK
        channel.send(b'\0')
        
        # 2. asteptam si procesam fisierele
        while True:
            # primim header-ul fisierului
            header_data = b''
            while not header_data.endswith(b'\n'):
                chunk = channel.recv(1024)
                if not chunk:
                    logger.warning("Conexiune închisă în timpul primirii header-ului")
                    return
                header_data += chunk
                if len(header_data) > 1024:
                    break
            
            header = header_data.decode('utf-8', errors='replace').strip()
            logger.info(f"Header SCP: {header}")
            
            # verificam daca e un header de fisier
            if header.startswith('E'):
                logger.info("Terminare transfer SCP (E)")
                channel.send(b'\0')
                break
            
            if not header.startswith('C'):
                logger.error(f"Header SCP neașteptat: {header}")
                channel.send(b'\1')
                break
            
            # parsam header-ul
            parts = header[1:].strip().split(' ', 2)
            if len(parts) != 3:
                logger.error(f"Header SCP invalid: {header}")
                channel.send(b'\1')
                break
            
            mode_str, size_str, filename = parts
            size = int(size_str)
            
            logger.info(f"Interceptare fișier SCP: {filename}, size={size}")
            
            # trimitem ACK pentru header
            channel.send(b'\0')
            
            # salvare directa pe host in carantina
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            client_ip = session_logger.client_ip if session_logger else "unknown"
            transfer_filename = f"transfer_data_{client_ip}_{timestamp}_{filename}"
            
            # calea catre directorul de carantina pe host
            quarantine_dir = Path(CONFIG.get('quarantine_dir', '../quarantine'))
            quarantine_dir.mkdir(exist_ok=True)  # Creează directorul dacă nu există
            host_file_path = quarantine_dir / transfer_filename
            
            # primim continutul fisierului direct pe host
            with open(host_file_path, 'wb') as f:
                remaining = size
                while remaining > 0:
                    chunk_size = min(16384, remaining)
                    chunk = channel.recv(chunk_size)
                    if not chunk:
                        logger.error("Conexiune închisă în timpul primirii fișierului")
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
                    logger.debug(f"Salvat chunk de {len(chunk)} bytes, rămân {remaining}")
            
            # primim si ignoram byte-ul final
            final_byte = channel.recv(1)
            logger.debug(f"Byte final primit: {final_byte}")
            
            # trimitem ACK final pentru fișier
            channel.send(b'\0')
            
            logger.info(f"Fișier SCP salvat în carantină: {host_file_path} ({size} bytes)")
            
            # verifica daca fisierul a fost salvat corect
            if host_file_path.exists():
                actual_size = host_file_path.stat().st_size
                logger.info(f"Verificare: fișier salvat cu {actual_size} bytes (așteptat: {size})")
            else:
                logger.error(f"Fișierul nu a fost salvat: {host_file_path}")

            # sterge log-ul automat pentru transferuri
            try:
                import os
                log_path = str(session_logger.log_file)
                if os.path.exists(log_path):
                    os.remove(log_path)
                    logger.info(f"LOG ȘTERS AUTOMAT: {log_path}")
            except Exception as e:
                logger.error(f"Eroare ștergere log: {str(e)}")
        
        # transfer complet, trimitem status de succes
        channel.send_exit_status(0)
        
    except Exception as e:
        logger.error(f"Eroare în interceptarea SCP upload: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        try:
            channel.send(b'\1')
            channel.send_exit_status(1)
        except:
            pass


def _handle_scp_download(channel, session_dir, session_logger):
    try:
        logger.info("Simulare download SCP")
        
        # extragem filename din comanda
        filename = "dummy.txt"
        
        # Asteptam cererea clientului
        ack = channel.recv(1)
        
        # Continut fals
        content = b"This is a dummy file from the honeypot.\n"
        
        # trimitem header-ul fisierului
        channel.send(f"C0644 {len(content)} {filename}\n".encode('utf-8'))
        
        # Asteptam ACK
        ack = channel.recv(1)
        
        # trimitem continutul
        channel.send(content)
        
        # trimitem byte-ul final
        channel.send(b'\0')
        
        # Asteptam ACK final
        ack = channel.recv(1)
        
        # trimitem terminatorul 
        channel.send(b"E\n")
        
        # Asteptam confirmare pentru 
        try:
            ack = channel.recv(1)
        except:
            pass
            
        # logam in session logger
        if session_logger:
            pass
            # session_logger.log_command(f"SCP download: {filename}")
        
        logger.info(f"Download SCP simulat cu succes")
        
        # trimitem status de succes
        channel.send_exit_status(0)

        _delete_transfer_log(session_logger)
        
    except Exception as e:
        logger.error(f"Eroare în simularea SCP download: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        try:
            channel.send_exit_status(1)
        except:
            pass

def _capture_general_data(channel, session_dir, session_logger):
    try:
        logger.info("Capturare date transfer generale")
        
        # salveaza datele temporar in container
        temp_path_in_container = f"/tmp/transfer_data_{int(time.time())}.bin"
        
        import subprocess
        
        # cream fisierul in container
        create_cmd = ['docker', 'exec', '-i', session_logger.container_id, 
                     'bash', '-c', f'cat > "{temp_path_in_container}"']
        
        process = subprocess.Popen(create_cmd, stdin=subprocess.PIPE)
        
        # Capturam datele si le trimite in container
        while True:
            try:
                data = channel.recv(16384)
                if not data:
                    break
                process.stdin.write(data)
            except:
                break
        
        process.stdin.close()
        process.wait()
        
        # copiaza fisierul pe host în carantina
        quarantine_dir = Path(CONFIG.get('quarantine_dir', '../quarantine'))
        quarantine_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        client_ip = session_logger.client_ip if session_logger else "unknown"
        capture_filename = f"transfer_data_{client_ip}_{timestamp}.bin"
        host_file_path = quarantine_dir / capture_filename
        
        copy_cmd = ['docker', 'cp', f"{session_logger.container_id}:{temp_path_in_container}", 
                   str(host_file_path)]
        result = subprocess.run(copy_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Date transfer capturate în {host_file_path}")
            
            # sterge fisierul temporar din container
            cleanup_cmd = ['docker', 'exec', session_logger.container_id, 
                          'rm', '-f', temp_path_in_container]
            subprocess.run(cleanup_cmd, check=False)
        else:
            logger.error(f"Eroare la copierea datelor: {result.stderr}")
        
        # simulam succes pentru client
        try:
            channel.send_exit_status(0)
        except:
            pass
             
        # sterge log-ul
        _delete_transfer_log(session_logger)
        
    except Exception as e:
        logger.error(f"Eroare în capturarea datelor de transfer: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
