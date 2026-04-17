#!/usr/bin/env python3

import sys
import signal
import logging
import atexit
from pathlib import Path
from threading import Thread
from time import sleep

# Configurare logging simplă
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HoneypotManager:
    def __init__(self):
        self.running = True
        self.threads = []
        self.cleanup_registered = False
        
    def setup_directories(self):
        for dir_name in ['logs', 'quarantine', 'keys']:
            Path(dir_name).mkdir(exist_ok=True)
    
    def check_dependencies(self):
        try:
            import docker
            import paramiko
            from honeypot.config import CONFIG
            return True
        except ImportError as e:
            logger.error(f"Dependență lipsă: {e}")
            return False
    
    def cleanup(self):
        if not self.cleanup_registered:
            return
            
        logger.info("Curățare honeypot...")
        self.running = False
        
        try:
            import docker
            client = docker.from_env()
            containers = client.containers.list(all=True, filters={"name": "honeypot-"})
            
            for container in containers:
                try:
                    container.stop(timeout=1)
                    container.remove(force=True)
                    logger.info(f"Container eliminat: {container.name}")
                except Exception:
                    pass
        except Exception:
            pass
    
    def signal_handler(self, sig, frame):
        logger.info("Oprire honeypot...")
        self.cleanup()
        sys.exit(0)
    
    def start_ssh_server(self):
        try:
            from honeypot.server.ssh_server import main as ssh_main
            ssh_main()
        except Exception as e:
            logger.error(f"Eroare server SSH: {e}")
    
    def start_gui(self, host='127.0.0.1', port=5000):
        try:
            from honeypot.gui import start_gui
            from honeypot.analyzer.global_analyzer import GlobalAnalyzer
            
            analyzer = GlobalAnalyzer(Path('logs'))
            analyzer.scan_all_logs()
            start_gui(analyzer, host, port)
        except Exception as e:
            logger.error(f"Eroare GUI: {e}")
    
    def run(self):
        # Verificări inițiale
        if not self.check_dependencies():
            return False
        
        self.setup_directories()
        
        # Înregistrare cleanup
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        atexit.register(self.cleanup)
        self.cleanup_registered = True
        
        # Pornire server SSH
        ssh_thread = Thread(target=self.start_ssh_server, daemon=True)
        ssh_thread.start()
        self.threads.append(ssh_thread)
        logger.info("Server SSH pornit")
        
        # Pornire GUI
        gui_thread = Thread(target=self.start_gui, args=('127.0.0.1', 5000), daemon=True)
        gui_thread.start()
        self.threads.append(gui_thread)
        logger.info("GUI pornit pe 127.0.0.1:5000")
        
        # Bucla principală
        try:
            while self.running and any(t.is_alive() for t in self.threads):
                sleep(1)
        except KeyboardInterrupt:
            pass
        
        return True

def main():
    manager = HoneypotManager()
    success = manager.run()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())