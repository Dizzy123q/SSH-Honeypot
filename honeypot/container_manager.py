#!/usr/bin/env python3

import os
import logging
import subprocess
import docker
import threading
import time
import atexit
from pathlib import Path
from .config import CONFIG

# configurare logging specific pentru acest modul
logger = logging.getLogger('honeypot')

# variabile globale pentru statistici (pentru a evita resetarea la reimportare)
_active_containers = 0
_total_containers = 0
_container_registry = {}

class ContainerManager:

    def __init__(self):
        # initializează managerul de containere
        try:
            # folosim variabilele globale pentru a pastra statisticile la reimportare
            global _active_containers, _total_containers, _container_registry
            
            self.client = docker.from_env()
            logger.info("Manager containere inițializat cu succes")
            
            # referinte la variabilele globale pentru statistici
            self.active_containers = _active_containers
            self.total_containers = _total_containers
            self.container_registry = _container_registry
            
            # creeaza directorul pentru carantina
            self.quarantine_dir = Path(CONFIG.get('quarantine_dir', '../quarantine'))
            self.quarantine_dir.mkdir(exist_ok=True)
            
            # incarcă imaginea Docker dacă exista
            self.image_name = CONFIG.get('docker', {}).get('image', 'ssh-honeypot:latest')
            self._ensure_image_exists()
            
            # inregistreaza functia de curatare pentru când programul se închide
            atexit.register(self.cleanup_all_containers)
            
            # numara containerele existente cu prefix honeypot pentru a avea statistici corecte
            self._count_existing_containers()
            
            logger.info(f"ContainerManager inițializat cu {self.active_containers} containere active")
            
        except Exception as e:
            logger.error(f"Eroare la inițializarea managerului de containere: {str(e)}")
            raise
    
    def _count_existing_containers(self):
        try:
            # resetam contoarele doar daca registry-ul este gol
            if not self.container_registry:
                self.active_containers = 0
                self.total_containers = 0
                
                containers = self.client.containers.list(all=True, filters={"name": "honeypot-"})
                
                for container in containers:
                    # adauga la total
                    self.total_containers += 1
                    
                    # Daca ruleaza, adaugă la active
                    if container.status == "running":
                        self.active_containers += 1
                        
                        # adauga in registru
                        self.container_registry[container.id] = {
                            'name': container.name,
                            'created_at': time.time(),
                            'container': container
                        }
                
                # actualizăm variabilele globale
                global _active_containers, _total_containers, _container_registry
                _active_containers = self.active_containers
                _total_containers = self.total_containers
                _container_registry = self.container_registry
                
                logger.info(f"Containere existente detectate: {self.total_containers} total, {self.active_containers} active")
        except Exception as e:
            logger.error(f"Eroare la numărarea containerelor existente: {str(e)}")
    
    def _ensure_image_exists(self):
        try:
            # verifica daca imaginea exista deja
            self.client.images.get(self.image_name)
            logger.info(f"Imaginea {self.image_name} există")
        except docker.errors.ImageNotFound:
            logger.warning(f"Imaginea {self.image_name} nu a fost găsită, se construiește acum")
            
            # cauta Dockerfile în directorul corespunzator
            dockerfile_path = Path('../docker/Dockerfile')
            if not dockerfile_path.exists():
                logger.error("Dockerfile nu a fost găsit")
                raise FileNotFoundError("Dockerfile nu a fost găsit")
            
            # construieste imaginea
            build_cmd = ['docker', 'build', '-t', self.image_name, '-f', str(dockerfile_path), '.']
            process = subprocess.run(build_cmd, capture_output=True, text=True)
            
            if process.returncode != 0:
                logger.error(f"Eroare la construirea imaginii: {process.stderr}")
                raise Exception(f"Nu s-a putut construi imaginea Docker: {process.stderr}")
            
            logger.info(f"Imaginea {self.image_name} a fost construită cu succes")
    
    def create_container(self, container_name):
        try:
            # configurare retea
            network_config = CONFIG.get('docker', {}).get('network', {})
            network_mode = network_config.get('mode', 'bridge')
            
            # configurare volume pentru logging
            logs_dir = Path(CONFIG.get('logs_dir', '../logs'))
            logs_dir.mkdir(exist_ok=True)
            
            # optiuni pentru container
            container_options = {
                'image': self.image_name,
                'name': container_name,
                'detach': True,
                'cap_add': ['NET_ADMIN'],
                'environment': {
                    'AUTHORIZED_USERS': ','.join(CONFIG.get('authorized_users', ['admin', 'developer', 'support']))
                },
                'mem_limit': CONFIG.get('docker', {}).get('mem_limit', '512m'),
                'cpu_count': CONFIG.get('docker', {}).get('cpu_count', 1),
                'hostname': 'srv-web-03'
            }
            
            # gestionare retea custom
            if network_mode == 'custom':
                network_name = network_config.get('name', 'honeypot-net')
                subnet = network_config.get('subnet', '192.168.1.0/24')
                
                # creeaza reteaua daca nu exista
                try:
                    network = self.client.networks.get(network_name)
                    logger.info(f"Rețeaua {network_name} există deja")
                except docker.errors.NotFound:
                    logger.info(f"Creez rețeaua {network_name}")
                    network = self.client.networks.create(
                        network_name,
                        driver="bridge",
                        ipam=docker.types.IPAMConfig(
                            pool_configs=[docker.types.IPAMPool(subnet=subnet)]
                        )
                    )
                
                # genereaza ip pentru container
                ip_address = self._generate_ip_address(network_config)
                
                # configureaza reteaua pentru container
                container_options['network'] = network_name
                if ip_address:
                    logger.info(f"Container va folosi IP: {ip_address}")
            else:
                # foloseste modul de retea standard
                container_options['network_mode'] = network_mode
            
            # creeaza containerul
            container = self.client.containers.run(**container_options)

            # conecteaza containerul la reteaua custom cu ip specific
            if network_mode == 'custom' and ip_address:
                try:
                    network = self.client.networks.get(network_name)
                    network.connect(container, ipv4_address=ip_address)
                    logger.info(f"Container conectat la rețeaua {network_name} cu IP: {ip_address}")
                except Exception as e:
                    logger.error(f"Eroare la conectarea containerului la rețea: {str(e)}")

            self.active_containers += 1
            self.total_containers += 1
            
            self.container_registry[container.id] = {
                'name': container_name,
                'created_at': time.time(),
                'container': container
            }
            
            global _active_containers, _total_containers, _container_registry
            _active_containers = self.active_containers
            _total_containers = self.total_containers
            _container_registry = self.container_registry
            
            logger.info(f"Container creat: {container.id} (Nume: {container_name})")
            time.sleep(2)
            
            return container.id
            
        except Exception as e:
            logger.error(f"Eroare la crearea containerului {container_name}: {str(e)}")
            return None

    def _generate_ip_address(self, network_config):
        # genereaza un ip disponibil din range-ul specificat
        try:
            ip_range = network_config.get('ip_range', '192.168.1.100-192.168.1.200')
            start_ip, end_ip = ip_range.split('-')
            
            # extrage ultimul octet
            start_last = int(start_ip.split('.')[-1])
            end_last = int(end_ip.split('.')[-1])
            base_ip = '.'.join(start_ip.split('.')[:-1])
            
            # gaseste primul ip disponibil
            for i in range(start_last, end_last + 1):
                test_ip = f"{base_ip}.{i}"
                if not self._ip_in_use(test_ip):
                    return test_ip
            
            logger.warning("Nu mai sunt IP-uri disponibile în range")
            return None
            
        except Exception as e:
            logger.error(f"Eroare la generarea IP-ului: {str(e)}")
            return None

    def _ip_in_use(self, ip_address):
        # verifica daca un ip este deja folosit
        try:
            for container_info in self.container_registry.values():
                container = container_info['container']
                container.reload()
                if container.status == "running":
                    # Verifică IP-ul containerului
                    networks = container.attrs['NetworkSettings']['Networks']
                    for network_info in networks.values():
                        if network_info.get('IPAddress') == ip_address:
                            return True
            return False
        except Exception:
            return False

    def test_network_restrictions(self, container_id):
        # incearca sa dea ping un server extern
        result = self.exec_command(container_id, "ping -c 1 -W 1 8.8.8.8")
        if "100% packet loss" in result or "Network is unreachable" in result:
            return True
        return False
    
    def stop_container(self, container_id):
        global _active_containers, _container_registry
        
        try:
            # verifica daca containerul este in registru
            if container_id in self.container_registry:
                container_info = self.container_registry[container_id]
                
                try:
                    # opreste containerul
                    container_info['container'].stop(timeout=1)
                    
                    # elimina containerul
                    container_info['container'].remove(force=True)
                    
                    # actualizeaza statisticile
                    self.active_containers -= 1
                    
                    # Actualizam si variabila globala
                    _active_containers = self.active_containers
                    
                    # elimina din registru
                    del self.container_registry[container_id]
                    
                    # actualiza si registrul global
                    _container_registry = self.container_registry
                    
                    logger.info(f"Container oprit și eliminat: {container_id}")
                    
                except Exception as e:
                    logger.error(f"Eroare la oprirea containerului {container_id}: {str(e)}")
                    
                    # incercăm fortat
                    try:
                        subprocess.run(['docker', 'rm', '-f', container_id], check=True, capture_output=True)
                        logger.info(f"Container eliminat forțat: {container_id}")
                        
                        # actualizeaza statisticile
                        self.active_containers -= 1
                        _active_containers = self.active_containers
                        
                        # elimina din registru
                        if container_id in self.container_registry:
                            del self.container_registry[container_id]
                        _container_registry = self.container_registry
                    except Exception as e2:
                        logger.error(f"Eșec și la eliminarea forțată a containerului {container_id}: {str(e2)}")
            
            else:
                # containerul nu este in registru, incearcă sa-l obtii direct
                try:
                    container = self.client.containers.get(container_id)
                    container.stop(timeout=1)
                    container.remove(force=True)
                    logger.info(f"Container oprit și eliminat (din afara registrului): {container_id}")
                except Exception as e:
                    logger.error(f"Eroare la oprirea containerului extern {container_id}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Eroare generală la oprirea containerului {container_id}: {str(e)}")
    
    def cleanup_all_containers(self):
        global _active_containers, _container_registry
        
        logger.info("Curățare toate containerele honeypot...")
        
        # copiem cheile pentru a evita modificarea dicționarului in timpul iterarii
        container_ids = list(self.container_registry.keys())
        
        for container_id in container_ids:
            self.stop_container(container_id)
        
        # verificam daca mai sunt containere cu prefix honeypot care nu au fost eliminate
        try:
            containers = self.client.containers.list(all=True, filters={"name": "honeypot-"})
            
            for container in containers:
                try:
                    logger.info(f"Curățare container rămas: {container.name} ({container.id})")
                    container.stop(timeout=1)
                    container.remove(force=True)
                except Exception as e:
                    logger.error(f"Eroare la curățarea containerului rămas {container.id}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Eroare la căutarea containerelor rămase: {str(e)}")
        
        # resetam statisticile
        self.active_containers = 0
        _active_containers = 0
        
        logger.info("Curățare containere finalizată")
    
    def exec_command(self, container_id, command, environment=None):
        try:
            # verifica daca containerul este în registru
            if container_id in self.container_registry:
                container = self.container_registry[container_id]['container']
            else:
                container = self.client.containers.get(container_id)
            
            # seteaza mediul implicit daca nu este furnizat
            if environment is None:
                environment = {}
            
            # executa comanda cu bash
            result = container.exec_run(
                ["/bin/bash", "-c", command], 
                environment=environment,
                tty=True
            )
            
            return result.output.decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Eroare la executarea comenzii în container {container_id}: {str(e)}")
            return None
    
    def get_stats(self):
        global _active_containers, _container_registry
        
        # verifica intai daca exista containere care nu mai exista
        to_remove = []
        for container_id, container_info in self.container_registry.items():
            try:
                # verifica daca containerul exista înca
                container_info['container'].reload()
            except Exception:
                logger.warning(f"Container zombie detectat: {container_id}")
                to_remove.append(container_id)
        
        # elimina containerele zombie din registru
        for container_id in to_remove:
            del self.container_registry[container_id]
            self.active_containers -= 1
            
            # actualizam si variabila globala
            _active_containers = self.active_containers
            _container_registry = self.container_registry
        
        # colecteaza informatii despre containerele active
        active_containers_info = []
        for container_id, container_info in self.container_registry.items():
            try:
                container = container_info['container']
                container.reload()
                
                # adauga doar daca containerul ruleaza
                if container.status == "running":
                    # calculeaza durata
                    duration = time.time() - container_info['created_at']
                    
                    # formatul duratei
                    hours, remainder = divmod(duration, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    duration_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
                    
                    # extrage ip-ul din numele containerului
                    ip = container_info['name'].replace('honeypot-', '').split('-')[0].replace('-', '.')
                    
                    active_containers_info.append({
                        'id': container_id[:12],  # ID scurt
                        'name': container_info['name'],
                        'ip': ip,
                        'created_at': time.strftime('%Y-%m-%d %H:%M:%S', 
                                                time.localtime(container_info['created_at'])),
                        'duration': duration_str
                    })
            except Exception as e:
                logger.error(f"Eroare la obținerea informațiilor despre container {container_id}: {str(e)}")
        
        return {
            'active_containers': self.active_containers,
            'total_containers': self.total_containers,
            'active_containers_info': active_containers_info
        }
        
    def upload_file(self, container_id, source_path, dest_path):
        try:
            # copiaza fisierul in container folosind comanda docker cp
            cmd = ['docker', 'cp', source_path, f"{container_id}:{dest_path}"]
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode != 0:
                logger.error(f"Eroare la încărcarea fișierului în container: {process.stderr}")
                return False
            
            logger.info(f"Fișier încărcat cu succes în {container_id}: {source_path} -> {dest_path}")
            return True
            
        except Exception as e:
            logger.error(f"Eroare la încărcarea fișierului în container {container_id}: {str(e)}")
            return False