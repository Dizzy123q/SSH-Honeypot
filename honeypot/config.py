#!/usr/bin/env python3

import os
import json
from pathlib import Path

# incarca configuratia din fisier daca exista
config_path = Path('../config/config.json')
CONFIG = {}

if config_path.exists():
    try:
        with open(config_path, 'r') as f:
            CONFIG = json.load(f)
    except Exception as e:
        print(f"Eroare la încărcarea configurației: {e}")
        # foloseste configuratia implicita
        CONFIG = {}

# setari implicite pentru server
if 'server' not in CONFIG:
    CONFIG['server'] = {
        'host': '0.0.0.0',  # asculta pe toate interfețele
        'port': 2222,
        'max_connections': 50
    }

# setari docker
if 'docker' not in CONFIG:
    CONFIG['docker'] = {
        'image': 'ssh-honeypot:latest',  # imaginea docker pentru containere
        'network': {
            'mode': 'custom',               # modul de retea pentru containere
            'name': 'honeypot-net',         # numele retelei custom
            'subnet': '192.168.1.0/24',     # subnet-ul retelei
            'ip_range': '192.168.1.100-192.168.1.200'  # range-ul de IP-uri
        },
        'mem_limit': '512m',    # limita de memorie
        'cpu_count': 1          # Numar de cpu-uri
    }

# verifica si actualizeaza configuratia Docker existenta pentru compatibilitate
if 'docker' in CONFIG:
    docker_config = CONFIG['docker']
    
    # Daca nu exista configuratia de retea sau este bridge, actualizeaza la custom
    if 'network' not in docker_config or docker_config['network'].get('mode') == 'bridge':
        docker_config['network'] = {
            'mode': 'custom',
            'name': 'honeypot-net',
            'subnet': '192.168.1.0/24',
            'ip_range': '192.168.1.100-192.168.1.200'
        }
    
    # adauga optiunile lipsa pentru reteaua custom
    if docker_config['network'].get('mode') == 'custom':
        network = docker_config['network']
        if 'name' not in network:
            network['name'] = 'honeypot-net'
        if 'subnet' not in network:
            network['subnet'] = '192.168.1.0/24'
        if 'ip_range' not in network:
            network['ip_range'] = '192.168.1.100-192.168.1.200'

# utilizatori autorizati
if 'authorized_users' not in CONFIG:
    CONFIG['authorized_users'] = ['admin', 'developer', 'support']

# directoare
if 'logs_dir' not in CONFIG:
    CONFIG['logs_dir'] = 'logs'

if 'quarantine_dir' not in CONFIG:
    CONFIG['quarantine_dir'] = 'quarantine'

# fișiere capcana monitorizate
if 'monitored_files' not in CONFIG:
    CONFIG['monitored_files'] = [
        '/usr/local/share/app-data/.config/credentials.txt',
        '/etc/systemd/system.private.d/service-config.yaml',
        '/var/cache/apt-archives/partial/.old/cache.db',
        '/srv/data/.archive/customers_2023.csv',
        '/var/local/backup-history/.system-backup.tar.gz',
        '/usr/local/share/app-data/.ssh_backup',
        '/opt/.maintenance/scripts/services.conf'
    ]

# informaiii geografice
if 'enable_geo_ip' not in CONFIG:
    CONFIG['enable_geo_ip'] = True

# Credentiale permise
if 'valid_credentials' not in CONFIG:
    CONFIG['valid_credentials'] = [
        {'username': 'admin', 'password': 'admin'},
        {'username': 'developer', 'password': 'dev'},
        {'username': 'support', 'password': 'support'}
    ]

# Functia pentru salvarea configuratiei
def save_config():
    try:
        with open(config_path, 'w') as f:
            json.dump(CONFIG, f, indent=4)
        return True
    except Exception as e:
        print(f"Eroare la salvarea configuratiei: {e}")
        return False