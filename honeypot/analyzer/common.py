#!/usr/bin/env python3

import re
import logging
import datetime
import socket
from pathlib import Path

# configurare logging
logger = logging.getLogger('honeypot.analyzer')

def parse_log_file(log_path):
    log_data = {
        'header': {},
        'commands': [],
        'trap_files_accessed': [],
        'uploaded_files': [],
        'summary': {},
    }
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            
        # extragea header-ului
        header_match = re.search(r'=== SSH Honeypot Session Log ===(.*?)==+\n', content, re.DOTALL)
        if header_match:
            header_text = header_match.group(1)
            
            # extrage ip client
            ip_match = re.search(r'Client IP: ([\d\.]+)', header_text)
            if ip_match:
                log_data['header']['client_ip'] = ip_match.group(1)
                log_data['header']['ip'] = ip_match.group(1)  # adaugat pentru compatibilitate
                
            # extrage id container
            container_match = re.search(r'Container ID: ([a-zA-Z0-9]+)', header_text)
            if container_match:
                log_data['header']['container_id'] = container_match.group(1)
                
            # extrage timestamp start
            time_match = re.search(r'Start Time: (.+)', header_text)
            if time_match:
                log_data['header']['start_time'] = time_match.group(1)
        
        # extrage informatii despre atacator
        attacker_match = re.search(r'Attacker Info:(.*?)(?=\[|\n\n)', content, re.DOTALL)
        if attacker_match:
            attacker_text = attacker_match.group(1)
            
            # extrage tara si oras
            country_match = re.search(r'country: (.+)', attacker_text)
            if country_match:
                log_data['header']['country'] = country_match.group(1)
                
            city_match = re.search(r'city: (.+)', attacker_text)
            if city_match:
                log_data['header']['city'] = city_match.group(1)
        
        # extrage comenzile
        command_matches = re.finditer(r'\[([\d\-\w:\.]+)\] Command: (.+?)(?=\n\[|\n==|$)', content)
        for match in command_matches:
            timestamp = match.group(1)
            command = match.group(2)
            log_data['commands'].append({
                'timestamp': timestamp,
                'command': command
            })
        
        return log_data
    
    except Exception as e:
        logger.error(f"Eroare la parsarea fișierului log {log_path}: {str(e)}")
        return log_data

def extract_commands(log_data):
    commands = []
    
    try:
        for cmd in log_data.get('commands', []):
            timestamp = cmd.get('timestamp')
            command = cmd.get('command')
            
            if timestamp and command:
                commands.append((timestamp, command))
        
        return commands
    
    except Exception as e:
        logger.error(f"Eroare la extragerea comenzilor: {str(e)}")
        return commands

def extract_ip_info(log_data):
    import socket
    
    # initializam dictionarul cu valori implicite
    ip_info = {
        'ip': None,
        'hostname': None,
        'country': None,
        'city': None,
        'location': None,
        'region': None,
        'org': None,
        'asn': None
    }
    
    try:
        # Extrage ip-ul din header
        client_ip = log_data.get('header', {}).get('client_ip')
        
        if not client_ip:
            return ip_info
        
        ip_info['ip'] = client_ip
        
        # incearca sa obtina hostname-ul
        try:
            hostname = socket.gethostbyaddr(client_ip)[0]
            ip_info['hostname'] = hostname
        except (socket.herror, socket.gaierror):
            ip_info['hostname'] = "Unknown"
        
        # cauta informatii geo în header
        attacker_info = log_data.get('header', {}).get('attacker_info', {})
        
        if attacker_info:
            ip_info['country'] = attacker_info.get('country', 'Unknown')
            ip_info['city'] = attacker_info.get('city', 'Unknown')
            ip_info['location'] = attacker_info.get('location', 'Unknown')
            
        # incercam să obtinem informatii folosind geoip2
        try:
            import geoip2.database
            import geoip2.errors
            from pathlib import Path
            import os
            
            # locații posibile pentru baza de date geoip2
            possible_paths = [
                'GeoLite2-City.mmdb',
                'GeoLite2-Country.mmdb',
                os.path.join('data', 'GeoLite2-City.mmdb'),
                os.path.join('data', 'GeoLite2-Country.mmdb'),
                os.path.expanduser('~/.local/share/GeoIP/GeoLite2-City.mmdb'),
                os.path.expanduser('~/.local/share/GeoIP/GeoLite2-Country.mmdb'),
                '/usr/share/GeoIP/GeoLite2-City.mmdb',
                '/usr/share/GeoIP/GeoLite2-Country.mmdb',
                '/var/lib/GeoIP/GeoLite2-City.mmdb',
                '/var/lib/GeoIP/GeoLite2-Country.mmdb',
            ]
            
            # gasim prima baza de date disponibila
            db_path = None
            for path in possible_paths:
                if Path(path).exists():
                    db_path = path
                    break
            
            if db_path:
                # deschidem baza de date si obtinem informatiile despre ip
                with geoip2.database.Reader(db_path) as reader:
                    # incercam mai intai city, daca esueaza incercam country
                    try:
                        response = reader.city(client_ip)
                        
                        ip_info['country'] = response.country.name or 'Unknown'
                        ip_info['city'] = response.city.name or 'Unknown'
                        if response.location.latitude and response.location.longitude:
                            ip_info['location'] = f"{response.location.latitude},{response.location.longitude}"
                        ip_info['region'] = response.subdivisions.most_specific.name if response.subdivisions else None
                        
                    except geoip2.errors.AddressNotFoundError:
                        # ip-ul nu a fost gasit in baza de date city
                        try:
                            response = reader.country(client_ip)
                            ip_info['country'] = response.country.name or 'Unknown'
                        except:
                            # nu putem obtine informatii despre tara
                            pass
                    except Exception as e:
                        logger.warning(f"Eroare la interogarea bazei de date GeoIP2 City pentru {client_ip}: {str(e)}")
            else:
                # incercam sa folosim api-ul web geoip2 daca exista cheia de api in configuratie
                try:
                    from honeypot.config import CONFIG
                    geoip_config = CONFIG.get('geoip', {})
                    account_id = geoip_config.get('account_id')
                    license_key = geoip_config.get('license_key')
                    
                    if account_id and license_key:
                        import geoip2.webservice
                        
                        # cream clientul pentru api-ul web
                        with geoip2.webservice.Client(account_id, license_key) as client:
                            try:
                                response = client.city(client_ip)
                                
                                ip_info['country'] = response.country.name or 'Unknown'
                                ip_info['city'] = response.city.name or 'Unknown'
                                if response.location.latitude and response.location.longitude:
                                    ip_info['location'] = f"{response.location.latitude},{response.location.longitude}"
                                ip_info['region'] = response.subdivisions.most_specific.name if response.subdivisions else None
                                
                            except geoip2.errors.AddressNotFoundError:
                                # ip-ul nu a fost gasit in baza de date
                                logger.warning(f"IP-ul {client_ip} nu a fost găsit în baza de date GeoIP2")
                            except Exception as e:
                                logger.warning(f"Eroare la interogarea API-ului GeoIP2 pentru {client_ip}: {str(e)}")
                    else:
                        logger.debug("Nu există chei pentru API-ul web GeoIP2 în configurație")
                        
                except ImportError:
                    logger.warning("Modulul geoip2.webservice nu este disponibil")
                except Exception as e:
                    logger.warning(f"Eroare la utilizarea API-ului web GeoIP2: {str(e)}")
        
        except ImportError:
            logger.warning("Biblioteca geoip2 nu este instalată. Instalați-o cu 'pip install geoip2'")
        except Exception as e:
            logger.warning(f"Eroare la utilizarea geoip2: {str(e)}")
        
        return ip_info
    
    except Exception as e:
        logger.error(f"Eroare la extragerea informațiilor IP: {str(e)}")
        return ip_info

def extract_session_duration(log_data):
    try:
        # verifica daca avem deja durata in sumar
        if 'summary' in log_data and 'duration' in log_data['summary']:
            duration_str = log_data['summary']['duration']
            
            try:
                # parseaza direct formatul de durata din log 
                parts = duration_str.split(':')
                if len(parts) == 3:
                    hours = int(parts[0])
                    minutes = int(parts[1])
                    seconds_parts = parts[2].split('.')
                    seconds = int(seconds_parts[0])
                    microseconds = int(seconds_parts[1]) if len(seconds_parts) > 1 else 0
                    
                    duration = datetime.timedelta(
                        hours=hours, 
                        minutes=minutes, 
                        seconds=seconds,
                        microseconds=microseconds
                    )
                    logger.debug(f"Durată calculată din summary: {duration}")
                    return duration
            except (ValueError, IndexError) as e:
                logger.debug(f"Nu s-a putut parsa durata din summary: {duration_str}, eroare: {str(e)}")
        
        # obtine timestamp-urile din log-ul brut daca exista
        if 'raw_log' in log_data:
            raw_log = log_data['raw_log']
            start_match = re.search(r'Start Time: ([\d-]+ [\d:\.]+)', raw_log)
            end_match = re.search(r'End Time: ([\d-]+T[\d:\.]+)', raw_log)
            duration_match = re.search(r'Duration: ([\d:\.]+)', raw_log)
            
            if duration_match:
                duration_str = duration_match.group(1)
                try:
                    # parseaza direct formatul de durata din log
                    parts = duration_str.split(':')
                    if len(parts) == 3:
                        hours = int(parts[0])
                        minutes = int(parts[1])
                        seconds_parts = parts[2].split('.')
                        seconds = int(seconds_parts[0])
                        microseconds = int(seconds_parts[1]) if len(seconds_parts) > 1 else 0
                        
                        return datetime.timedelta(
                            hours=hours, 
                            minutes=minutes, 
                            seconds=seconds,
                            microseconds=microseconds
                        )
                except (ValueError, IndexError):
                    pass
            
            # calculeaza din start si end time
            if start_match and end_match:
                start_time_str = start_match.group(1)
                end_time_str = end_match.group(1)
                
                try:
                    start_time = datetime.datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S.%f')
                    end_time = datetime.datetime.strptime(end_time_str.replace('T', ' '), '%Y-%m-%d %H:%M:%S.%f')
                    
                    return end_time - start_time
                except ValueError:
                    pass
        
        # verifica daca exista timestamp-uri in header si summary
        start_time_str = log_data.get('header', {}).get('start_time')
        end_time_str = log_data.get('summary', {}).get('end_time')
        
        if start_time_str and end_time_str:
            # incearca sa parseze timestamp-urile folosind formate multiple
            start_formats = ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']
            end_formats = ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S']
            
            # parseaza start_time
            start_time = None
            for fmt in start_formats:
                try:
                    start_time = datetime.datetime.strptime(start_time_str, fmt)
                    break
                except ValueError:
                    continue
            
            # parseaza end_time
            end_time = None
            for fmt in end_formats:
                try:
                    end_time = datetime.datetime.strptime(end_time_str, fmt)
                    break
                except ValueError:
                    # incearca sa inlocuiasca T cu spațiu
                    try:
                        end_time = datetime.datetime.strptime(end_time_str.replace('T', ' '), fmt)
                        break
                    except ValueError:
                        continue
            
            if start_time and end_time:
                return end_time - start_time
        
        # Daca tot nu am reusit, folosim timestamp-urile comenzilor
        commands = log_data.get('commands', [])
        if commands:
            timestamps = []
            
            # extrage timestamp-urile din comenzi
            for cmd in commands:
                if isinstance(cmd, dict) and 'timestamp' in cmd:
                    timestamp_str = cmd['timestamp']
                    for fmt in ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                        try:
                            timestamp = datetime.datetime.strptime(timestamp_str.replace('T', ' ') if 'T' in timestamp_str else timestamp_str, fmt)
                            timestamps.append(timestamp)
                            break
                        except ValueError:
                            continue
            
            if len(timestamps) >= 2:
                timestamps.sort()
                return timestamps[-1] - timestamps[0]
        
        # daca nimic nu functioneaza, consulta datele brute din log
        logger.warning("Nu s-a putut calcula durata în mod standard, se verifică log-ul brut")
        return datetime.timedelta(0)
    
    except Exception as e:
        logger.error(f"Eroare la calcularea duratei sesiunii: {str(e)}")
        return datetime.timedelta(0)

def classify_attack(commands):
    categories = {
        'system_recon': [],
        'privilege_escalation': [],
        'data_exfiltration': [],
        'persistence': [],
        'honeypot_detection': [],
        'network_scanning': [],
        'brute_force': [],
        'file_access': [],
        'malware_upload': [],
        'lateral_movement': []
    }
    
    # pattern-uri simple pentru fiecare categorie
    patterns = {
        'system_recon': [
            r'uname', r'hostname', r'whoami', r'id', r'pwd', r'ls', r'cat /etc/passwd',
            r'cat /etc/shadow', r'w', r'who', r'last', r'ps', r'top', r'df', r'du'
        ],
        'privilege_escalation': [
            r'sudo', r'su( |$)', r'chmod( |\+)', r'pkexec', r'setuid', r'setgid',
            r'chmod 4', r'chmod 2', r'chmod u\+s', r'chmod g\+s'
        ],
        'data_exfiltration': [
            r'scp', r'rsync', r'sftp', r'ftp', r'curl -T', r'wget --post-file',
            r'nc', r'netcat', r'base64', r'gzip', r'zip', r'tar'
        ],
        'persistence': [
            r'crontab', r'cron', r'systemctl', r'service', r'rc\.d', r'init\.d',
            r'\.bashrc', r'\.profile', r'\.bash_profile', r'\.ssh/authorized_keys'
        ],
        'honeypot_detection': [
            r'docker', r'lxc', r'df -h', r'ps aux', r'cat /etc/mtab', r'cat /proc/cpuinfo',
            r'systemd-detect-virt', r'/proc/self/cgroup'
        ],
        'network_scanning': [
            r'ping', r'nmap', r'nc -z', r'telnet', r'netstat', r'ip addr', r'ifconfig',
            r'arp', r'dig', r'host'
        ],
        'brute_force': [
            r'hydra', r'medusa', r'john', r'hashcat', r'crack', r'bruteforce',
            r'wordlist', r'dictionary'
        ],
        'file_access': [
            r'password', r'\.config/credentials', r'\.ssh_backup', r'\.ssh/',
            r'service-config', r'systemd/system\.private', r'cache\.db', r'backup'
        ],
        'malware_upload': [
            r'wget', r'curl( |-O)', r'scp', r'git clone', r'svn checkout',
            r'\.sh', r'\.py', r'\.pl', r'chmod \+x'
        ],
        'lateral_movement': [
            r'ssh', r'meterpreter', r'xfreerdp', r'rdesktop',
            r'proxychains', r'socat', r'pivoting'
        ]
    }
    
    try:
        # extragem doar comenzile daca sunt tupluri
        cmd_list = []
        for cmd in commands:
            if isinstance(cmd, tuple) and len(cmd) >= 2:
                cmd_list.append(cmd[1])
            elif isinstance(cmd, str):
                cmd_list.append(cmd)
            elif isinstance(cmd, dict) and 'command' in cmd:
                cmd_list.append(cmd['command'])
        
        # aplicam pattern-urile pentru fiecare comanda
        for cmd in cmd_list:
            normalized_cmd = normalize_command(cmd)
            
            for category, category_patterns in patterns.items():
                for pattern in category_patterns:
                    if re.search(pattern, normalized_cmd, re.IGNORECASE):
                        categories[category].append(cmd)
                        break  # trecem la urmatoarea categorie odata ce am gasit o potrivire
        
        return categories
    
    except Exception as e:
        logger.error(f"Eroare la clasificarea atacului: {str(e)}")
        return categories

def calculate_severity(attack_data):
    # definim ponderi pentru fiecare categorie
    weights = {
        'system_recon': 2,
        'privilege_escalation': 9,
        'data_exfiltration': 8,
        'persistence': 9,
        'honeypot_detection': 3,
        'network_scanning': 4,
        'brute_force': 5,
        'file_access': 6,
        'malware_upload': 10,
        'lateral_movement': 7
    }
    
    try:
        if not attack_data:
            return 1
        
        # calculam numarul de comenzi per categorie
        category_counts = {cat: len(cmds) for cat, cmds in attack_data.items() if cmds}
        
        if not category_counts:
            return 1
        
        # calculam scorul ca medie ponderata
        score = 0
        total_weight = 0
        
        for category, count in category_counts.items():
            weight = weights.get(category, 1)
            score += weight * min(count, 5)  # limitare la 5 comenzi per categorie
            total_weight += weight
        
        if total_weight > 0:
            final_score = int(score / total_weight)
            
            # ajustam scorul final pe baza numarului de categorii
            num_categories = len([cat for cat, cmds in attack_data.items() if cmds])
            category_multiplier = min(num_categories / 10 + 0.5, 1.0)
            
            final_score = int(final_score * category_multiplier)
            
            # asiguram ca scorul este între 1 si 10
            return max(1, min(final_score, 10))
        
        return 1
    
    except Exception as e:
        logger.error(f"Eroare la calcularea severității: {str(e)}")
        return 1

def normalize_command(command):
    try:
        if not command:
            return ""
        
        # convertim la lowercase
        normalized = command.lower()
        
        # eliminam spatiile multiple
        normalized = re.sub(r'\s+', ' ', normalized)
        
        # eliminam argumentele de tip cale absoluta
        normalized = re.sub(r'(/[a-zA-Z0-9_\-\.\/]+)+', '/PATH', normalized)
        
        # eliminam adrese ip
        normalized = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_ADDR', normalized)
        
        # eliminam url-uri
        normalized = re.sub(r'https?://[a-zA-Z0-9\.\-\/\?=&%]+', 'URL', normalized)
        
        # eliminam argumente numerice
        normalized = re.sub(r'\b\d+\b', 'NUM', normalized)
        
        return normalized.strip()
    
    except Exception as e:
        logger.error(f"Eroare la normalizarea comenzii: {str(e)}")
        return command

def extract_timestamp(log_line):
    try:
        # pattern pentru timestamp-ul din loguri
        match = re.search(r'\[([\d\-]+ [\d:]+)(?:\.\d+)?\]', log_line)
        
        if match:
            timestamp_str = match.group(1)
            
            # convertim in obiect datetime
            return datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        
        return None
    
    except Exception as e:
        logger.error(f"Eroare la extragerea timestamp-ului: {str(e)}")
        return None

def is_automated_attack(commands_timing):
    try:
        if not commands_timing or len(commands_timing) < 5:
            return False
        
        # calculam intervalele dintre comenzi
        intervals = []
        
        for i in range(1, len(commands_timing)):
            delta = (commands_timing[i] - commands_timing[i-1]).total_seconds()
            intervals.append(delta)
        
        if not intervals:
            return False
        
        # verificam pentru intervale foarte scurte
        short_intervals = [i for i in intervals if i < 0.5]
        if len(short_intervals) / len(intervals) > 0.7:  # peste 70% sunt foarte scurte
            return True
        
        # verificam pentru intervale foarte regulate
        avg_interval = sum(intervals) / len(intervals)
        
        # Calculam deviatia standard
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # coeficientul de variatie (std_dev / mean) indică cat de regulate sunt intervalele
        # un coeficient mic (<0.3) indica intervale foarte regulate
        if avg_interval > 0 and (std_dev / avg_interval) < 0.3:
            return True
        
        return False
    
    except Exception as e:
        logger.error(f"Eroare la determinarea tipului de atac: {str(e)}")
        return False