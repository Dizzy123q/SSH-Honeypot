#!/usr/bin/env python3

import os
import logging
import datetime
import collections
from pathlib import Path
from collections import Counter, defaultdict

# luam ce avem nevoie din modulele locale
from .common import (
    parse_log_file, extract_commands, extract_ip_info,
    extract_session_duration, classify_attack, 
    normalize_command
)
from .attack_patterns import CommandMatcher

# setam logging-ul sa vedem ce se intampla
logger = logging.getLogger('honeypot.analyzer')

class GlobalAnalyzer:  
    def __init__(self, logs_dir):
        self.logs_dir = Path(logs_dir)
        
        # vedem daca folderul chiar exista
        if not self.logs_dir.exists() or not self.logs_dir.is_dir():
            logger.error(f"Directorul de log-uri nu există: {logs_dir}")
            raise FileNotFoundError(f"Directorul de log-uri nu există: {logs_dir}")
        
        # initializam toate structurile in care o sa tinem datele
        self.sessions_data = []
        self.total_sessions = 0
        self.categorized_commands = {}  # aici o sa tinem categoriile de comenzi pentru toate sesiunile
        self.attack_distribution = {}
        self.geographic_distribution = {}
        self.hourly_distribution = [0] * 24
        self.daily_distribution = [0] * 7
        self.command_frequency = Counter()
        
        logger.info(f"Analizator global inițializat pentru directorul: {logs_dir}")
    
    def scan_all_logs(self):
        try:
            # curatam datele vechi daca avem
            self.sessions_data = []
            self.total_sessions = 0
            
            # cautam toate fisierele de log
            log_files = []
            for item in self.logs_dir.iterdir():
                # luam doar fisierele .log care nu sunt log-uri de sistem
                if item.is_file() and item.suffix == '.log' and item.name not in ['honeypot.log', 'debug.log', 'error.log', 'app.log']:
                    # filtram doar log-urile de sesiune (format: IP_TIMESTAMP.log)
                    if '_' in item.stem and item.stem[0].isdigit():
                        log_files.append(item)
            
            logger.info(f"Au fost găsite {len(log_files)} fișiere de log pentru analiză")
            
            # procesam pe rand fiecare fisier de log
            for log_file in log_files:
                try:
                    # parsam fisierul de log
                    log_data = parse_log_file(log_file)
                    
                    # vedem daca log-ul are date ok
                    if not log_data or 'header' not in log_data or not log_data['header']:
                        logger.warning(f"Log-ul {log_file} nu conține date valide și va fi ignorat")
                        continue
                    
                    # adaugam niste info extra
                    log_data['file_path'] = str(log_file)
                    log_data['file_name'] = log_file.name
                    
                    # extragem comenzile
                    commands = extract_commands(log_data)
                    
                    # extragem info despre ip si geolocatie
                    ip_info = extract_ip_info(log_data)
                    log_data['ip_info'] = ip_info
                    
                    # calculam cat a durat sesiunea
                    duration = extract_session_duration(log_data)
                    log_data['duration'] = duration
                    
                    # adaugam sesiunea la lista noastra
                    self.sessions_data.append(log_data)
                    
                except Exception as e:
                    logger.error(f"Eroare la procesarea log-ului {log_file}: {str(e)}")
            
            # actualizam numarul total de sesiuni
            self.total_sessions = len(self.sessions_data)
            
            logger.info(f"Scanare finalizată. {self.total_sessions} sesiuni procesate cu succes")
            
            return True
            
        except Exception as e:
            logger.error(f"Eroare la scanarea log-urilor: {str(e)}")
            return False
    
    def analyze_attack_distribution(self):
        # resetam dictionarul
        self.attack_distribution = {
            'system_recon': 0,
            'privilege_escalation': 0,
            'data_exfiltration': 0,
            'persistence': 0,
            'honeypot_detection': 0,
            'network_scanning': 0,
            'brute_force': 0,
            'file_access': 0,
            'malware_upload': 0,
            'lateral_movement': 0
        }
        
        # resetam si categoriile de comenzi
        self.categorized_commands = defaultdict(list)
        
        # ne plimbam prin fiecare sesiune
        for session in self.sessions_data:
            # extragem comenzile
            commands = []
            for cmd_entry in session.get('commands', []):
                if isinstance(cmd_entry, dict) and 'command' in cmd_entry:
                    commands.append(cmd_entry['command'])
            
            # clasificam comenzile
            if commands:
                categories = classify_attack(commands)
                
                # actualizam distributia
                for category, cmd_list in categories.items():
                    self.attack_distribution[category] += len(cmd_list)
                    
                    # salvam comenzile categorizate pentru mai tarziu
                    for cmd in cmd_list:
                        self.categorized_commands[category].append({
                            'command': cmd,
                            'session': session.get('file_name', 'unknown')
                        })
        
        # calculam procentajele
        total_categorized = sum(self.attack_distribution.values())
        
        if total_categorized > 0:
            percentages = {}
            for category, count in self.attack_distribution.items():
                percentages[category] = (count / total_categorized) * 100
        else:
            percentages = {category: 0 for category in self.attack_distribution}
        
        # adaugam procentajele la rezultat
        result = {
            'counts': self.attack_distribution,
            'percentages': percentages,
            'total_categorized': total_categorized
        }
        
        logger.info(f"Analiza distribuției atacurilor completă: {total_categorized} comenzi categorizate")
        return result
    
    def analyze_geographic_distribution(self):
        # resetam dictionarul
        self.geographic_distribution = {
            'countries': Counter(),
            'cities': Counter(),
            'total_ips': 0,
            'unique_ips': set()
        }
        
        # ne plimbam prin fiecare sesiune
        for session in self.sessions_data:
            ip_info = session.get('ip_info', {})
            ip = ip_info.get('ip')
            
            if ip:
                self.geographic_distribution['total_ips'] += 1
                self.geographic_distribution['unique_ips'].add(ip)
                
                country = ip_info.get('country', 'Unknown')
                city = ip_info.get('city', 'Unknown')
                
                self.geographic_distribution['countries'][country] += 1
                self.geographic_distribution['cities'][city] += 1
        
        # convertim set-ul in numar
        self.geographic_distribution['unique_ips'] = len(self.geographic_distribution['unique_ips'])
        
        # sortam contoarele dupa frecventa
        self.geographic_distribution['countries'] = dict(self.geographic_distribution['countries'].most_common())
        self.geographic_distribution['cities'] = dict(self.geographic_distribution['cities'].most_common())
        
        logger.info(f"Analiza distribuției geografice completă: {self.geographic_distribution['unique_ips']} IP-uri unice")
        return self.geographic_distribution
    
    def analyze_time_patterns(self):
        # resetam distributiile
        self.hourly_distribution = [0] * 24
        self.daily_distribution = [0] * 7
        
        # structura pentru rezultat
        time_patterns = {
            'hourly': self.hourly_distribution,
            'daily': self.daily_distribution,
            'peak_hour': 0,
            'peak_day': 0
        }
        
        # ne plimbam prin fiecare sesiune
        for session in self.sessions_data:
            # vedem daca avem un timestamp de inceput valid
            start_time_str = session.get('header', {}).get('start_time')
            
            if start_time_str:
                try:
                    # convertim string-ul in obiect datetime
                    try:
                        start_time = datetime.datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S.%f')
                    except ValueError:
                        start_time = datetime.datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S')
                    
                    # incrementam contorii pentru ora si zi
                    hour = start_time.hour
                    day = start_time.weekday()  # 0 = luni, 6 = duminica
                    
                    self.hourly_distribution[hour] += 1
                    self.daily_distribution[day] += 1
                    
                except Exception as e:
                    logger.error(f"Eroare la parsarea timestamp-ului: {start_time_str}, eroare: {str(e)}")
        
        # gasim ora si ziua de varf
        time_patterns['peak_hour'] = self.hourly_distribution.index(max(self.hourly_distribution))
        time_patterns['peak_day'] = self.daily_distribution.index(max(self.daily_distribution))
        
        # convertim listele la dictionare pentru rezultat
        time_patterns['hourly'] = {hour: count for hour, count in enumerate(self.hourly_distribution)}
        time_patterns['daily'] = {day: count for day, count in enumerate(self.daily_distribution)}
        
        logger.info(f"Analiza modelelor temporale completă: ora de vârf {time_patterns['peak_hour']}, ziua de vârf {time_patterns['peak_day']}")
        return time_patterns
    
    def analyze_command_frequency(self):
        # resetam contorul
        self.command_frequency = Counter()
        
        # colectam toate comenzile din toate sesiunile
        for session in self.sessions_data:
            for cmd_entry in session.get('commands', []):
                if isinstance(cmd_entry, dict) and 'command' in cmd_entry:
                    # normalizam comanda pentru clasificare
                    normalized = normalize_command(cmd_entry['command'])
                    self.command_frequency[normalized] += 1
        
        logger.info(f"Analiza frecvenței comenzilor completă: {len(self.command_frequency)} comenzi unice")
        return self.command_frequency
    
    def analyze_attack_sophistication(self):
        # aici o sa tinem rezultatele
        sophistication = {
            'average_score': 0,
            'max_score': 0,
            'min_score': 10,
            'session_scores': {},
            'sophistication_distribution': {
                'low': 0,      # 1-3
                'medium': 0,   # 4-6
                'high': 0      # 7-10
            }
        }
        
        # folosim categoriile de comenzi deja calculate
        if not self.categorized_commands:
            self.analyze_attack_distribution()
        
        # calculam scorul pentru fiecare sesiune
        total_score = 0
        session_count = 0
        
        for session in self.sessions_data:
            session_name = session.get('file_name', 'unknown')
            
            # colectam categoriile de atac pentru sesiunea asta
            session_categories = {}
            for category, commands in self.categorized_commands.items():
                session_cmd_list = [cmd for cmd in commands if cmd['session'] == session_name]
                if session_cmd_list:
                    session_categories[category] = [cmd['command'] for cmd in session_cmd_list]
            
            # calculam scorul
            if session_categories:
                # diversitatea categoriilor (cate categorii diferite de atac)
                diversity = len([cat for cat, cmds in session_categories.items() if cmds])
                
                # complexitatea comenzilor (numarul mediu de comenzi per categorie)
                cmd_count = sum(len(cmds) for cmds in session_categories.values())
                complexity = cmd_count / len(session_categories) if len(session_categories) > 0 else 0
                
                # prezenta categoriilor critice
                critical_categories = ['privilege_escalation', 'persistence', 'data_exfiltration', 'malware_upload']
                critical_score = sum(1 for cat in critical_categories if cat in session_categories and session_categories[cat])
                
                # calculam scorul final
                score = min(10, (diversity * 1.5 + complexity * 0.5 + critical_score * 2) / 4)
                
                # rotunjim la numar intreg
                score = round(score)
                
                # actualizam statisticile
                sophistication['session_scores'][session_name] = score
                total_score += score
                session_count += 1
                
                # actualizam max si min
                sophistication['max_score'] = max(sophistication['max_score'], score)
                sophistication['min_score'] = min(sophistication['min_score'], score)
                
                # actualizam distributia
                if score >= 1 and score <= 3:
                    sophistication['sophistication_distribution']['low'] += 1
                elif score >= 4 and score <= 6:
                    sophistication['sophistication_distribution']['medium'] += 1
                elif score >= 7:
                    sophistication['sophistication_distribution']['high'] += 1
        
        # calculam scorul mediu
        if session_count > 0:
            sophistication['average_score'] = total_score / session_count
        
        logger.info(f"Analiza sofisticării atacurilor completă: scor mediu {sophistication['average_score']:.2f}")
        return sophistication
    
    def get_statistics(self):
        # vedem daca avem date scanate
        if not self.sessions_data:
            logger.warning("Nu există date scanate pentru a genera statistici")
            return {}
        
        # colectam toate statisticile
        statistics = {
            'total_sessions': self.total_sessions,
            'attack_distribution': self.analyze_attack_distribution(),
            'geographic_distribution': self.analyze_geographic_distribution(),
            'time_patterns': self.analyze_time_patterns(),
            'top_commands': self.get_top_commands(10),
            'attack_sophistication': self.analyze_attack_sophistication()
        }
        
        # calculam durata medie a sesiunilor
        total_duration = datetime.timedelta(0)
        valid_sessions = 0
        
        for session in self.sessions_data:
            duration = session.get('duration')
            if duration and duration.total_seconds() > 0:  # adaugam verificarea pentru durata pozitiva
                total_duration += duration
                valid_sessions += 1
        
        if valid_sessions > 0:
            statistics['average_duration'] = str(total_duration / valid_sessions)
        else:
            statistics['average_duration'] = "0:00:00"
        
        logger.info(f"Statistici generate cu succes pentru {self.total_sessions} sesiuni")
        return statistics
    


    def get_hourly_distribution(self):
        # vedem daca avem deja analiza temporala
        if all(x == 0 for x in self.hourly_distribution):
            self.analyze_time_patterns()
        
        # formatam rezultatul sa fie mai usor de folosit
        result = {hour: count for hour, count in enumerate(self.hourly_distribution)}
        
        return result
    
    def get_top_commands(self, limit=10):
        # vedem daca avem analiza frecventei comenzilor
        if not self.command_frequency:
            self.analyze_command_frequency()
        
        # luam cele mai frecvente comenzi
        top_commands = dict(self.command_frequency.most_common(limit))
        
        return top_commands

    def get_most_interesting_logs(self, count=3):
        if not self.sessions_data:
            logger.warning("Nu există date scanate pentru a identifica log-uri interesante")
            return []
        
        # calculam scorul de "interesanta" pentru fiecare sesiune
        session_scores = []
        
        for session in self.sessions_data:
            score = self._calculate_interest_score(session)
            
            session_scores.append({
                'file_name': session.get('file_name', 'unknown'),
                'file_path': session.get('file_path', ''),
                'score': score,
                'details': self._get_session_summary(session)
            })
        
        # sortam dupa scor (descrescator)
        session_scores.sort(key=lambda x: x['score'], reverse=True)
        
        # returnam top x log-uri
        top_logs = session_scores[:count]
        
        logger.info(f"Identificate {len(top_logs)} log-uri interesante din {len(self.sessions_data)} total")
        
        # returnam doar numele fisierelor
        return [log['file_name'] for log in top_logs]

    def _calculate_interest_score(self, session):
        score = 0
        
        # 1. numarul de comenzi (mai multe comenzi = mai interesant)
        commands = session.get('commands', [])
        command_count = len(commands)
        score += min(command_count * 0.5, 20)  # max 20 puncte
        
        # 2. durata sesiunii (sesiuni mai lungi = mai interesante)
        duration = session.get('duration')
        if duration and hasattr(duration, 'total_seconds'):
            duration_minutes = duration.total_seconds() / 60
            score += min(duration_minutes * 0.2, 15)  # max 15 puncte
        
        # 3. diversitatea comenzilor (comenzi unice)
        if commands:
            unique_commands = set()
            for cmd_entry in commands:
                if isinstance(cmd_entry, dict) and 'command' in cmd_entry:
                    unique_commands.add(normalize_command(cmd_entry['command']))
            
            diversity_ratio = len(unique_commands) / len(commands) if len(commands) > 0 else 0
            score += diversity_ratio * 10  # max 10 puncte
        
        # 4. prezenta categoriilor critice
        critical_categories = ['privilege_escalation', 'persistence', 'data_exfiltration', 'malware_upload']
        session_commands = [cmd_entry.get('command', '') for cmd_entry in commands if isinstance(cmd_entry, dict)]
        
        if session_commands:
            categories = classify_attack(session_commands)
            critical_present = sum(1 for cat in critical_categories if categories.get(cat, []))
            score += critical_present * 8  # max 32 puncte pentru toate categoriile critice
        
        # 5. comenzi rare/neobisnuite
        if hasattr(self, 'command_frequency') and self.command_frequency:
            rare_commands = 0
            for cmd_entry in commands:
                if isinstance(cmd_entry, dict) and 'command' in cmd_entry:
                    normalized = normalize_command(cmd_entry['command'])
                    frequency = self.command_frequency.get(normalized, 0)
                    if frequency <= 2:  # comenzi foarte rare
                        rare_commands += 1
            
            score += min(rare_commands * 1.5, 10)  # max 10 puncte
        
        return round(score, 2)

    def _get_session_summary(self, session):
        commands = session.get('commands', [])
        ip_info = session.get('ip_info', {})
        
        return {
            'command_count': len(commands),
            'duration': str(session.get('duration', 'N/A')),
            'ip': ip_info.get('ip', 'Unknown'),
            'country': ip_info.get('country', 'Unknown')
        }

    def get_detailed_interesting_logs(self, count=3):
        if not self.sessions_data:
            return []
        
        session_scores = []
        
        for session in self.sessions_data:
            score = self._calculate_interest_score(session)
            
            session_scores.append({
                'file_name': session.get('file_name', 'unknown'),
                'file_path': session.get('file_path', ''),
                'score': score,
                'summary': self._get_session_summary(session)
            })
        
        # sortam si returnam top x
        session_scores.sort(key=lambda x: x['score'], reverse=True)
        return session_scores[:count]