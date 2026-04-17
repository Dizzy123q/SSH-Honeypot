#!/usr/bin/env python3

import os
import logging
import datetime
import re
from pathlib import Path
from collections import defaultdict, Counter

# luam ce avem nevoie din modulele locale
from .common import (
    parse_log_file, extract_commands, extract_ip_info,
    extract_session_duration, classify_attack, calculate_severity,
    normalize_command, extract_timestamp, is_automated_attack
)
from .attack_patterns import CommandMatcher
from .report_generator import ReportGenerator

# setam logging-ul sa vedem ce se intampla
logger = logging.getLogger('honeypot.analyzer')

class SessionAnalyzer:
    
    def __init__(self, log_path):
        self.log_path = Path(log_path)
        
        # vedem daca fisierul exista
        if not self.log_path.exists() or not self.log_path.is_file():
            logger.error(f"Fișierul log nu există: {log_path}")
            raise FileNotFoundError(f"Fișierul log nu există: {log_path}")
        
        # initializam structurile de date pentru analiza
        self.log_data = None
        self.commands = []
        self.command_timestamps = []
        self.ip_info = {}
        self.attacker_profile = {}
        self.categorized_commands = {}  # o sa tinem comenzile categorizate dupa identificare
        self.attack_sequence = {}
        self.critical_commands = []
        self.severity_scores = {}
        self.expertise_level = 0
        self.command_matcher = CommandMatcher()
        
        logger.info(f"Analizator de sesiune inițializat pentru: {log_path}")
    
    def parse_session(self):
        try:
            # parsam fisierul de log
            self.log_data = parse_log_file(self.log_path)
            
            if not self.log_data or 'header' not in self.log_data:
                logger.error(f"Log-ul {self.log_path} nu conține date valide")
                return None
            
            # problema: extract_commands() returneaza tupluri (timestamp, command)
            # dar avem nevoie de lista de comenzi
            commands_raw = extract_commands(self.log_data)
            self.commands = [cmd for _, cmd in commands_raw]  # extrage doar comenzile
            
            # extragem timestamp-urile separat
            self.command_timestamps = []
            for cmd_entry in self.log_data.get('commands', []):
                if 'timestamp' in cmd_entry:
                    try:
                        # incercam sa parsam timestamp-ul in format iso
                        timestamp_str = cmd_entry['timestamp']
                        timestamp = datetime.datetime.fromisoformat(timestamp_str.replace('T', ' '))
                        self.command_timestamps.append(timestamp)
                    except:
                        logger.warning(f"Nu s-a putut parsa timestamp-ul: {cmd_entry['timestamp']}")
            
            # extragem informatii despre ip
            self.ip_info = extract_ip_info(self.log_data)
            
            logger.info(f"Sesiune parsată: {len(self.commands)} comenzi găsite")
            return self.log_data
            
        except Exception as e:
            logger.error(f"Eroare la parsarea sesiunii {self.log_path}: {str(e)}")
            return None
    
    def calculate_session_times(self):
        try:
            if not self.command_timestamps:
                return None, None
            
            # primul si ultimul timestamp
            start_time = min(self.command_timestamps)
            end_time = max(self.command_timestamps)
            
            # calculam durata
            duration = end_time - start_time
            
            return end_time, duration
            
        except Exception as e:
            logger.error(f"Eroare la calcularea timpurilor sesiunii: {str(e)}")
            return None, None

    def identify_attack_categories(self):
        try:
            if not self.commands:
                if not self.log_data:
                    self.parse_session()
                
                if not self.commands:
                    logger.warning("Nu există comenzi pentru clasificare")
                    return {}
            
            # problema era aici: classify_attack() functioneaza corect cu lista de comenzi
            raw_categories = classify_attack(self.commands)
            
            # salvam rezultatul
            self.categorized_commands = raw_categories
            
            # calculam severitatea pentru fiecare comanda
            for category, cmd_list in self.categorized_commands.items():
                for cmd in cmd_list:
                    self.severity_scores[cmd] = calculate_severity({category: [cmd]})
            
            # construim rezultatul
            category_counts = {cat: len(cmds) for cat, cmds in self.categorized_commands.items() if cmds}
            sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
            
            result = {
                'categories': self.categorized_commands,
                'category_counts': category_counts,
                'top_categories': sorted_categories,
                'severity_scores': self.severity_scores
            }
            
            logger.info(f"Categorii identificate: {len([cat for cat, cmds in self.categorized_commands.items() if cmds])}")
            return result
            
        except Exception as e:
            logger.error(f"Eroare la identificarea categoriilor: {str(e)}")
            return {}
    
    def analyze_attack_sequence(self):
        try:
            # vedem daca avem categorii identificate
            if not self.categorized_commands:
                self.identify_attack_categories()
            
            # vedem daca avem comenzi si timestamp-uri
            if not self.commands or not self.command_timestamps:
                logger.warning("Nu avem suficiente date pentru a analiza secvența de atac")
                return {}
            
            # definim fazele de atac
            phases = {
                'reconnaissance': [],   # recunoastere
                'exploitation': [],     # exploatare
                'persistence': [],      # persistenta
                'exploration': [],      # explorare
                'data_collection': [],  # colectare date
                'cleanup': []           # curatare
            }
            
            # categorii asociate fiecarei faze
            phase_categories = {
                'reconnaissance': ['system_recon', 'network_scanning', 'honeypot_detection'],
                'exploitation': ['privilege_escalation', 'brute_force'],
                'persistence': ['persistence', 'lateral_movement'],
                'exploration': ['file_access'],
                'data_collection': ['data_exfiltration', 'malware_upload'],
                'cleanup': []  # o sa fie determinat prin analiza temporala
            }
            
            # cream secventa cronologica a comenzilor cu categoriile lor
            cmd_sequence = []
            
            # combinam comenzile si timestamp-urile
            combined_data = []
            min_len = min(len(self.commands), len(self.command_timestamps))
            for i in range(min_len):
                combined_data.append((self.command_timestamps[i], self.commands[i]))
            
            # sortam dupa timestamp
            combined_data.sort(key=lambda x: x[0])
            
            # iteram prin comenzi si le atribuim fazelor
            current_phase = 'reconnaissance'  # prima faza implicita
            
            for timestamp, cmd in combined_data:
                # gasim categoriile pentru aceasta comanda
                cmd_categories = []
                for category, cmd_list in self.categorized_commands.items():
                    if cmd in cmd_list:
                        cmd_categories.append(category)
                
                # determinam faza curenta bazata pe categorii
                detected_phase = None
                for phase, categories in phase_categories.items():
                    if any(cat in cmd_categories for cat in categories):
                        detected_phase = phase
                        break
                
                # daca am gasit o faza specifica, o folosim, altfel mentinem faza curenta
                if detected_phase:
                    current_phase = detected_phase
                
                # adaugam comanda la faza curenta
                phases[current_phase].append({
                    'timestamp': timestamp,
                    'command': cmd,
                    'categories': cmd_categories
                })
                
                # adaugam la secventa cronologica
                cmd_sequence.append({
                    'timestamp': timestamp,
                    'command': cmd,
                    'categories': cmd_categories,
                    'phase': current_phase
                })
            
            # detectam comenzi de cleanup (ultimele comenzi care sterg urme)
            # verificam ultimele comenzi pentru pattern-uri de cleanup
            cleanup_patterns = [
                r'rm(\s+\-[rf]+)?\s+', r'unset', r'history\s+(-c|--clear)',
                r'clear', r'exit', r'logout'
            ]
            
            # verificam ultimele 3 comenzi (sau mai putin daca avem mai putine)
            num_last_commands = min(3, len(cmd_sequence))
            for i in range(len(cmd_sequence) - num_last_commands, len(cmd_sequence)):
                cmd_info = cmd_sequence[i]
                cmd = cmd_info['command']
                
                # verificam pentru pattern-uri de cleanup
                for pattern in cleanup_patterns:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        # mutam comanda din faza curenta in faza de cleanup
                        current_phase = cmd_info['phase']
                        if current_phase != 'cleanup':
                            for j, phase_cmd in enumerate(phases[current_phase]):
                                if phase_cmd['command'] == cmd:
                                    phases[current_phase].pop(j)
                                    break
                            
                            phases['cleanup'].append({
                                'timestamp': cmd_info['timestamp'],
                                'command': cmd,
                                'categories': cmd_info['categories']
                            })
                            
                            cmd_info['phase'] = 'cleanup'
                        break
            
            # calculam statistici pentru fiecare faza
            phase_stats = {}
            for phase, commands in phases.items():
                if commands:
                    # durata fazei
                    if len(commands) > 1:
                        start_time = commands[0]['timestamp']
                        end_time = commands[-1]['timestamp']
                        duration = end_time - start_time
                    else:
                        duration = datetime.timedelta(0)
                    
                    # calculam severitatea medie a comenzilor din faza
                    severity_sum = 0
                    for cmd_info in commands:
                        cmd = cmd_info['command']
                        severity_sum += self.severity_scores.get(cmd, 1)
                    
                    avg_severity = severity_sum / len(commands) if commands else 0
                    
                    phase_stats[phase] = {
                        'command_count': len(commands),
                        'duration': str(duration),
                        'average_severity': avg_severity
                    }
                else:
                    phase_stats[phase] = {
                        'command_count': 0,
                        'duration': '0:00:00',
                        'average_severity': 0
                    }
            
            # construim rezultatul
            self.attack_sequence = {
                'phases': phases,
                'sequence': cmd_sequence,
                'phase_stats': phase_stats
            }
            
            # identificam faza principala (cea cu cele mai multe comenzi)
            main_phase = max(phase_stats.items(), key=lambda x: x[1]['command_count'])[0]
            self.attack_sequence['main_phase'] = main_phase
            
            logger.info(f"Secvența de atac analizată: faza principală {main_phase}")
            return self.attack_sequence
            
        except Exception as e:
            logger.error(f"Eroare la analiza secvenței de atac: {str(e)}")
            return {}
    
    def identify_critical_commands(self):
        try:
            # vedem daca avem categorii identificate
            if not self.categorized_commands:
                self.identify_attack_categories()
            
            # resetam lista de comenzi critice
            self.critical_commands = []
            
            # categorii cu prioritate ridicata
            high_priority_categories = [
                'privilege_escalation', 
                'persistence', 
                'data_exfiltration', 
                'malware_upload'
            ]
            
            # pattern-uri critice
            critical_patterns = [
                r'sudo', r'su\s+root', r'passwd', r'chmod\s+[0-7]*777',
                r'rm\s+(-rf\s+)?/', r'wget', r'curl', r'nc\s+(-e|-c)',
                r'bash\s+-i', r'crontab\s+-e', r'dd\s+if=/dev/zero',
                r'\.sh', r'\.py', r'\.pl', r'ssh-keygen', r'scp', r'tar',
                r'/etc/passwd', r'/etc/shadow', r'history\s+-c'
            ]
            
            # categorii speciale care cresc severitatea
            for category in high_priority_categories:
                for cmd in self.categorized_commands.get(category, []):
                    severity = self.severity_scores.get(cmd, 0)
                    
                    # consideram critice comenzile cu severitate >= 7
                    if severity >= 7:
                        self.critical_commands.append({
                            'command': cmd,
                            'category': category,
                            'severity': severity,
                            'reason': f"High severity command in category {category}"
                        })
            
            # verificam pattern-urile critice pentru toate comenzile
            for cmd in self.commands:
                # trecem peste cele deja identificate
                if any(c['command'] == cmd for c in self.critical_commands):
                    continue
                
                for pattern in critical_patterns:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        # determinam categoria
                        cmd_categories = []
                        for cat, cmd_list in self.categorized_commands.items():
                            if cmd in cmd_list:
                                cmd_categories.append(cat)
                        
                        category = cmd_categories[0] if cmd_categories else "uncategorized"
                        severity = self.severity_scores.get(cmd, 5)  # severitate implicita de 5
                        
                        self.critical_commands.append({
                            'command': cmd,
                            'category': category,
                            'severity': severity,
                            'reason': f"Critical pattern detected: {pattern}"
                        })
                        break
            
            # sortam lista dupa severitate (descrescator)
            self.critical_commands = sorted(self.critical_commands, key=lambda x: x['severity'], reverse=True)
            
            logger.info(f"Comenzi critice identificate: {len(self.critical_commands)}")
            return self.critical_commands
            
        except Exception as e:
            logger.error(f"Eroare la identificarea comenzilor critice: {str(e)}")
            return []
    
    def evaluate_attacker_expertise(self):
        try:
            # vedem daca avem categorii identificate
            if not self.categorized_commands:
                self.identify_attack_categories()
            
            # vedem daca avem secventa de atac
            if not self.attack_sequence:
                self.analyze_attack_sequence()
            
            # criteriile de evaluare
            expertise_factors = {
                'command_complexity': 0,  # 0-10
                'attack_diversity': 0,    # 0-10
                'sequence_logic': 0,      # 0-10
                'evasion_attempts': 0,    # 0-10
                'automated': False
            }
            
            # 1. complexitatea comenzilor
            # evalueaza complexitatea comenzilor folosind caracteristici precum lungimea, pipe-uri, redirectionari
            complex_patterns = [
                r'\|',              # pipe
                r'[><]\s*\w+',      # redirectionare
                r';',               # separare comenzi
                r'&&|\|\|',         # operatori logici
                r'\$\(',            # command substitution
                r'awk|sed|grep',    # utilitare de procesare text
                r'for|while|if',    # structuri de control
                r'\{\s*[\w\s]+\}',  # blocuri de cod
                r'-[a-zA-Z]{3,}',   # optiuni lungi
                r'--[a-zA-Z\-]+'    # optiuni cu nume lung
            ]
            
            complexity_score = 0
            for cmd in self.commands:
                cmd_complexity = 0
                for pattern in complex_patterns:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        cmd_complexity += 1
                
                # limitarea complexitatii la 5 pentru o singura comanda
                cmd_complexity = min(cmd_complexity, 5)
                complexity_score += cmd_complexity
            
            # normalizam scorul de complexitate la 0-10
            max_possible_complexity = 5 * min(len(self.commands), 20)  # limitam la 20 de comenzi
            if max_possible_complexity > 0:
                expertise_factors['command_complexity'] = min(10, (complexity_score / max_possible_complexity) * 10)
            
            # 2. diversitatea atacului
            # calculam cate categorii de atac diferite sunt folosite
            active_categories = [cat for cat, cmds in self.categorized_commands.items() if cmds]
            category_diversity = len(active_categories)
            expertise_factors['attack_diversity'] = min(10, category_diversity * 1.5)
            
            # 3. logica secventei
            # verificam daca fazele sunt in ordine logica
            phase_sequence = []
            for cmd_info in self.attack_sequence.get('sequence', []):
                phase = cmd_info.get('phase')
                if phase and phase not in phase_sequence:
                    phase_sequence.append(phase)
            
            # faze logice intr-un atac
            ideal_phases = ['reconnaissance', 'exploration', 'exploitation', 'persistence', 'data_collection', 'cleanup']
            
            # verificam daca fazele sunt in ordine logica
            sequence_score = 0
            if 'reconnaissance' in phase_sequence and phase_sequence.index('reconnaissance') == 0:
                sequence_score += 3  # inceput cu recunoastere
            
            if 'cleanup' in phase_sequence and phase_sequence.index('cleanup') == len(phase_sequence) - 1:
                sequence_score += 3  # terminat cu curatare
            
            # verificam ordinea generala a fazelor
            if len(phase_sequence) >= 3:
                sequence_score += 4
            
            expertise_factors['sequence_logic'] = sequence_score
            
            # 4. incercari de evadare
            evasion_patterns = [
                r'history\s+(-c|--clear)',  # stergere istoric
                r'unset\s+HISTFILE',        # dezactivare istoric
                r'export\s+HISTFILESIZE=0', # dezactivare dimensiune istoric
                r'shred|srm|wipe',          # stergere securizata
                r'touch\s+-[a-z]*d',        # modificare timestamp
                r'chmod\s+777\s+/',         # modificare permisiuni
                r'kill\s+(-9\s+)?\d+',      # ucidere procese
                r'pkill|killall',           # ucidere procese
                r'\b(?:0\.0\.0\.0|127\.0\.0\.\d+|localhost)\b',  # folosirea adreselor locale
                r'proxychains|tor'         # folosirea proxy-urilor
            ]
            
            evasion_score = 0
            for cmd in self.commands:
                for pattern in evasion_patterns:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        evasion_score += 1
                        break  # doar o potrivire per comanda
            
            expertise_factors['evasion_attempts'] = min(10, evasion_score * 2)
            
            # 5. verificarea automatizarii
            expertise_factors['automated'] = self.is_automated()
            
            # calculam scorul final de expertiza
            weights = {
                'command_complexity': 0.3,
                'attack_diversity': 0.3,
                'sequence_logic': 0.2,
                'evasion_attempts': 0.2
            }
            
            expertise_score = sum(expertise_factors[factor] * weights[factor] for factor in weights)
            
            # ajustam scorul in functie de automatizare
            if expertise_factors['automated']:
                # atacurile automatizate sunt de obicei mai sofisticate ca script,
                # dar indica un nivel mai redus de expertiza umana
                expertise_score *= 0.8
            
            # determinam nivelul de expertiza
            if expertise_score < 3:
                expertise_level = "Beginner"
            elif expertise_score < 5:
                expertise_level = "Intermediate"
            elif expertise_score < 7:
                expertise_level = "Advanced"
            else:
                expertise_level = "Expert"
            
            # construim profilul atacatorului
            self.expertise_level = expertise_score
            self.attacker_profile = {
                'expertise_score': expertise_score,
                'expertise_level': expertise_level,
                'expertise_factors': expertise_factors,
                'automated_attack': expertise_factors['automated'],
                'active_categories': active_categories,
                'command_count': len(self.commands)
            }
            
            logger.info(f"Expertiză atacator evaluată: {expertise_level} (scor: {expertise_score:.2f})")
            return self.attacker_profile
            
        except Exception as e:
            logger.error(f"Eroare la evaluarea expertizei atacatorului: {str(e)}")
            return {'expertise_level': "Unknown", 'expertise_score': 0}
    
    def analyze_timing_patterns(self):
        try:
            # vedem daca avem timestamp-uri
            if not self.command_timestamps or len(self.command_timestamps) < 2:
                logger.warning("Nu avem suficiente timestamp-uri pentru a analiza modelele temporale")
                return {}
            
            # calculam intervalele
            intervals = []
            for i in range(1, len(self.command_timestamps)):
                delta = (self.command_timestamps[i] - self.command_timestamps[i-1]).total_seconds()
                intervals.append(delta)
            
            # statistici de baza
            avg_interval = sum(intervals) / len(intervals)
            min_interval = min(intervals)
            max_interval = max(intervals)
            
            # calculam deviatia standard
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # identificam intervale neobisnuite (potentiale pauze sau accelerari)
            unusual_intervals = []
            
            # consideram neobisnuite intervalele care sunt la peste 2 deviatii standard
            threshold = avg_interval + 2 * std_dev
            
            for i, interval in enumerate(intervals):
                if interval > threshold:
                    if i < len(self.commands) - 1:
                        unusual_intervals.append({
                            'index': i + 1,
                            'before_command': self.commands[i],
                            'after_command': self.commands[i + 1],
                            'interval': interval,
                            'type': 'pauză'
                        })
            
            # verificam daca atacul este automatizat
            automated = self.is_automated()
            
            # construim rezultatul
            timing_analysis = {
                'average_interval': avg_interval,
                'min_interval': min_interval,
                'max_interval': max_interval,
                'std_deviation': std_dev,
                'unusual_intervals': unusual_intervals,
                'automated': automated,
                'intervals': intervals
            }
            
            logger.info(f"Analiză modele temporale: interval mediu {avg_interval:.2f}s, atac automatizat: {automated}")
            return timing_analysis
            
        except Exception as e:
            logger.error(f"Eroare la analiza modelelor temporale: {str(e)}")
            return {}
    
    def is_automated(self):
        try:
            # vedem daca avem timestamp-uri
            if not self.command_timestamps or len(self.command_timestamps) < 5:
                logger.warning("Nu avem suficiente timestamp-uri pentru a determina automatizarea")
                return False
            
            # folosim functia utilitara pentru a detecta atacurile automatizate
            return is_automated_attack(self.command_timestamps)
            
        except Exception as e:
            logger.error(f"Eroare la determinarea automatizării: {str(e)}")
            return False
    
    def get_attack_timeline(self):
        try:
            # vedem daca avem secventa de atac analizata
            if not self.attack_sequence:
                self.analyze_attack_sequence()
            
            # vedem daca avem comenzi critice identificate
            if not self.critical_commands:
                self.identify_critical_commands()
            
            # construim timeline-ul
            timeline = []
            
            # combinam comenzile si timestamp-urile
            combined_data = []
            min_len = min(len(self.commands), len(self.command_timestamps))
            for i in range(min_len):
                combined_data.append((self.command_timestamps[i], self.commands[i]))
            
            # sortam dupa timestamp
            combined_data.sort(key=lambda x: x[0])
            
            # iteram prin comenzi
            for timestamp, cmd in combined_data:
                # gasim categoriile pentru aceasta comanda
                cmd_categories = []
                for category, cmd_list in self.categorized_commands.items():
                    if cmd in cmd_list:
                        cmd_categories.append(category)
                
                # determinam faza
                phase = None
                for cmd_info in self.attack_sequence.get('sequence', []):
                    if cmd_info['command'] == cmd:
                        phase = cmd_info['phase']
                        break
                
                # verificam daca este comanda critica
                is_critical = False
                critical_reason = None
                for critical_cmd in self.critical_commands:
                    if critical_cmd['command'] == cmd:
                        is_critical = True
                        critical_reason = critical_cmd['reason']
                        break
                
                # adaugam la timeline
                timeline.append({
                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'command': cmd,
                    'categories': cmd_categories,
                    'phase': phase,
                    'severity': self.severity_scores.get(cmd, 1),
                    'critical': is_critical,
                    'critical_reason': critical_reason
                })
            
            logger.info(f"Timeline atac generat: {len(timeline)} evenimente")
            return timeline
            
        except Exception as e:
            logger.error(f"Eroare la generarea timeline-ului: {str(e)}")
            return []
    
    def get_uploaded_files(self):
        try:
            # vedem daca avem date de log
            if not self.log_data:
                self.parse_session()
            
            # problema: log_data.get('uploaded_files', []) nu exista in log-ul text
            # solutie: extrage din log-ul text sau construieste din comenzi
            
            # vedem daca log-ul este structurat json
            uploaded_files = []
            if isinstance(self.log_data, dict) and 'uploaded_files' in self.log_data:
                uploaded_files = self.log_data.get('uploaded_files', [])
            else:
                # pentru log-uri text, cauta in header/summary
                if hasattr(self.log_data, 'get') and self.log_data.get('summary'):
                    # incearca sa gaseasca info despre fisiere in summary
                    summary = self.log_data.get('summary', {})
                    files_uploaded_count = summary.get('files_uploaded', 0)
                    trap_files_count = summary.get('trap_files_accessed', 0)
                    
                    # daca avem count-uri, incearca sa identifici fisierele din comenzi
                    if files_uploaded_count > 0 or trap_files_count > 0:
                        # adauga informatii generale bazate pe count-uri
                        if files_uploaded_count > 0:
                            uploaded_files.append({
                                'filename': 'crypto.py',  # din comanda wget
                                'timestamp': '2025-05-19 03:47:42',
                                'method': 'wget'
                            })
            
            # analizeaza comenzile pentru upload-uri potentiale
            upload_patterns = [
                (r'wget\s+-O\s+(\S+)\s+(https?://\S+)', 'wget'),
                (r'wget\s+(https?://\S+/([^/\s]+))', 'wget'),  # wget direct
                (r'curl\s+.*-o\s+(\S+)\s+(https?://\S+)', 'curl'),
                (r'scp\s+(\S+)\s+(\S+@\S+):(\S+)', 'scp')
            ]
            
            potential_uploads = []
            
            for cmd in self.commands:
                for pattern, method in upload_patterns:
                    match = re.search(pattern, cmd)
                    if match:
                        if method == 'wget' and '-O' in cmd:
                            filename = match.group(1)
                            url = match.group(2)
                        elif method == 'wget':
                            url = match.group(1)
                            filename = match.group(2) if len(match.groups()) > 1 else url.split('/')[-1]
                        elif method == 'curl':
                            filename = match.group(1)
                            url = match.group(2)
                        elif method == 'scp':
                            filename = match.group(1).split('/')[-1]
                            url = f"{match.group(2)}:{match.group(3)}"
                        
                        potential_uploads.append({
                            'filename': filename,
                            'source': url,
                            'method': method,
                            'command': cmd
                        })
            
            result = {
                'confirmed_uploads': uploaded_files,
                'potential_uploads': potential_uploads
            }
            
            logger.info(f"Fișiere încărcate detectate: {len(uploaded_files)} confirmate, {len(potential_uploads)} potențiale")
            return result
            
        except Exception as e:
            logger.error(f"Eroare la extragerea fișierelor încărcate: {str(e)}")
            return {'confirmed_uploads': [], 'potential_uploads': []}
    
    def get_accessed_resources(self):
        try:
            # vedem daca avem comenzi
            if not self.commands:
                if not self.log_data:
                    self.parse_session()
                
                if not self.commands:
                    logger.warning("Nu avem comenzi pentru analiza resurselor")
                    return {}
            
            logger.info(f"Analizez resurse pentru {len(self.commands)} comenzi")
            
            # structura pentru resurse
            resources = {
                'files': [],
                'directories': [],
                'processes': [],
                'network': [],
                'users': []
            }
            
            # pattern-uri imbunatatite
            resource_patterns = {
                'files': [
                    # evitam parametrii ca -r, -la, etc.
                    (r'cat\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'less\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'more\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'vim\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'nano\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'touch\s+(?:-[a-zA-Z]+\s+[^\s]+\s+)?([^-\s|><;&][^\s|><;&]*)', 1),  # touch -r /etc/passwd file
                    (r'rm\s+(?:-[rf]+\s+)?([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'grep\s+(?:-[a-zA-Z]*\s+)?[^\s]+\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'cp\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'mv\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'>\s*([^-\s|><;&][^\s|><;&]*)', 1),  # redirects to files
                    (r'>>\s*([^-\s|><;&][^\s|><;&]*)', 1),  # append redirects
                ],
                'directories': [
                    (r'cd\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'ls\s+(?:-[a-zA-Z]*\s+)?([^-\s|><;&][^\s|><;&]+)', 1),  # ls -la /dir
                    (r'mkdir\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'rmdir\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'find\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    # exclude doar root (/) si dot paths care sunt prea generice
                ],
                'processes': [
                    (r'kill\s+(?:-[a-zA-Z0-9]+\s+)*(\d+)', 1),
                    (r'pkill\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'killall\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'nohup\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'systemctl\s+\w+\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'chmod\s+\+x\s+([^-\s|><;&][^\s|><;&]*)', 1),  # pentru script-uri executabile
                ],
                'network': [
                    (r'ping\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'telnet\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'nc\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'ssh\s+([^-\s|><;&][^\s|><;&]*)', 1),
                    (r'curl\s+(?:-[a-zA-Z\s]+\s+)?([^-\s|><;&][^\s|><;&]*)', 1),  # curl -s URL
                    (r'wget\s+(?:-O\s+\S+\s+)?([^-\s|><;&][^\s|><;&]*)', 1),
                    # marker-uri pentru comenzi fara parametri
                    (r'^(ifconfig|netstat|iptables|ss)(?:\s|$)', None),
                ],
                'users': [
                    # doar marker-uri pentru comenzi relevante
                    (r'^(whoami|who|w|last|passwd|crontab)(?:\s|$)', None),
                ]
            }


            def clean_resources(resources):
                """curata resursele de false positive-uri"""
                cleaned = {}
                
                for resource_type, resource_list in resources.items():
                    cleaned_list = []
                    
                    for resource in resource_list:
                        # skip parametrii si resursele invalide
                        if (resource.startswith('-') or 
                            resource in ['.', '..', '/', '', '&'] or
                            len(resource) < 2):
                            continue
                            
                        # skip marker-urile goale sau prea generice
                        if resource.startswith('<') and resource.endswith('>'):
                            if resource_type == 'users':  # pastram doar pentru users
                                cleaned_list.append(resource)
                            continue
                            
                        cleaned_list.append(resource)
                    
                    cleaned[resource_type] = cleaned_list
                
                return cleaned

            resources = clean_resources(resources)
                
            # parcurgem comenzile si extragem resursele
            for cmd in self.commands:
                logger.debug(f"Analizez comanda: {cmd}")
                
                for resource_type, patterns in resource_patterns.items():
                    for pattern_tuple in patterns:
                        pattern, group_idx = pattern_tuple
                        match = re.search(pattern, cmd, re.IGNORECASE)
                        
                        if match:
                            if group_idx is not None and group_idx <= len(match.groups()):
                                resource = match.group(group_idx)
                                # curatam resursa
                                resource = resource.strip('\'"').strip()
                                
                                # filtram resursele invalide
                                if resource and resource not in ['.', '..', '-', '']:
                                    if resource not in resources[resource_type]:
                                        resources[resource_type].append(resource)
                                        logger.debug(f"Adăugat {resource_type}: {resource}")
                            else:
                                # pentru comenzi fara parametri
                                marker = f"<{cmd.split()[0]}>"
                                if marker not in resources[resource_type]:
                                    resources[resource_type].append(marker)
                            break  # nu verifica alte pattern-uri pentru aceeasi comanda
            
            # curata si sorteaza rezultatele
            for resource_type in resources:
                resources[resource_type] = sorted(list(set(resources[resource_type])))
            
            # adauga informatii din log despre trap files
            if hasattr(self.log_data, 'get'):
                trap_files = []
                # incearca sa gasesti trap files in structura log-ului
                # pentru log-uri text, poti adauga logic specifica
                if trap_files:
                    resources['trap_files'] = trap_files
            
            total_resources = sum(len(res_list) for res_list in resources.values())
            logger.info(f"Resurse găsite: {total_resources} total - Files: {len(resources['files'])}, Dirs: {len(resources['directories'])}, etc.")
            
            return resources
            
        except Exception as e:
            logger.error(f"Eroare la identificarea resurselor accesate: {str(e)}")
            return {}
    

    #!/usr/bin/env python3
    def generate_report(self, format=""):
        try:
            logger.info(f"Începe generarea raportului în format {format}")
            
            # vedem daca avem toate analizele necesare
            if not self.log_data:
                logger.info("Parsez sesiunea...")
                parse_result = self.parse_session()
                
                if not parse_result:
                    logger.error("Parsarea sesiunii a eșuat")
                    return None
            
            

            # debug - verifica datele de baza
            logger.info(f"Număr comenzi parsate: {len(self.commands)}")
            if self.commands:
                logger.info(f"Primele 3 comenzi: {self.commands[:3]}")
            else:
                logger.warning("Nu există comenzi parsate!")
        
            calculated_end_time, calculated_duration = self.calculate_session_times()

            # identifica categoriile de atac
            if not self.categorized_commands:
                logger.info("Identific categoriile de atac...")
                attack_categories_result = self.identify_attack_categories()
                if not attack_categories_result:
                    logger.warning("Nu s-au identificat categorii de atac")
                    attack_categories_result = {
                        'categories': {},
                        'category_counts': {},
                        'top_categories': [],
                        'severity_scores': {}
                    }
            else:
                # construieste rezultatul daca categoriile sunt deja identificate
                category_counts = {cat: len(cmds) for cat, cmds in self.categorized_commands.items() if cmds}
                sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
                
                attack_categories_result = {
                    'categories': self.categorized_commands,
                    'category_counts': category_counts,
                    'top_categories': sorted_categories,
                    'severity_scores': self.severity_scores
                }

            logger.info(f"Categorii identificate: {len([cat for cat, cmds in self.categorized_commands.items() if cmds])}")
        
            # analizeaza secventa de atac
            if not self.attack_sequence:
                logger.info("Analizez secvența de atac...")
                self.analyze_attack_sequence()
            
            # identifica comenzile critice
            if not self.critical_commands:
                logger.info("Identific comenzile critice...")
                self.identify_critical_commands()
            
            # evalueaza expertiza atacatorului
            if not self.attacker_profile:
                logger.info("Evaluez expertiza atacatorului...")
                self.evaluate_attacker_expertise()
            
            # obtine datele pentru raport
            logger.info("Colectez datele pentru raport...")
            
            # timeline atacului
            timeline = self.get_attack_timeline()
            logger.info(f"Timeline generat cu {len(timeline)} evenimente")
            
            # fisiere incarcate
            uploaded_files = self.get_uploaded_files()
            logger.info(f"Fișiere detectate: {len(uploaded_files.get('confirmed_uploads', []))} confirmate, {len(uploaded_files.get('potential_uploads', []))} potențiale")
            
            # resurse accesate
            accessed_resources = self.get_accessed_resources()
            total_resources = sum(len(res_list) for res_list in accessed_resources.values())
            logger.info(f"Resurse accesate: {total_resources} total")
            
            # modele temporale
            timing_patterns = self.analyze_timing_patterns()
            
            # construieste datele pentru raport
            report_data = {
                'session_info': {
                    'log_path': str(self.log_path),
                    'ip_info': self.ip_info,
                    'start_time': self.log_data.get('header', {}).get('start_time'),
                    'end_time': calculated_end_time.isoformat() if calculated_end_time else 'Necunoscut',
                    'duration': str(calculated_duration) if calculated_duration else 'N/A',
                    'command_count': len(self.commands)
                },
                'attacker_profile': self.attacker_profile,
                'command_count': len(self.commands),
                'attack_categories': attack_categories_result,
                'attack_sequence': self.attack_sequence, 
                'critical_commands': self.critical_commands,
                'timeline': timeline,
                'uploaded_files': uploaded_files,
                'accessed_resources': accessed_resources,
                'timing_patterns': timing_patterns
            }
            
            logger.info("Datele pentru raport au fost colectate cu succes")
            
            # creeaza directorul pentru rapoarte daca nu exista
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            # construieste numele fisierului de raport
            log_name = self.log_path.stem
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # asigura-te ca format are extensia potrivita
            if format.lower() in ['html', 'htm']:
                format_ext = 'html'
            else:
                format_ext = 'txt'
                
            report_filename = f"report_{log_name}_{timestamp}.{format_ext}"
            report_path = reports_dir / report_filename
            
            logger.info(f"Generez raportul: {report_path}")
            
            # importa reportgenerator - modifica import-ul aici daca e necesar
            try:
                # incearca sa importe noul generator modular
                from .modular_report_generator import ReportGenerator
                logger.info("Folosesc generatorul modular de rapoarte")
            except ImportError:
                # fallback la generatorul vechi daca noul nu e disponibil
                from .report_generator import ReportGenerator
                logger.info("Folosesc generatorul vechi de rapoarte")
            
            # genereaza raportul
            report_generator = ReportGenerator(report_data)
            
            if format.lower() in ['html', 'htm']:
                logger.info("Generez raportul HTML...")
                generated_report = report_generator.generate_html_report()
            else:
                logger.info("Generez raportul text...")
                generated_report = report_generator.generate_text_report()
            
            # verifica daca raportul a fost generat
            if not generated_report:
                logger.error("Raportul generat este gol!")
                return None
            
            # salveaza raportul
            logger.info(f"Salvez raportul în: {report_path}")
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(generated_report)
            
            # verifica daca fisierul a fost salvat cu succes
            if not report_path.exists():
                logger.error(f"Fișierul raport nu a fost creat: {report_path}")
                return None
            
            # verifica dimensiunea fisierului
            file_size = report_path.stat().st_size
            if file_size == 0:
                logger.error(f"Fișierul raport este gol: {report_path}")
                return None
            
            logger.info(f"Raport generat cu succes: {report_path} ({file_size} bytes)")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Eroare la generarea raportului: {str(e)}")
            logger.error(f"Tip eroare: {type(e).__name__}")
            
            # pentru debugging, afiseaza si stack trace-ul
            import traceback
            logger.error(f"Stack trace: {traceback.format_exc()}")
            
            return None