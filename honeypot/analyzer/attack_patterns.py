#!/usr/bin/env python3

import os
import logging
import importlib
import inspect
import re
import pkgutil
from pathlib import Path

# setam putin logging-ul sa vedem ce se intampla
logger = logging.getLogger('honeypot.analyzer')

class CommandMatcher:
    def __init__(self):
        # aici o sa tinem toate categoriile de atacuri
        self.categories = {}
        
        # incarcam toate categoriile disponibile
        self.load_category_modules()
        
        logger.info(f"CommandMatcher inițializat cu {len(self.categories)} categorii de atac")
    
    def load_category_modules(self):
        try:
            # incercam sa incarcam modulul cu toate categoriile
            try:
                from analyzer.categories import get_all_categories
                
                # luam clasele pentru toate categoriile
                category_classes = get_all_categories()
                
                # facem cate o instanta pentru fiecare categorie
                for category_class in category_classes:
                    try:
                        category = category_class()
                        self.categories[category.get_name()] = category
                        logger.debug(f"Categorie încărcată: {category.get_name()}")
                    except Exception as e:
                        logger.error(f"Eroare la inițializarea categoriei {category_class.__name__}: {str(e)}")
                
                logger.info(f"Au fost încărcate {len(self.categories)} categorii de atac")
                
            except ImportError:
                logger.warning("Nu s-a putut importa modulul categories, se încearcă încărcarea directă a categoriilor")
                
                # daca nu merge, incercam manual sa le incarcam
                self._load_categories_fallback()
        
        except Exception as e:
            logger.error(f"Eroare la încărcarea modulelor de categorii: {str(e)}")
    
    def _load_categories_fallback(self):
        try:
            # vedem daca avem folderul cu categorii
            categories_path = Path(__file__).parent / "categories"
            
            if not categories_path.exists() or not categories_path.is_dir():
                logger.error(f"Directorul de categorii nu există: {categories_path}")
                return
            
            # astea sunt categoriile principale pe care le stim
            categories = [
                'system_recon',
                'privilege_escalation',
                'data_exfiltration',
                'persistence',
                'honeypot_detection',
                'network_scanning',
                'brute_force',
                'file_access',
                'malware_upload',
                'lateral_movement'
            ]
            
            # incarcam pe rand fiecare categorie
            for category_name in categories:
                try:
                    # construim numele modulului din numele categoriei
                    module_name = f"analyzer.categories.{category_name}"
                    
                    # incarcam modulul
                    module = importlib.import_module(module_name)
                    
                    # numele clasei e numele categoriei cu litere mari si Category la sfarsit
                    class_name = "".join(word.title() for word in category_name.split('_')) + "Category"
                    
                    # daca clasa exista in modul
                    if hasattr(module, class_name):
                        # luam clasa si facem o instanta din ea
                        category_class = getattr(module, class_name)
                        category = category_class()
                        
                        # o bagam in dictionarul nostru
                        self.categories[category.get_name()] = category
                        logger.debug(f"Categorie încărcată manual: {category.get_name()}")
                    
                except ImportError:
                    logger.warning(f"Nu s-a putut importa modulul pentru categoria {category_name}")
                except Exception as e:
                    logger.error(f"Eroare la încărcarea categoriei {category_name}: {str(e)}")
            
            logger.info(f"Au fost încărcate manual {len(self.categories)} categorii de atac")
            
        except Exception as e:
            logger.error(f"Eroare la încărcarea manuală a categoriilor: {str(e)}")
    
    def match_command(self, command):
        try:
            # daca nu avem categorii, nu avem cu ce sa facem match
            if not self.categories:
                logger.warning("Nu există categorii încărcate pentru potrivire")
                return {}
            
            # vedem care categorii se potrivesc cu comanda
            matches = {}
            
            for category_name, category in self.categories.items():
                try:
                    # vedem daca comanda asta se potriveste cu categoria
                    if category.match(command):
                        # calculam cat de serioasa e treaba
                        severity = category.get_severity(command) if hasattr(category, 'get_severity') else 5
                        
                        # si cat de siguri suntem ca e match-ul corect
                        confidence = self._calculate_confidence(command, category)
                        
                        # punem rezultatul in lista
                        matches[category_name] = {
                            'matched': True,
                            'confidence': confidence,
                            'severity': severity
                        }
                except Exception as e:
                    logger.error(f"Eroare la potrivirea comenzii '{command}' cu categoria {category_name}: {str(e)}")
            
            return matches
            
        except Exception as e:
            logger.error(f"Eroare la potrivirea comenzii: {str(e)}")
            return {}
    
    def get_match_details(self, command, category_name):
        try:
            # mai intai vedem daca categoria exista
            if category_name not in self.categories:
                logger.warning(f"Categoria {category_name} nu există")
                return {'error': f"Categoria {category_name} nu există"}
            
            # luam categoria
            category = self.categories[category_name]
            
            # vedem daca comanda se potriveste cu categoria asta
            if not category.match(command):
                return {'matched': False, 'message': f"Comanda nu se potrivește cu categoria {category_name}"}
            
            # informatii de baza despre match
            details = {
                'matched': True,
                'category': category_name,
                'description': getattr(category, 'description', 'Fără descriere')
            }
            
            # daca categoria stie sa calculeze severitatea, o adaugam
            if hasattr(category, 'get_severity'):
                details['severity'] = category.get_severity(command)
            
            # fiecare categorie poate avea metode speciale de analiza
            special_methods = {
                'system_recon': [
                    ('analyze_reconnaissance_depth', 'reconnaissance_depth'),
                    ('get_system_info_commands', 'system_info_commands'),
                    ('get_user_info_commands', 'user_info_commands'),
                    ('get_network_info_commands', 'network_info_commands'),
                    ('get_file_system_commands', 'file_system_commands')
                ],
                'privilege_escalation': [
                    ('analyze_escalation_attempt', 'escalation_details'),
                    ('get_sudo_attempts', 'sudo_attempts'),
                    ('get_suid_attempts', 'suid_attempts'),
                    ('get_kernel_exploit_attempts', 'kernel_exploits'),
                    ('get_service_exploit_attempts', 'service_exploits')
                ],
                'data_exfiltration': [
                    ('analyze_exfiltration_method', 'exfiltration_method'),
                    ('get_file_transfer_commands', 'file_transfers'),
                    ('get_data_encoding_commands', 'data_encoding'),
                    ('get_compression_commands', 'compression'),
                    ('get_network_exfiltration_commands', 'network_exfiltration')
                ],
                'persistence': [
                    ('analyze_persistence_mechanism', 'persistence_mechanism'),
                    ('get_cron_job_attempts', 'cron_jobs'),
                    ('get_service_creation_attempts', 'service_creation'),
                    ('get_startup_modification_attempts', 'startup_mods'),
                    ('get_backdoor_installation_attempts', 'backdoors')
                ],
                'honeypot_detection': [
                    ('analyze_detection_technique', 'detection_technique'),
                    ('get_container_detection_attempts', 'container_detection'),
                    ('get_system_anomaly_checks', 'system_anomalies'),
                    ('get_artifact_detection_attempts', 'artifact_detection')
                ],
                'network_scanning': [
                    ('analyze_scanning_technique', 'scanning_technique'),
                    ('get_port_scan_attempts', 'port_scans'),
                    ('get_host_discovery_attempts', 'host_discovery'),
                    ('get_service_enumeration_attempts', 'service_enumeration')
                ],
                'brute_force': [
                    ('analyze_brute_force_technique', 'brute_force_technique'),
                    ('get_password_cracking_attempts', 'password_cracking'),
                    ('get_dictionary_attack_attempts', 'dictionary_attacks'),
                    ('get_credential_stuffing_attempts', 'credential_stuffing')
                ],
                'file_access': [
                    ('analyze_file_access', 'file_access_details'),
                    ('get_sensitive_file_access', 'sensitive_files'),
                    ('get_configuration_file_access', 'config_files'),
                    ('get_user_data_access', 'user_data_files')
                ],
                'malware_upload': [
                    ('analyze_upload_method', 'upload_method'),
                    ('get_download_commands', 'downloads'),
                    ('get_file_transfer_commands', 'file_transfers'),
                    ('get_script_execution_commands', 'script_execution')
                ],
                'lateral_movement': [
                    ('analyze_lateral_movement_technique', 'lateral_movement_technique'),
                    ('get_ssh_connection_attempts', 'ssh_connections'),
                    ('get_credential_harvesting_attempts', 'credential_harvesting'),
                    ('get_internal_network_scan_attempts', 'internal_scans')
                ]
            }
            
            # daca categoria noastra are metode speciale, le apelam
            if category_name in special_methods:
                for method_name, result_key in special_methods[category_name]:
                    if hasattr(category, method_name):
                        try:
                            # vedem cati parametri vrea metoda
                            method = getattr(category, method_name)
                            
                            # aflam parametrii metodei
                            sig = inspect.signature(method)
                            params = list(sig.parameters.keys())
                            
                            # o apelam cu sau fara comanda, depinde ce vrea
                            if len(params) > 1:  # metoda care vrea comanda ca parametru
                                result = method(command)
                            else:  # metoda care merge fara parametri
                                result = method()
                            
                            details[result_key] = result
                        except Exception as e:
                            logger.error(f"Eroare la apelarea metodei {method_name}: {str(e)}")
            
            return details
            
        except Exception as e:
            logger.error(f"Eroare la obținerea detaliilor pentru categorie: {str(e)}")
            return {'error': str(e)}
    
    def _calculate_confidence(self, command, category):
        try:
            # cat de siguri suntem ca match-ul e corect
            # categoriile pot sa isi faca propriul calcul daca vor
            
            # daca categoria are propria metoda de calcul, o folosim
            if hasattr(category, 'calculate_confidence'):
                return category.calculate_confidence(command)
            
            # altfel folosim ceva simplu
            confidence = 0.6  # incepem cu 60%
            
            # vedem daca categoria are pattern-uri definite
            if hasattr(category, 'PATTERNS'):
                patterns = getattr(category, 'PATTERNS')
                
                # daca patterns e dictionar, luam toate pattern-urile
                if isinstance(patterns, dict):
                    all_patterns = []
                    for pattern_group in patterns.values():
                        if isinstance(pattern_group, list):
                            all_patterns.extend(pattern_group)
                        else:
                            all_patterns.append(pattern_group)
                else:
                    all_patterns = patterns if isinstance(patterns, list) else [patterns]
                
                # vedem cate pattern-uri se potrivesc cu comanda
                matched_patterns = 0
                for pattern in all_patterns:
                    if isinstance(pattern, str) and re.search(pattern, command, re.IGNORECASE):
                        matched_patterns += 1
                
                # cu cat mai multe pattern-uri se potrivesc, cu atat suntem mai siguri
                if matched_patterns > 0:
                    confidence = min(0.9, 0.6 + matched_patterns * 0.1)
            
            return confidence
            
        except Exception as e:
            logger.error(f"Eroare la calcularea scorului de încredere: {str(e)}")
            return 0.5  # daca se strica ceva, returnam 50%