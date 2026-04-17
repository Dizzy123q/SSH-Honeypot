#!/usr/bin/env python3
import os
import json
import logging
from pathlib import Path
from flask import Flask, render_template, redirect, url_for, request, jsonify
import re
from collections import Counter

# configurare logging
logger = logging.getLogger('honeypot.gui')

class HoneypotGUI:
    
    def __init__(self, analyzer, host='127.0.0.1', port=5000, debug=False):
        self.analyzer = analyzer
        self.host = host
        self.port = port
        self.debug = debug
        
        # intializeaza aplicatia Flask
        self.app = Flask(__name__, 
                        template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
                        static_folder=os.path.join(os.path.dirname(__file__), 'static'))
        
        # configureaza rutele
        self._setup_routes()
        
        logger.info(f"HoneypotGUI inițializat pe {host}:{port}")
    
    def _get_geographic_data_from_logs(self):
        # extrage datele geografice direct din log-uri
        countries = Counter()
        unique_ips = set()
        
        logs_folder = Path('logs')
        
        if not logs_folder.exists():
            return {'countries': {}, 'unique_ips': 0}
        
        # proceseaza fiecare fisier log
        for log_file in logs_folder.glob('*.log'):
            try:
                # citeste continutul
                with open(log_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # extrage tara din log
                country_match = re.search(r'country:\s*(.+)', content, re.IGNORECASE)
                if country_match:
                    country = country_match.group(1).strip()
                    countries[country] += 1
                
                # extrage ip-ul din numele fisierului
                if '_' in log_file.name:
                    ip = log_file.name.split('_')[0]
                    unique_ips.add(ip)
                    
            except Exception as e:
                logger.warning(f"Eroare la procesarea {log_file.name}: {e}")
        
        return {
            'countries': dict(countries),
            'unique_ips': len(unique_ips)
        }


    def _setup_routes(self):
    
        @self.app.route('/')
        def index():
            try:
                # obtine statisticile de baza
                stats = self.analyzer.get_statistics()
                
                # adauga datele geografice din log-uri
                geo_data = self._get_geographic_data_from_logs()
                stats['geographic_distribution'] = geo_data
                
                # adauga log-urile interesante
                try:
                    interesting_logs = self.analyzer.get_detailed_interesting_logs(3)
                    stats['interesting_logs'] = interesting_logs
                    logger.info(f"Log-uri interesante găsite: {len(interesting_logs)}")
                except Exception as e:
                    logger.warning(f"Eroare la obținerea log-urilor interesante: {str(e)}")
                    stats['interesting_logs'] = []
                
                return render_template('index.html', stats=stats)
            except Exception as e:
                logger.error(f"Eroare la afișarea paginii principale: {str(e)}")
                return render_template('error.html', error=str(e))
        
        @self.app.route('/analyze_session/<filename>')
        def analyze_session(filename):
            try:
                logger.info(f"Redirecționare către analiza sesiunii: {filename}")
                # redirectioneaza catre generarea raportului HTML
                return redirect(url_for('generate_report', format='html', log_filename=filename))
            except Exception as e:
                logger.error(f"Eroare la analizarea sesiunii {filename}: {str(e)}")
                return render_template('error.html', error=str(e))
        
        @self.app.route('/logs')
        def logs():
            try:
                # calea catre folderul logs
                logs_folder = Path('logs')  # folosesc cale relativa
                
                # lista pentru stocarea datelor sesiunilor
                sessions = []
                
                # verifica daca folderul logs exista
                if logs_folder.exists() and logs_folder.is_dir():
                    files_list = list(logs_folder.glob('*'))
                    # logger.info(f"Număr total de fișiere în folder: {len(files_list)}")
                    # logger.info(f"Fișiere găsite: {[f.name for f in files_list]}")
                    
                    # filtram doar fișierele .log
                    log_files = list(logs_folder.glob('*.log'))
                    logger.info(f"Număr de fișiere .log: {len(log_files)}")
                    
                    # itereaza prin toate fisierele log
                    for log_file in log_files:
                        #logger.info(f"Procesare fișier: {log_file.name}")
                        
                        # obtine numele fisierului
                        filename = log_file.name
                        
                        # extrage ip-ul si timestamp-ul din numele fisierului
                        if '_' in filename:
                            parts = filename.split('_')
                            ip = parts[0]
                            timestamp_str = parts[1].split('.')[0]
                            
                            # formateaza timestamp-ul pentru afisare
                            formatted_timestamp = ""
                            if len(timestamp_str) == 14:
                                formatted_timestamp = f"{timestamp_str[0:4]}-{timestamp_str[4:6]}-{timestamp_str[6:8]} {timestamp_str[8:10]}:{timestamp_str[10:12]}:{timestamp_str[12:14]}"
                            
                            # Citeste continutul fisierului
                            try:
                                with open(log_file, 'r') as f:
                                    content = f.read()
                            except Exception as e:
                                logger.error(f"Eroare la citirea fișierului {filename}: {str(e)}")
                                content = f"Eroare la citirea fișierului: {str(e)}"
                            
                            # adauga informatiile in lista de sesiuni
                            sessions.append({
                                'id': filename,  # foloses numele fisierului ca id
                                'ip': ip,
                                'timestamp': timestamp_str,
                                'formatted_timestamp': formatted_timestamp,
                                'filename': filename,
                                'commands': content
                            })
                        else:
                            logger.warning(f"Fișierul {filename} nu respectă formatul așteptat (IP_TIMESTAMP.log)")
                else:
                    logger.warning(f"Folderul logs nu există sau nu este un director: {logs_folder}")
                
                #logger.info(f"Număr total de sesiuni găsite: {len(sessions)}")
                
                # sorteaza descrescator sesiunile dupa timestamp
                if sessions:
                    sessions.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                
                return render_template('session_logs.html', logs=sessions)
            except Exception as e:
                logger.error(f"Eroare la afișarea paginii de loguri: {str(e)}")
                return render_template('error.html', error=str(e))

        @self.app.route('/update_global', methods=['POST'])
        def update_global():
            try:
                logger.info("Actualizare statistici globale...")
                
                # rescanneaza toate log-urile
                success = self.analyzer.scan_all_logs()
                
                if success:
                    logger.info(f"Statistici actualizate: {self.analyzer.total_sessions} sesiuni")
                    return redirect(url_for('index'))
                else:
                    logger.error("Eroare la rescannarea log-urilor")
                    return render_template('error.html', error="Eroare la actualizarea statisticilor")
                    
            except Exception as e:
                logger.error(f"Eroare la actualizarea globală: {str(e)}")
                return render_template('error.html', error=str(e))
            
        @self.app.route('/update_sessions', methods=['POST'])
        def update_sessions():
            try:
                logger.info("Verificare log-uri noi...")
                
                # verifica daca exista log-uri noi
                logs_folder = Path('logs')
                current_logs = set()
                
                if logs_folder.exists():
                    current_logs = {f.name for f in logs_folder.glob('*.log') 
                                if '_' in f.name and f.name[0].isdigit()}
                
                # obtine lista log-urilor deja scanate
                scanned_logs = set()
                if self.analyzer.sessions_data:
                    scanned_logs = {session.get('file_name', '') for session in self.analyzer.sessions_data}
                
                # gaseste log-urile noi
                new_logs = current_logs - scanned_logs
                
                if new_logs:
                    logger.info(f"Găsite {len(new_logs)} log-uri noi, se rescannează...")
                    self.analyzer.scan_all_logs()
                else:
                    logger.info("Nu există log-uri noi")
                
                return redirect(url_for('logs'))
                
            except Exception as e:
                logger.error(f"Eroare la actualizarea sesiunilor: {str(e)}")
                return render_template('error.html', error=str(e))

        @self.app.route('/api/stats')
        def api_stats():
            try:
                stats = self.analyzer.get_statistics()
                return jsonify(stats)
            except Exception as e:
                logger.error(f"Eroare la furnizarea statisticilor API: {str(e)}")
                return jsonify({"error": str(e)})
        
        @self.app.route('/api/sessions')
        def api_sessions():
            try:
                # calea catre folderul logs
                logs_folder = Path('logs')  # folosesc aceeasi cale relativa
                
                # lista pentru stocarea datelor sesiunilor
                sessions = []
                
                # verifica daca folderul logs exista
                if logs_folder.exists() and logs_folder.is_dir():
                    # itereaza prin toate fisierele din folderul logs
                    for log_file in logs_folder.glob('*.log'):
                        # obtine numele fisierului
                        filename = log_file.name
                        
                        # extrage ip-ul si timestamp-ul din numele fisierului
                        if '_' in filename:
                            parts = filename.split('_')
                            ip = parts[0]
                            timestamp_str = parts[1].split('.')[0]
                            
                            # formateaza timestamp-ul pentru afisare
                            formatted_timestamp = ""
                            if len(timestamp_str) == 14:
                                formatted_timestamp = f"{timestamp_str[0:4]}-{timestamp_str[4:6]}-{timestamp_str[6:8]} {timestamp_str[8:10]}:{timestamp_str[10:12]}:{timestamp_str[12:14]}"
                            
                            # Citeste continutul fisierului
                            try:
                                with open(log_file, 'r') as f:
                                    content = f.read()
                            except Exception as e:
                                content = f"Eroare la citirea fișierului: {str(e)}"
                            
                            # adauga informatiile in lista de sesiuni
                            sessions.append({
                                'id': filename,  # folosim numele fisierului ca id
                                'ip': ip,
                                'timestamp': timestamp_str,
                                'formatted_timestamp': formatted_timestamp,
                                'filename': filename,
                                'commands': content
                            })
                
                # sorteaza descrescător sesiunile dupa timestamp
                sessions.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                
                return jsonify(sessions)
            except Exception as e:
                logger.error(f"Eroare la furnizarea datelor sesiunilor API: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/export_logs', methods=['GET'])
        def export_logs():
            try:
                sessions = self.analyzer.sessions_data
                response = jsonify(sessions)
                response.headers["Content-Disposition"] = "attachment; filename=ssh_honeypot_logs.json"
                return response
            except Exception as e:
                logger.error(f"Eroare la exportarea logurilor: {str(e)}")
                return jsonify({"error": str(e)}), 500

        @self.app.route('/generate_report/<format>/<path:log_filename>', methods=['GET'])
        def generate_report(format, log_filename):
            try:
                logger.info(f"Generare raport format {format} pentru fișierul: {log_filename}")
                
                # calea catre folderul logs
                logs_folder = Path('logs')
                
                # construim calea completa catre fisierul log
                log_path = logs_folder / log_filename
                
                # verifica daca fisierul exista
                if not log_path.exists():
                    logger.error(f"Fișierul log {log_filename} nu există")
                    return jsonify({"error": f"Fișierul log {log_filename} nu există"}), 404
                
                # importa analizatorul de sesiune
                from honeypot.analyzer.session_analyzer import SessionAnalyzer
                
                # creeaza instanta analyzer
                session_analyzer = SessionAnalyzer(str(log_path))
                
                # parseaza sesiunea
                session_data = session_analyzer.parse_session()
                if not session_data:
                    return jsonify({"error": "Nu s-a putut parsa fișierul log"}), 500
                
                # ruleaza analizele
                session_analyzer.identify_attack_categories()
                session_analyzer.analyze_attack_sequence()
                session_analyzer.identify_critical_commands()
                session_analyzer.evaluate_attacker_expertise()
                
                # genereaza raportul si obtine calea fisierului
                if format.lower() == 'html':
                    report_file_path = session_analyzer.generate_report("html")
                elif format.lower() == 'text':
                    report_file_path = session_analyzer.generate_report()
                else:
                    return jsonify({"error": f"Format necunoscut: {format}"}), 400
                
                # citeste continutul fisierului generat
                try:
                    with open(report_file_path, 'r', encoding='utf-8') as f:
                        report_content = f.read()
                except Exception as e:
                    logger.error(f"Eroare la citirea raportului: {str(e)}")
                    return jsonify({"error": f"Eroare la citirea raportului: {str(e)}"}), 500
                
                # extrage ip-ul pentru nume fisier
                ip = log_filename.split('_')[0] if '_' in log_filename else "unknown"
                
                # returnează response-ul
                from flask import Response
                
                if format.lower() == 'html':
                    # HTML se afiseaza in browser
                    response = Response(
                        report_content,
                        mimetype='text/html'
                    )
                else:
                    # text se descarca
                    response = Response(
                        report_content,
                        mimetype='text/plain',
                        headers={"Content-Disposition": f"attachment;filename={ip}_report.txt"}
                    )
                
                return response
                
            except Exception as error:
                logger.error(f"Eroare la generarea raportului: {str(error)}")
                return jsonify({"error": str(error)}), 500

            
    def run(self):
        try:
            logger.info(f"Pornire server web pe {self.host}:{self.port}")
            self.app.run(host=self.host, port=self.port, debug=self.debug)
        except Exception as e:
            logger.error(f"Eroare la pornirea serverului web: {str(e)}")
            raise

def start_gui(analyzer, host='127.0.0.1', port=5000, debug=False):
    # verifica daca analizatorul a scanat log-urile
    if not analyzer.sessions_data:
        logger.info("Scanez log-urile pentru prima dată...")
        analyzer.scan_all_logs()
    
    # Creeaza si porneste interfata
    gui = HoneypotGUI(analyzer, host, port, debug)
    gui.run()
    
    return gui