#!/usr/bin/env python3

import re
from .. import AttackCategory
from ..common import normalize_command

class NetworkScanningCategory(AttackCategory):
 
    def __init__(self):
        super().__init__("network_scanning", "Comenzi folosite pentru scanarea și explorarea rețelei")
        
        # tinem aici comenzile analizate ca sa le refolosim
        self.analyzed_commands = []
    
    # aici avem toate pattern-urile pentru diferite tipuri de scanare de retea
    PATTERNS = {
        'port_scanning': [
            r'nmap(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'nc\s+(-[a-zA-Z]+\s+)?(\S+)\s+(\d+)',
            r'netcat\s+(-[a-zA-Z]+\s+)?(\S+)\s+(\d+)',
            r'ncat\s+(-[a-zA-Z]+\s+)?(\S+)\s+(\d+)',
            r'telnet\s+(\S+)\s+(\d+)',
            r'ssh\s+(-[a-zA-Z]+\s+)?(\S+)\s+(\d+)',
            r'hping3\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'masscan\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'unicornscan\s+(-[a-zA-Z0-9]+\s+)?(\S+)',
            r'curl\s+(-[a-zA-Z]+\s+)?(\S+):(\d+)',
            r'wget\s+(-[a-zA-Z]+\s+)?(\S+):(\d+)',
            r'socat\s+(\S+)\s+(\S+)',
            r'for\s+.*\s*do.*\s*nc\s+.*\s*\d+',
            r'for\s+.*\s*do.*\s*ping\s+',
            r'nc\s+-z\s+(\S+)\s+(\d+)(?:-(\d+))?',
            r'for\s+p\s+in\s+.*\s*;\s*do.*\s*\d+',
            r'awk\s+.*\s+netstat\s+',
            r'awk\s+.*\s+nmap\s+'
        ],
        'host_discovery': [
            r'ping(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'fping(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'arping(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'nmap\s+-sn\s+(\S+)',
            r'nmap\s+-sP\s+(\S+)',
            r'nmap\s+(-[a-zA-Z0-9]+\s+)?-n\s+-sn\s+(\S+)',
            r'nmap\s+.*--disable-arp-ping',
            r'ping\s+-b\s+(\S+)',
            r'for\s+.*\s*do\s*ping\s+-c\s+1',
            r'arp\s+-a',
            r'arp-scan(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'nping(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'traceroute(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'tracepath(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'mtr(\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'for\s+host\s+in\s+.*\s*;\s*do.*\s*ping',
            r'\d+\.\d+\.\d+\.\d+\/\d+'
        ],
        'service_enumeration': [
            r'nmap\s+-s[SV](\s+-[a-zA-Z0-9]+)?\s+(\S+)',
            r'nmap\s+.*-p\s+(\S+)',
            r'nmap\s+.*--open',
            r'nmap\s+.*-A\s+(\S+)',
            r'nmap\s+.*-O\s+(\S+)',
            r'nmap\s+.*-sC\s+(\S+)',
            r'nmap\s+.*-sV\s+(\S+)',
            r'nmap\s+.*-oA\s+(\S+)',
            r'nmap\s+.*-oG\s+(\S+)',
            r'nmap\s+.*-oN\s+(\S+)',
            r'smbclient\s+(-[a-zA-Z]+\s+)?.*',
            r'enum4linux\s+(-[a-zA-Z]+\s+)?(\S+)',
            r'showmount\s+(-[a-zA-Z]+\s+)?(\S+)',
            r'rpcinfo\s+(-[a-zA-Z]+\s+)?(\S+)',
            r'snmpwalk\s+(-[a-zA-Z]+\s+)?(\S+)',
            r'snmpget\s+(-[a-zA-Z]+\s+)?(\S+)',
            r'onesixtyone\s+(-[a-zA-Z]+\s+)?(\S+)',
            r'amap\s+(-[a-zA-Z]+\s+)?(\S+)'
        ],
        'network_investigation': [
            r'ip\s+a(ddr|ddress)?(\s+show)?',
            r'ip\s+r(oute)?(\s+show)?',
            r'ip\s+n(eigh)?(\s+show)?',
            r'ip\s+l(ink)?(\s+show)?',
            r'ifconfig(\s+-[a-zA-Z]+)?',
            r'iwconfig(\s+-[a-zA-Z]+)?',
            r'netstat\s+(-[a-zA-Z]+)?',
            r'ss\s+(-[a-zA-Z]+)?',
            r'lsof\s+(-[a-zA-Z]+)?\s+-i',
            r'tcpdump(\s+-[a-zA-Z]+)?',
            r'route(\s+-[a-zA-Z]+)?',
            r'iptables\s+-L',
            r'cat\s+/proc/net/\w+',
            r'cat\s+/etc/hosts',
            r'dig(\s+-[a-zA-Z]+)?\s+(\S+)',
            r'host\s+(\S+)',
            r'nslookup\s+(\S+)',
            r'whois\s+(\S+)'
        ]
    }
    
    def match(self, command):
        # vedem daca comanda se potriveste cu vreo tehnica de scanare retea
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    # adaugam comanda la lista analizata daca nu exista deja
                    if command not in self.analyzed_commands:
                        self.analyzed_commands.append(command)
                    return True
        
        return False
    
    def analyze_scanning_technique(self, command):
        # incepem cu valorile de baza
        result = {
            'method': 'Unknown',
            'target': 'Unknown',
            'ports': 'Unknown',
            'scan_type': 'Unknown',
            'severity': self.get_severity(command),
            'description': ''
        }
        
        # cautam sa vedem ce metoda de scanare e
        for sub_category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    result['method'] = sub_category
                    break
            if result['method'] != 'Unknown':
                break
        
        # analizam specificul metodei de scanare
        if result['method'] == 'port_scanning':
            # detectam scanari nmap
            nmap_match = re.search(r'nmap\s+(-[a-zA-Z0-9]+\s+)?(\S+)', command, re.IGNORECASE)
            if nmap_match:
                result['scan_type'] = 'Nmap scan'
                result['target'] = nmap_match.group(2)
                
                # vedem parametrii specifici
                if '-p' in command:
                    port_match = re.search(r'-p\s+([0-9,-]+)', command)
                    if port_match:
                        result['ports'] = port_match.group(1)
                
                # vedem tipul scanarii
                if '-sT' in command:
                    result['scan_type'] = 'TCP connect scan'
                elif '-sS' in command:
                    result['scan_type'] = 'SYN scan'
                elif '-sU' in command:
                    result['scan_type'] = 'UDP scan'
                elif '-sA' in command:
                    result['scan_type'] = 'ACK scan'
                elif '-sF' in command or '-sX' in command or '-sN' in command:
                    result['scan_type'] = 'Stealth scan'
                
                result['description'] = f"Scanare porturi cu Nmap către {result['target']}"
                if result['ports'] != 'Unknown':
                    result['description'] += f" port(uri) {result['ports']}"
            
            # detectam scanari cu netcat
            nc_match = re.search(r'n(?:c|etcat)\s+(?:-[a-zA-Z]+\s+)?(\S+)\s+(\d+)', command, re.IGNORECASE)
            if nc_match:
                result['scan_type'] = 'Netcat scan'
                result['target'] = nc_match.group(1)
                result['ports'] = nc_match.group(2)
                result['description'] = f"Verificare conexiune port cu Netcat către {result['target']}:{result['ports']}"
            
            # detectam scanning nested (for loops)
            for_loop_match = re.search(r'for\s+(\w+)\s+in\s+(.*?)\s*;\s*do\s*(.*?)\s*(?:done|$)', command, re.IGNORECASE)
            if for_loop_match:
                loop_var = for_loop_match.group(1)
                loop_range = for_loop_match.group(2)
                loop_command = for_loop_match.group(3)
                
                # vedem daca e pentru porturi
                if ('p' in loop_var.lower() or 'port' in loop_var.lower()) and 'nc' in loop_command:
                    result['scan_type'] = 'Port range scan'
                    
                    # incercam sa scoatem tinta
                    target_match = re.search(r'nc\s+(?:-[a-zA-Z]+\s+)?(\S+)', loop_command)
                    if target_match:
                        result['target'] = target_match.group(1)
                    
                    # incercam sa scoatem range-ul de porturi
                    if '{' in loop_range and '}' in loop_range:
                        port_range_match = re.search(r'\{(\d+)\.\.(\d+)\}', loop_range)
                        if port_range_match:
                            result['ports'] = f"{port_range_match.group(1)}-{port_range_match.group(2)}"
                    
                    result['description'] = f"Scanare range porturi (for loop) către {result['target']}"
                    if result['ports'] != 'Unknown':
                        result['description'] += f" pe range {result['ports']}"
        
        elif result['method'] == 'host_discovery':
            # detectam ping sweep
            ping_match = re.search(r'ping\s+(?:-[a-zA-Z0-9]+\s+)?(\S+)', command, re.IGNORECASE)
            if ping_match:
                result['scan_type'] = 'Ping sweep'
                result['target'] = ping_match.group(1)
                result['description'] = f"Verificare disponibilitate host cu ping către {result['target']}"
            
            # detectam scanari arp
            arp_match = re.search(r'arp(?:-scan)?\s+(?:-[a-zA-Z0-9]+\s+)?(\S+)', command, re.IGNORECASE)
            if arp_match:
                result['scan_type'] = 'ARP scan'
                result['target'] = arp_match.group(1)
                result['description'] = f"Scanare ARP pentru descoperire hosts în {result['target']}"
            
            # detectam scanari nmap host discovery
            nmap_host_match = re.search(r'nmap\s+(?:-[a-zA-Z0-9]+\s+)?(?:-sn|-sP)\s+(\S+)', command, re.IGNORECASE)
            if nmap_host_match:
                result['scan_type'] = 'Nmap host discovery'
                result['target'] = nmap_host_match.group(1)
                result['description'] = f"Scanare descoperire host-uri Nmap pe {result['target']}"
            
            # detectam trace route
            trace_match = re.search(r'trace(?:route|path)\s+(?:-[a-zA-Z0-9]+\s+)?(\S+)', command, re.IGNORECASE)
            if trace_match:
                result['scan_type'] = 'Traceroute'
                result['target'] = trace_match.group(1)
                result['description'] = f"Trasare rută către {result['target']}"
        
        elif result['method'] == 'service_enumeration':
            # detectam scanari de servicii nmap
            nmap_svc_match = re.search(r'nmap\s+(?:-[a-zA-Z0-9]+\s+)?(?:-sV|-A|-sC)\s+(\S+)', command, re.IGNORECASE)
            if nmap_svc_match:
                result['scan_type'] = 'Service version detection'
                result['target'] = nmap_svc_match.group(1)
                result['description'] = f"Scanare versiuni servicii pe {result['target']}"
            
            # detectam scanari os detection
            nmap_os_match = re.search(r'nmap\s+(?:-[a-zA-Z0-9]+\s+)?-O\s+(\S+)', command, re.IGNORECASE)
            if nmap_os_match:
                result['scan_type'] = 'OS fingerprinting'
                result['target'] = nmap_os_match.group(1)
                result['description'] = f"Scanare detecție sistem operare pe {result['target']}"
            
            # detectam enumerare smb
            smb_match = re.search(r'(smbclient|enum4linux)\s+(?:-[a-zA-Z]+\s+)?(\S+)', command, re.IGNORECASE)
            if smb_match:
                result['scan_type'] = 'SMB enumeration'
                result['target'] = smb_match.group(2)
                result['description'] = f"Enumerare servicii SMB pe {result['target']}"
            
            # detectam enumerare snmp
            snmp_match = re.search(r'snmp(?:walk|get)\s+(?:-[a-zA-Z]+\s+)?(\S+)', command, re.IGNORECASE)
            if snmp_match:
                result['scan_type'] = 'SNMP enumeration'
                result['target'] = snmp_match.group(1)
                result['description'] = f"Enumerare SNMP pe {result['target']}"
        
        elif result['method'] == 'network_investigation':
            # detectam comenzi de investigare retea
            if 'netstat' in command:
                result['scan_type'] = 'Connection listing'
                result['description'] = "Listare conexiuni de rețea active"
            elif 'ifconfig' in command or 'ip addr' in command:
                result['scan_type'] = 'Interface inspection'
                result['description'] = "Afișare configurație interfețe rețea"
            elif 'route' in command or 'ip route' in command:
                result['scan_type'] = 'Routing inspection'
                result['description'] = "Afișare tabele de rutare"
            elif 'tcpdump' in command:
                result['scan_type'] = 'Packet capture'
                result['description'] = "Captură pachete rețea"
            elif 'dig' in command or 'host' in command or 'nslookup' in command:
                dns_match = re.search(r'(?:dig|host|nslookup)\s+(?:-[a-zA-Z]+\s+)?(\S+)', command, re.IGNORECASE)
                if dns_match:
                    result['scan_type'] = 'DNS query'
                    result['target'] = dns_match.group(1)
                    result['description'] = f"Interogare DNS pentru {result['target']}"
        
        # daca nu am reusit sa determinam detalii specifice, oferim o descriere generala
        if result['description'] == '':
            result['description'] = f"Posibilă scanare de rețea folosind metoda {result['method']}"
        
        # calculam un scor de incredere bazat pe cat de precisa este potrivirea
        confidence = 0.7  # scor implicit
        
        # daca avem o tinta specifica, un tip de scan si o metoda clara, avem mai multa incredere
        if result['target'] != 'Unknown' and result['scan_type'] != 'Unknown' and result['method'] != 'Unknown':
            confidence = 0.9
        elif result['target'] != 'Unknown' and result['method'] != 'Unknown':
            confidence = 0.8
        
        result['confidence'] = confidence
        
        return result
    
    def get_port_scan_attempts(self):
        return self._filter_commands_by_subcategory('port_scanning')
    
    def get_host_discovery_attempts(self):
        return self._filter_commands_by_subcategory('host_discovery')
    
    def get_service_enumeration_attempts(self):
        return self._filter_commands_by_subcategory('service_enumeration')
    
    def _filter_commands_by_subcategory(self, subcategory):
        filtered_commands = []
        
        # verificam daca subcategoria exista
        if subcategory not in self.PATTERNS:
            return filtered_commands
        
        # luam pattern-urile pentru subcategorie
        patterns = self.PATTERNS[subcategory]
        
        # filtram comenzile
        for command in self.analyzed_commands:
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    filtered_commands.append(command)
                    break
        
        return filtered_commands
    
    def get_severity(self, command):
        # comenzile de scanare retea au severitate variabila in functie de agresivitate si acoperire
        
        # severitate implicita
        severity = 5
        
        # pattern-uri de scanare foarte agresive (8-10)
        aggressive_patterns = [
            r'nmap\s+-[a-zA-Z0-9]*[TAO]',
            r'nmap\s+.*-p-',
            r'nmap\s+.*--min-rate\s+\d{3,}',
            r'nmap\s+.*-d',
            r'masscan\s+',
            r'for\s+.*\s*do.*\s*nc\s+.*\s*\d+',
            r'for\s+.*\s*do.*\s*ping\s+',
            r'hping3\s+',
            r'unicornscan\s+',
            r'amap\s+',
            r'nmap\s+.*--script',
            r'nmap\s+.*--script-updatedb',
            r'nmap\s+.*vulners',
            r'nmap\s+.*exploit',
            r'nmap\s+.*-sV\s+.*-sC',
            r'nmap\s+.*-A\s+.*-T[4-5]'
        ]
        
        # verificam pattern-urile foarte agresive
        for pattern in aggressive_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # scanari agresive, cu rata ridicata sau acoperire completa
                return 9  # severitate foarte mare (aproape maxima)
        
        # pattern-uri de scanare de acoperire larga sau cu rata medie (6-7)
        medium_patterns = [
            r'nmap\s+-[a-zA-Z0-9]*sV',
            r'nmap\s+-[a-zA-Z0-9]*sC',
            r'nmap\s+-[a-zA-Z0-9]*sS',
            r'nmap\s+-[a-zA-Z0-9]*sU',
            r'nmap\s+.*/24',
            r'nmap\s+.*-T[3]',
            r'for\s+p\s+in\s+.*\s*;\s*do.*\s*\d+',
            r'arp-scan\s+',
            r'tcpdump\s+',
            r'enum4linux\s+',
            r'onesixtyone\s+',
            r'smbclient\s+',
            r'showmount\s+'
        ]
        
        # verificam pattern-urile de severitate medie
        for pattern in medium_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # scanari cu acoperire medie sau rata moderata
                return 7  # severitate mare
        
        # pattern-uri de scanare limitate sau cu rata scazuta (4-5)
        limited_patterns = [
            r'nmap\s+-[a-zA-Z0-9]*sn',
            r'nmap\s+-[a-zA-Z0-9]*sP',
            r'nmap\s+.*-p\s+\d+,\d+',
            r'nmap\s+.*-T[1-2]',
            r'ping\s+(-[a-zA-Z0-9]+\s+)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'nc\s+-z\s+\S+\s+\d+',
            r'telnet\s+\S+\s+\d+',
            r'traceroute\s+',
            r'mtr\s+',
            r'nslookup\s+',
            r'dig\s+',
            r'host\s+'
        ]
        
        # verificam pattern-urile de severitate limitata
        for pattern in limited_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # scanari limitate la cateva porturi sau host-uri
                return 5  # severitate medie
        
        # pattern-uri de investigare pasiva (2-3)
        passive_patterns = [
            r'netstat\s+',
            r'ss\s+',
            r'lsof\s+-i',
            r'ip\s+a',
            r'ifconfig',
            r'route',
            r'arp\s+-a',
            r'cat\s+/etc/hosts',
            r'cat\s+/proc/net/\w+'
        ]
        
        # verificam pattern-urile de investigare pasiva
        for pattern in passive_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                # investigatii pasive, fara trafic de retea generat
                return 3  # severitate scazuta
        
        return severity