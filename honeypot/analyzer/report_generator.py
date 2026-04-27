#!/usr/bin/env python3

import datetime
import html as html_module
import logging
from pathlib import Path
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

logger = logging.getLogger('honeypot.analyzer')

@dataclass
class ReportConfig:
    title: str = "SSH Honeypot Session Analysis Report"
    max_commands_display: int = 10
    max_timeline_items: int = 50
    max_resources_per_type: int = 10

    css_classes = {
        'container': 'font-sans max-w-5xl mx-auto p-6',
        'section': 'bg-[#111111] p-5 mb-4 rounded-xl',
        'section_inner': 'rounded-xl bg-[#0f0f0f] p-4',
        'subsection': 'bg-[#0f0f0f] p-4 rounded-xl flex-1 min-w-0 mx-1 min-w-[280px] overflow-hidden',
        'title': 'text-white mb-3 text-xl font-medium',
        'subtitle': 'text-gray-300 text-base font-medium mb-3',
        'command': 'font-mono bg-[#1a1a1a] text-gray-300 px-2 py-1 mx-1 inline-block rounded-lg text-sm break-all',
        'critical': 'text-red-400 font-medium',
        'warning': 'text-orange-400',
        'info': 'text-gray-400',
        'success': 'text-gray-300'
    }

class DataFormatter:

    @staticmethod
    def format_timestamp(timestamp) -> str:
        if not timestamp or timestamp in ['Unknown', 'None', None]:
            return 'Unknown'
        try:
            if isinstance(timestamp, str):
                if 'T' in timestamp:
                    dt = datetime.datetime.fromisoformat(timestamp.replace('T', ' '))
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    return timestamp
            return str(timestamp)
        except:
            return str(timestamp) if timestamp else 'Unknown'

    @staticmethod
    def get_severity_class(severity: int) -> str:
        if severity >= 7:
            return 'critical'
        elif severity >= 4:
            return 'warning'
        else:
            return 'info'

    @staticmethod
    def get_expertise_class(level: str) -> str:
        classes = {
            'Beginner': 'bg-[#1a1a1a] text-gray-300',
            'Intermediate': 'bg-[#1a1a1a] text-gray-300',
            'Advanced': 'bg-[#1a1a1a] text-gray-300',
            'Expert': 'bg-[#1a1a1a] text-gray-300'
        }
        return classes.get(level, 'bg-[#1a1a1a] text-gray-300')

class ReportSection(ABC):
    def __init__(self, config: ReportConfig, data: Dict[str, Any]):
        self.config = config
        self.data = data
        self.formatter = DataFormatter()

    @abstractmethod
    def render_html(self) -> str:
        pass

    @abstractmethod
    def render_text(self) -> str:
        pass

    def _css(self, key: str) -> str:
        return self.config.css_classes.get(key, '')

class SessionInfoSection(ReportSection):

    def render_html(self) -> str:
        session_info = self.data.get('session_info', {})
        ip_info = session_info.get('ip_info', {})

        return f"""
        <div class="{self._css('section')}">
            <h2 class="{self._css('title')}">Session Information</h2>
            <div class="{self._css('section_inner')}">
                <div class="flex flex-wrap justify-between gap-4">
                    {self._render_attacker_info(ip_info)}
                    {self._render_session_details(session_info)}
                </div>
            </div>
        </div>
        """

    def _render_attacker_info(self, ip_info: Dict) -> str:
        def is_valid_value(value):
            if not value:
                return False
            if isinstance(value, str):
                invalid_values = ['unknown', 'none', 'null', '', 'n/a', '-']
                return value.lower().strip() not in invalid_values
            return True

        field_mapping = {
            'ip': 'IP',
            'hostname': 'Hostname',
            'country': 'Country',
            'city': 'City',
            'isp': 'ISP',
            'org': 'Organization',
            'region': 'Region'
        }

        table_rows = ""
        for field, label in field_mapping.items():
            value = ip_info.get(field)
            if is_valid_value(value):
                table_rows += f"""
                <tr>
                    <td class="p-2 text-sm text-gray-500">{label}</td>
                    <td class="p-2 text-sm text-gray-200">{value}</td>
                </tr>
                """

        if not table_rows:
            table_rows = """
            <tr>
                <td class="p-2 text-sm text-gray-500" colspan="2">No attacker information available</td>
            </tr>
            """

        return f"""
        <div class="{self._css('subsection')}">
            <h3 class="{self._css('subtitle')}">Attacker</h3>
            <table class="w-full border-collapse">
                {table_rows}
            </table>
        </div>
        """

    def _render_session_details(self, session_info: Dict) -> str:
        return f"""
        <div class="{self._css('subsection')}">
            <h3 class="{self._css('subtitle')}">Session</h3>
            <table class="w-full border-collapse">
                <tr>
                    <td class="p-2 text-sm text-gray-500">Start</td>
                    <td class="p-2 text-sm text-gray-200">{self.formatter.format_timestamp(session_info.get('start_time'))}</td>
                </tr>
                <tr>
                    <td class="p-2 text-sm text-gray-500">End</td>
                    <td class="p-2 text-sm text-gray-200">{self.formatter.format_timestamp(session_info.get('end_time'))}</td>
                </tr>
                <tr>
                    <td class="p-2 text-sm text-gray-500">Duration</td>
                    <td class="p-2 text-sm text-gray-200">{session_info.get('duration', 'N/A')}</td>
                </tr>
                <tr>
                    <td class="p-2 text-sm text-gray-500">Commands</td>
                    <td class="p-2 text-sm text-gray-200">{session_info.get('command_count', 0)}</td>
                </tr>
            </table>
        </div>
        """

    def render_text(self) -> str:
        session_info = self.data.get('session_info', {})
        ip_info = session_info.get('ip_info', {})

        return f"""SESSION INFORMATION
{'=' * 80}
Attacker IP: {ip_info.get('ip', 'Unknown')}
Hostname: {ip_info.get('hostname', 'Unknown')}
Country: {ip_info.get('country', 'Unknown')}
City: {ip_info.get('city', 'Unknown')}

Start: {self.formatter.format_timestamp(session_info.get('start_time'))}
End: {self.formatter.format_timestamp(session_info.get('end_time'))}
Duration: {session_info.get('duration', 'N/A')}
Commands: {session_info.get('command_count', 0)}

"""

class AttackSummarySection(ReportSection):

    def render_html(self) -> str:
        attacker_profile = self.data.get('attacker_profile', {})
        attack_categories = self.data.get('attack_categories', {})
        critical_commands = self.data.get('critical_commands', [])

        return f"""
        <div class="{self._css('section')}">
            <h2 class="{self._css('title')}">Attack Summary</h2>
            <div class="{self._css('section_inner')}">
                {self._render_expertise_info(attacker_profile)}
                <div class="flex flex-wrap justify-between mt-4 gap-4">
                    {self._render_top_categories(attack_categories)}
                    {self._render_critical_commands(critical_commands)}
                </div>
            </div>
        </div>
        """

    def _render_expertise_info(self, profile: Dict) -> str:
        expertise_level = profile.get('expertise_level', 'Unknown')
        expertise_score = profile.get('expertise_score', 0)
        automated = profile.get('automated_attack', False)

        expertise_class = self.formatter.get_expertise_class(expertise_level)
        automated_label = 'Yes' if automated else 'No'
        automated_color = 'text-red-400' if automated else 'text-gray-400'

        return f"""
        <p class="text-gray-300 text-sm mb-2">
            Expertise level:
            <span class="inline-block px-2 py-1 text-sm rounded-lg mr-1 {expertise_class}">
                {expertise_level}
            </span>
            <span class="text-gray-500">(Score: {expertise_score:.2f})</span>
        </p>
        <p class="text-gray-300 text-sm">
            Automated attack:
            <span class="{automated_color} font-medium">{automated_label}</span>
        </p>
        """

    def _render_top_categories(self, attack_categories: Dict) -> str:
        top_categories = attack_categories.get('top_categories', [])

        categories_html = ""
        for category, count in top_categories[:9]:
            display_name = category.replace('_', ' ').title()
            categories_html += f"""
            <li class="text-gray-300 text-sm mb-2">
                {display_name}:
                <span class="inline-block px-2 py-0.5 text-xs rounded-lg mr-1 bg-[#1a1a1a] text-gray-400">
                    {count}
                </span>
            </li>
            """

        return f"""
        <div class="{self._css('subsection')}">
            <p class="text-gray-400 text-sm font-medium mb-2">Top attack categories</p>
            <ul class="list-disc pl-5">
                {categories_html or '<li class="text-gray-500 text-sm">No categories detected</li>'}
            </ul>
        </div>
        """

    def _render_critical_commands(self, critical_commands: List) -> str:
        commands_html = ""
        for cmd_info in critical_commands[:10]:
            cmd = html_module.escape(cmd_info.get('command', ''))
            severity = cmd_info.get('severity', 0)

            if severity >= 7:
                severity_class = 'text-red-400'
            elif severity >= 4:
                severity_class = 'text-orange-400'
            else:
                severity_class = 'text-gray-500'

            commands_html += f"""
            <li class="text-gray-300 text-sm mb-2">
                <span class="{severity_class}">[{severity}]</span>
                <span class="{self._css('command')}">{cmd}</span>
            </li>
            """

        return f"""
        <div class="{self._css('subsection')}">
            <p class="text-gray-400 text-sm font-medium mb-2">Critical commands detected</p>
            <ul class="list-disc pl-5">
                {commands_html or '<li class="text-gray-500 text-sm">No critical commands detected</li>'}
            </ul>
        </div>
        """

    def render_text(self) -> str:
        attacker_profile = self.data.get('attacker_profile', {})
        attack_categories = self.data.get('attack_categories', {})
        critical_commands = self.data.get('critical_commands', [])

        lines = [
            "ATTACK SUMMARY",
            "=" * 80,
            f"Expertise level: {attacker_profile.get('expertise_level', 'Unknown')} "
            f"(Score: {attacker_profile.get('expertise_score', 0):.2f})",
            f"Automated attack: {'Yes' if attacker_profile.get('automated_attack') else 'No'}",
            "",
            "Top attack categories:"
        ]

        for category, count in attack_categories.get('top_categories', []):
            lines.append(f"- {category.replace('_', ' ').title()}: {count} commands")

        lines.extend(["", "Critical commands detected:"])
        for cmd_info in critical_commands[:10]:
            lines.append(f"- [{cmd_info.get('severity', 0)}] {cmd_info.get('command', '')}")

        lines.append("")
        return "\n".join(lines)

class AttackCategoriesSection(ReportSection):

    def render_html(self) -> str:
        attack_categories = self.data.get('attack_categories', {})
        categories = attack_categories.get('categories', {})

        if not categories:
            return f"""
            <div class="{self._css('section')}">
                <h2 class="{self._css('title')}">Attack Categories</h2>
                <div class="{self._css('section_inner')}">
                    <p class="text-gray-500 text-sm">No attack categories detected.</p>
                </div>
            </div>
            """

        categories_html = self._render_categories_grid(categories)

        return f"""
        <div class="{self._css('section')}">
            <h2 class="{self._css('title')}">Attack Categories</h2>
            <div class="{self._css('section_inner')}">
                <div class="flex flex-wrap justify-between gap-4">
                    {categories_html}
                </div>
            </div>
        </div>
        """

    def _render_categories_grid(self, categories: Dict) -> str:
        category_order = [
            'system_recon', 'privilege_escalation', 'data_exfiltration',
            'persistence', 'honeypot_detection', 'network_scanning',
            'file_access', 'malware_upload', 'lateral_movement'
        ]

        def get_category_priority(item):
            cat, cmds = item
            if cat in category_order:
                return (category_order.index(cat), -len(cmds))
            return (len(category_order), -len(cmds))

        active_categories = [(cat, cmds) for cat, cmds in categories.items() if cmds]
        active_categories.sort(key=get_category_priority)

        html_content = []

        for i in range(0, len(active_categories), 2):
            html_content.append('<div class="flex flex-wrap justify-between w-full">')
            cat, cmds = active_categories[i]
            html_content.append(self._render_single_category(cat, cmds))
            if i + 1 < len(active_categories):
                cat, cmds = active_categories[i + 1]
                html_content.append(self._render_single_category(cat, cmds))
            html_content.append('</div>')

        return ''.join(html_content)

    def _render_single_category(self, category: str, commands: List) -> str:
        category_names = {
            'system_recon': 'System Recon',
            'privilege_escalation': 'Privilege Escalation',
            'data_exfiltration': 'Data Exfiltration',
            'persistence': 'Persistence',
            'honeypot_detection': 'Honeypot Detection',
            'network_scanning': 'Network Scanning',
            'file_access': 'File Access',
            'malware_upload': 'Malware Upload',
            'lateral_movement': 'Lateral Movement',
            'brute_force': 'Brute Force',
            'exploration': 'Exploration'
        }

        display_name = category_names.get(category, category.replace('_', ' ').title())

        commands_html = ""
        for cmd in commands[:self.config.max_commands_display]:
            escaped_cmd = html_module.escape(cmd)
            commands_html += f'<li class="mb-2"><span class="{self._css("command")}">{escaped_cmd}</span></li>'

        if len(commands) > self.config.max_commands_display:
            remaining = len(commands) - self.config.max_commands_display
            commands_html += f'<li class="text-gray-500 text-sm mb-2">... and {remaining} more commands</li>'

        return f"""
        <div class="{self._css('subsection')}">
            <h3 class="text-gray-300 text-sm font-medium mb-3">
                {display_name}
                <span class="inline-block px-2 py-0.5 text-xs rounded-lg ml-1 bg-[#1a1a1a] text-gray-400">
                    {len(commands)}
                </span>
            </h3>
            <ul class="list-disc pl-5 text-gray-300">
                {commands_html}
            </ul>
        </div>
        """

    def render_text(self) -> str:
        attack_categories = self.data.get('attack_categories', {})
        categories = attack_categories.get('categories', {})

        if not categories:
            return "ATTACK CATEGORIES\n" + "=" * 80 + "\nNo attack categories detected.\n\n"

        lines = ["ATTACK CATEGORIES", "=" * 80]

        sorted_categories = sorted(
            [(cat, cmds) for cat, cmds in categories.items() if cmds],
            key=lambda x: len(x[1]), reverse=True
        )

        for cat, cmds in sorted_categories:
            display_name = cat.replace('_', ' ').title()
            lines.append(f"\n{display_name} ({len(cmds)} commands):")
            for cmd in cmds[:self.config.max_commands_display]:
                lines.append(f"- {cmd}")
            if len(cmds) > self.config.max_commands_display:
                lines.append(f"- ... and {len(cmds) - self.config.max_commands_display} more commands")

        lines.append("")
        return "\n".join(lines)

class TimelineSection(ReportSection):

    def render_html(self) -> str:
        timeline = self.data.get('timeline', [])

        if not timeline:
            return f"""
            <div class="{self._css('section')}">
                <h2 class="{self._css('title')}">Attack Timeline</h2>
                <div class="{self._css('section_inner')}">
                    <p class="text-gray-500 text-sm">No timeline data available.</p>
                </div>
            </div>
            """

        phases_html = self._render_timeline_by_phases(timeline)

        return f"""
        <div class="{self._css('section')}">
            <h2 class="{self._css('title')}">Attack Timeline</h2>
            <div class="{self._css('section_inner')}">
                {phases_html}
            </div>
        </div>
        """

    def _render_timeline_by_phases(self, timeline: List) -> str:
        phases = {}
        for item in timeline:
            phase = item.get('phase', 'unknown')
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(item)

        phase_config = {
            'reconnaissance': {'color': '#555', 'name': 'Reconnaissance'},
            'persistence':    {'color': '#555', 'name': 'Persistence'},
            'exploitation':   {'color': '#7a3a3a', 'name': 'Exploitation'},
            'data_collection':{'color': '#555', 'name': 'Data Collection'},
            'exploration':    {'color': '#555', 'name': 'Exploration'},
            'cleanup':        {'color': '#333', 'name': 'Cleanup'}
        }

        phase_order = ['reconnaissance', 'persistence', 'exploitation', 'data_collection', 'exploration', 'cleanup']

        html_content = []
        for phase in phase_order:
            if phase not in phases or not phases[phase]:
                continue

            cfg = phase_config.get(phase, {'color': '#333', 'name': phase.replace('_', ' ').title()})
            color = cfg['color']
            phase_name = cfg['name']
            commands = phases[phase]

            html_content.append(f"""
            <div class="bg-[#0a0a0a] p-4 mb-4 rounded-xl" style="border-left: 2px solid {color}">
                <h3 class="text-gray-300 text-sm font-medium mb-3">{phase_name}</h3>
            """)

            for cmd_info in commands:
                html_content.append(self._render_timeline_command(cmd_info, color))

            html_content.append('</div>')

        return ''.join(html_content)

    def _render_timeline_command(self, cmd_info: Dict, color: str) -> str:
        timestamp = cmd_info.get('timestamp', '')
        command = html_module.escape(cmd_info.get('command', ''))
        categories = cmd_info.get('categories', [])
        is_critical = cmd_info.get('critical', False)
        critical_reason = cmd_info.get('critical_reason', '')

        critical_class = 'text-red-400' if is_critical else ''

        html_content = f"""
        <div class="p-3 rounded-xl mb-2 bg-[#111111] {critical_class}">
            <div class="text-gray-500 text-xs mb-1">{timestamp}</div>
            <div class="font-mono bg-[#1a1a1a] rounded-lg text-gray-300 px-2 py-1 block my-1 text-sm break-all">{command}</div>
        """

        if categories:
            html_content += '<div class="mt-2 flex flex-wrap gap-1">'
            for category in categories:
                html_content += f'<span class="inline-block px-2 py-0.5 text-xs rounded-lg bg-[#1a1a1a] text-gray-400">{category}</span>'
            html_content += '</div>'

        if is_critical and critical_reason:
            html_content += f'<div class="text-red-400 text-xs mt-2">Alert: {critical_reason}</div>'

        html_content += '</div>'
        return html_content

    def render_text(self) -> str:
        timeline = self.data.get('timeline', [])

        if not timeline:
            return "ATTACK TIMELINE\n" + "=" * 80 + "\nNo timeline data available.\n\n"

        lines = ["ATTACK TIMELINE", "=" * 80]

        phases = {}
        for item in timeline:
            phase = item.get('phase', 'unknown')
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(item)

        for phase, commands in phases.items():
            if not commands:
                continue

            lines.append(f"\n{phase.replace('_', ' ').upper()}:")

            for cmd_info in commands:
                timestamp = cmd_info.get('timestamp', '')
                command = cmd_info.get('command', '')
                is_critical = cmd_info.get('critical', False)
                critical_reason = cmd_info.get('critical_reason', '')

                critical_mark = "!!! " if is_critical else ""
                lines.append(f"[{timestamp}] {critical_mark}{command}")

                if is_critical and critical_reason:
                    lines.append(f"  ALERT: {critical_reason}")

                lines.append("")

        return "\n".join(lines)

class ResourcesSection(ReportSection):

    def render_html(self) -> str:
        uploaded_files = self.data.get('uploaded_files', {})
        accessed_resources = self.data.get('accessed_resources', {})

        return f"""
        <div class="{self._css('section')}">
            <h2 class="{self._css('title')}">Files & Accessed Resources</h2>
            <div class="{self._css('section_inner')}">
                {self._render_uploaded_files(uploaded_files)}
                {self._render_accessed_resources(accessed_resources)}
            </div>
        </div>
        """

    def _render_uploaded_files(self, uploaded_files: Dict) -> str:
        confirmed = uploaded_files.get('confirmed_uploads', [])
        potential = uploaded_files.get('potential_uploads', [])

        html_content = f"""
        <p class="text-gray-400 text-sm mb-4">
            Uploaded files: <span class="text-gray-200">{len(confirmed)}</span> confirmed,
            <span class="text-gray-200">{len(potential)}</span> potential
        </p>
        """

        if confirmed or potential:
            html_content += '<div class="flex flex-wrap justify-between gap-4 mb-4">'

            html_content += f"""
            <div class="{self._css('subsection')}">
                <h3 class="{self._css('subtitle')}">Confirmed files</h3>
            """
            if confirmed:
                html_content += self._render_files_table(confirmed, ['File', 'Timestamp'], True)
            else:
                html_content += '<p class="text-gray-500 text-sm">No confirmed files detected</p>'
            html_content += '</div>'

            html_content += f"""
            <div class="{self._css('subsection')}">
                <h3 class="{self._css('subtitle')}">Potential files</h3>
            """
            if potential:
                html_content += self._render_files_table(potential, ['File', 'Source', 'Method'], False)
            else:
                html_content += '<p class="text-gray-500 text-sm">No potential files detected</p>'
            html_content += '</div></div>'

        return html_content

    def _render_files_table(self, files: List, headers: List, is_confirmed: bool) -> str:
        html_content = '<table class="w-full border-collapse table-fixed"><tr>'
        for header in headers:
            html_content += f'<th class="p-2 text-left text-xs text-gray-500 font-medium uppercase tracking-wider">{header}</th>'
        html_content += '</tr>'

        for file_info in files:
            filename = html_module.escape(file_info.get('filename', 'Unknown'))
            html_content += '<tr>'
            html_content += f'<td class="p-2"><span class="{self._css("command")}">{filename}</span></td>'
            if is_confirmed:
                timestamp = file_info.get('timestamp', 'Unknown')
                html_content += f'<td class="p-2 text-sm text-gray-400 break-all">{timestamp}</td>'
            else:
                source = html_module.escape(file_info.get('source', 'Unknown'))
                method = file_info.get('method', 'Unknown')
                html_content += f'<td class="p-2 text-sm text-gray-400 break-all">{source}</td>'
                html_content += f'<td class="p-2 text-sm text-gray-400 break-all">{method}</td>'
            html_content += '</tr>'

        html_content += '</table>'
        return html_content

    def _render_accessed_resources(self, resources: Dict) -> str:
        html_content = '<h3 class="text-gray-400 text-sm font-medium mb-3 mt-2">Accessed resources</h3>'

        if not resources or not any(resources.values()):
            return html_content + '<p class="text-gray-500 text-sm">No accessed resources detected</p>'

        html_content += '<div class="flex flex-wrap justify-between gap-4">'
        html_content += self._render_resource_column(resources, 'files', 'Files')
        html_content += self._render_resource_column(resources, 'directories', 'Directories')
        html_content += '</div>'

        if resources.get('processes') or resources.get('network'):
            html_content += '<div class="flex flex-wrap justify-between gap-4 mt-4">'
            html_content += self._render_resource_column(resources, 'processes', 'Processes')
            html_content += self._render_resource_column(resources, 'network', 'Network')
            html_content += '</div>'

        html_content += '<div class="flex flex-wrap justify-between gap-4 mt-4">'
        html_content += self._render_resource_column(resources, 'users', 'Users')
        html_content += self._render_trap_files_column(resources)
        html_content += '</div>'

        return html_content

    def _render_resource_column(self, resources: Dict, res_type: str, res_title: str) -> str:
        resource_list = resources.get(res_type, [])

        html_content = f"""
        <div class="{self._css('subsection')}">
            <h4 class="{self._css('subtitle')}">{res_title}</h4>
        """

        if resource_list:
            html_content += '<ul class="text-gray-300 list-disc pl-5">'
            display_count = min(len(resource_list), self.config.max_resources_per_type)
            for resource in resource_list[:display_count]:
                escaped_resource = html_module.escape(resource)
                html_content += f'<li class="mb-1 text-sm break-all"><span class="{self._css("command")}">{escaped_resource}</span></li>'
            if len(resource_list) > display_count:
                remaining = len(resource_list) - display_count
                html_content += f'<li class="text-gray-500 text-sm">... and {remaining} more {res_title.lower()}</li>'
            html_content += '</ul>'
        else:
            html_content += f'<p class="text-gray-500 text-sm">No {res_title.lower()} accessed</p>'

        html_content += '</div>'
        return html_content

    def _render_trap_files_column(self, resources: Dict) -> str:
        trap_files = resources.get('trap_files', [])

        html_content = f"""
        <div class="{self._css('subsection')}">
            <h4 class="{self._css('subtitle')}">Trap files accessed</h4>
        """

        if trap_files:
            html_content += '<ul class="text-gray-300 list-disc pl-5">'
            for trap_file in trap_files:
                escaped_file = html_module.escape(trap_file)
                html_content += f'<li class="mb-1 text-sm"><span class="{self._css("command")}">{escaped_file}</span></li>'
            html_content += '</ul>'
        else:
            html_content += '<p class="text-gray-500 text-sm">No trap files accessed</p>'

        html_content += '</div>'
        return html_content

    def render_text(self) -> str:
        uploaded_files = self.data.get('uploaded_files', {})
        accessed_resources = self.data.get('accessed_resources', {})

        confirmed = uploaded_files.get('confirmed_uploads', [])
        potential = uploaded_files.get('potential_uploads', [])

        lines = [
            "FILES & ACCESSED RESOURCES",
            "=" * 80,
            f"Uploaded files: {len(confirmed)} confirmed, {len(potential)} potential"
        ]

        if confirmed:
            lines.extend(["\nConfirmed files:"])
            for file_info in confirmed:
                lines.append(f"- {file_info.get('filename', 'Unknown')}")

        if potential:
            lines.extend(["\nPotential files:"])
            for file_info in potential:
                filename = file_info.get('filename', 'Unknown')
                source = file_info.get('source', 'Unknown')
                method = file_info.get('method', 'Unknown')
                lines.append(f"- {filename} (via {method} from {source})")

        lines.extend(["\nAccessed resources:"])

        resource_types = [
            ('files', 'Files'),
            ('directories', 'Directories'),
            ('processes', 'Processes'),
            ('network', 'Network'),
            ('users', 'Users')
        ]

        for res_type, res_title in resource_types:
            resource_list = accessed_resources.get(res_type, [])
            if resource_list:
                lines.append(f"\n{res_title}:")
                display_count = min(len(resource_list), self.config.max_resources_per_type)
                for resource in resource_list[:display_count]:
                    lines.append(f"- {resource}")
                if len(resource_list) > display_count:
                    lines.append(f"  ... and {len(resource_list) - display_count} more {res_title.lower()}")

        lines.append("")
        return "\n".join(lines)

class TimingPatternsSection(ReportSection):

    def render_html(self) -> str:
        timing = self.data.get('timing_patterns', {})

        if not timing:
            return ""

        return f"""
        <div class="{self._css('section')}">
            <h2 class="{self._css('title')}">Timing Patterns</h2>
            <div class="{self._css('section_inner')}">
                {self._render_timing_stats(timing)}
                {self._render_unusual_intervals(timing)}
            </div>
        </div>
        """

    def _render_timing_stats(self, timing: Dict) -> str:
        avg_interval = timing.get('average_interval', 0)
        min_interval = timing.get('min_interval', 0)
        max_interval = timing.get('max_interval', 0)
        std_dev = timing.get('std_deviation', 0)

        return f"""
        <div class="flex flex-wrap justify-between gap-4 mb-4">
            <div class="{self._css('subsection')}">
                <h3 class="{self._css('subtitle')}">General Statistics</h3>
                <table class="w-full border-collapse">
                    <tr>
                        <td class="p-2 text-sm text-gray-500">Average interval</td>
                        <td class="p-2 text-sm text-gray-200">{avg_interval:.2f}s</td>
                    </tr>
                    <tr>
                        <td class="p-2 text-sm text-gray-500">Minimum interval</td>
                        <td class="p-2 text-sm text-gray-200">{min_interval:.2f}s</td>
                    </tr>
                    <tr>
                        <td class="p-2 text-sm text-gray-500">Maximum interval</td>
                        <td class="p-2 text-sm text-gray-200">{max_interval:.2f}s</td>
                    </tr>
                    <tr>
                        <td class="p-2 text-sm text-gray-500">Standard deviation</td>
                        <td class="p-2 text-sm text-gray-200">{std_dev:.2f}s</td>
                    </tr>
                </table>
            </div>
        </div>
        """

    def _render_unusual_intervals(self, timing: Dict) -> str:
        unusual = timing.get('unusual_intervals', [])

        if not unusual:
            return ""

        html_content = f"""
        <h3 class="text-gray-400 text-sm font-medium mb-3">Unusual intervals detected</h3>
        <div class="{self._css('subsection')}">
            <table class="w-full border-collapse table-fixed">
                <tr>
                    <th class="p-2 text-left text-xs text-gray-500 font-medium uppercase tracking-wider w-2/5">Previous command</th>
                    <th class="p-2 text-left text-xs text-gray-500 font-medium uppercase tracking-wider w-2/5">Next command</th>
                    <th class="p-2 text-left text-xs text-gray-500 font-medium uppercase tracking-wider w-1/5">Interval (s)</th>
                </tr>
        """

        for interval in unusual:
            before = html_module.escape(interval.get('before_command', ''))
            after = html_module.escape(interval.get('after_command', ''))
            time = interval.get('interval', 0)

            html_content += f"""
                <tr>
                    <td class="p-2"><span class="{self._css('command')}">{before}</span></td>
                    <td class="p-2"><span class="{self._css('command')}">{after}</span></td>
                    <td class="p-2 text-sm text-gray-300">{time:.2f}</td>
                </tr>
            """

        html_content += '</table></div>'
        return html_content

    def render_text(self) -> str:
        timing = self.data.get('timing_patterns', {})

        if not timing:
            return ""

        avg_interval = timing.get('average_interval', 0)
        min_interval = timing.get('min_interval', 0)
        max_interval = timing.get('max_interval', 0)
        unusual = timing.get('unusual_intervals', [])

        lines = [
            "TIMING PATTERNS",
            "=" * 80,
            f"Average interval between commands: {avg_interval:.2f} seconds",
            f"Minimum interval: {min_interval:.2f} seconds",
            f"Maximum interval: {max_interval:.2f} seconds"
        ]

        if unusual:
            lines.extend(["\nUnusual intervals detected:"])
            for interval in unusual:
                before = interval.get('before_command', '')
                after = interval.get('after_command', '')
                time = interval.get('interval', 0)
                lines.extend([
                    f"- Pause of {time:.2f} seconds between:",
                    f"  * {before}",
                    f"  * {after}"
                ])

        lines.append("")
        return "\n".join(lines)

class ReportGenerator:
    def __init__(self, session_data: Dict[str, Any], config: Optional[ReportConfig] = None):
        self.session_data = session_data
        self.config = config or ReportConfig()
        self.sections = self._initialize_sections()

    def _initialize_sections(self) -> List[ReportSection]:
        return [
            SessionInfoSection(self.config, self.session_data),
            AttackSummarySection(self.config, self.session_data),
            AttackCategoriesSection(self.config, self.session_data),
            TimelineSection(self.config, self.session_data),
            ResourcesSection(self.config, self.session_data),
            TimingPatternsSection(self.config, self.session_data)
        ]

    def generate_html_report(self) -> str:
        html_content = self._get_html_header()

        for section in self.sections:
            try:
                section_html = section.render_html()
                if section_html.strip():
                    html_content += section_html
            except Exception as e:
                logger.error(f"Error rendering HTML section: {str(e)}")
                continue

        html_content += self._get_html_footer()
        return html_content

    def generate_text_report(self) -> str:
        text_content = self._get_text_header()

        for section in self.sections:
            try:
                section_text = section.render_text()
                if section_text.strip():
                    text_content += section_text
            except Exception as e:
                logger.error(f"Error rendering text section: {str(e)}")
                continue

        text_content += self._get_text_footer()
        return text_content

    def _get_html_header(self) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.config.title}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ background: #0a0a0a; font-family: system-ui, sans-serif; }}
    </style>
</head>
<body class="{self.config.css_classes['container']}">
    <div style="padding: 24px 0 8px">
        <h1 class="text-white text-2xl font-medium">{self.config.title}</h1>
        <p class="text-gray-500 text-sm mt-1">Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
"""

    def _get_html_footer(self) -> str:
        return f"""
    <footer class="mt-6 text-sm text-gray-600 pt-4">
        <p>Report generated at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — SSH Honeypot Analyzer</p>
    </footer>
</body>
</html>
"""

    def _get_text_header(self) -> str:
        return f"""{'=' * 80}
{self.config.title.upper()}
Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 80}

"""

    def _get_text_footer(self) -> str:
        return f"""{'=' * 80}
End of report | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 80}
"""