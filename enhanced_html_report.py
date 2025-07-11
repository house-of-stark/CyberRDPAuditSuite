#!/usr/bin/env python3
"""
Enhanced HTML Security Report Generator for RDP Security Testing

This module generates comprehensive HTML reports for RDP security testing results,
including vulnerability details, risk assessments, and remediation recommendations.
"""

import json
import sys
import os
import argparse
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import webbrowser
from dataclasses import dataclass

# Constants for report styling and configuration
REPORT_TITLE = "RDP Security Assessment Report"
COMPANY_NAME = "CyberArk Security Team"
REPORT_VERSION = "2.0.0"

# Color scheme for different severity levels
SEVERITY_COLORS = {
    'critical': '#dc3545',
    'high': '#ff6b6b',
    'medium': '#ffc107',
    'low': '#17a2b8',
    'info': '#6c757d',
    'success': '#28a745'
}

@dataclass
class Vulnerability:
    """Class to represent a security vulnerability finding"""
    id: str
    title: str
    severity: str
    description: str
    impact: str
    recommendation: str
    references: List[Dict[str, str]]
    cvss_score: str
    status: str = 'Open'
    evidence: List[str] = None
    affected_assets: List[str] = None
    first_seen: str = None
    last_seen: str = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity.lower(),
            'description': self.description,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'references': self.references,
            'cvss_score': self.cvss_score,
            'status': self.status,
            'evidence': self.evidence or [],
            'affected_assets': self.affected_assets or [],
            'first_seen': self.first_seen or datetime.now().isoformat(),
            'last_seen': self.last_seen or datetime.now().isoformat()
        }

def get_vulnerability_details(vuln_type: str, severity: str = None) -> Dict[str, Any]:
    """Get detailed information about a specific vulnerability type.
    
    Args:
        vuln_type: Type of vulnerability (e.g., 'bruteforce', 'mfa_bypass')
        severity: Optional severity level ('Critical', 'High', 'Medium', 'Low')
        
    Returns:
        Dictionary containing detailed vulnerability information
    """
    # Default details structure
    details = {
        'title': vuln_type.replace('_', ' ').title(),
        'description': 'No additional details available.',
        'impact': 'Impact not specified.',
        'recommendation': 'No specific recommendation provided.',
        'mitigation': 'No specific mitigation provided.',
        'references': [],
        'technical_details': {},
        'cvss_score': get_cvss_score(severity or 'medium'),
        'category': 'Authentication',
        'cwe': [],
        'mitre_attack': [],
        'nist_controls': [],
        'exploit_available': False,
        'exploit_frameworks': [],
        'detection_methods': []
    }
    
    # Enhanced vulnerability database with detailed information
    vuln_db = {
        # Authentication Bypass
        'authentication_bypass': {
            'title': 'Authentication Bypass',
            'description': 'The system is vulnerable to authentication bypass techniques that could allow unauthorized access.',
            'impact': 'Attackers could gain unauthorized access to the RDP service without valid credentials.',
            'recommendation': (
                '1. Implement Network Level Authentication (NLA)\n'
                '2. Enable Restricted Admin mode\n'
                '3. Apply the latest security patches\n'
                '4. Monitor authentication logs for suspicious activities'
            ),
            'mitigation': (
                '1. Enable Network Level Authentication (NLA)\n'
                '2. Implement account lockout policies\n'
                '3. Use strong authentication mechanisms\n'
                '4. Monitor and alert on repeated authentication failures'
            ),
            'category': 'Authentication',
            'cwe': ['CWE-287: Improper Authentication', 'CWE-306: Missing Authentication for Critical Function'],
            'mitre_attack': ['T1110: Brute Force', 'T1078: Valid Accounts'],
            'nist_controls': ['AC-2: Account Management', 'AC-7: Unsuccessful Logon Attempts'],
            'exploit_available': True,
            'exploit_frameworks': ['Metasploit', 'Cobalt Strike'],
            'detection_methods': ['Network monitoring', 'Authentication logs', 'SIEM alerts'],
            'references': [
                {'title': 'CWE-287', 'url': 'https://cwe.mitre.org/data/definitions/287.html'},
                {'title': 'MITRE ATT&CK T1110', 'url': 'https://attack.mitre.org/techniques/T1110/'},
                {'title': 'NIST SP 800-53', 'url': 'https://nvd.nist.gov/800-53'}
            ],
            'technical_details': {
                'attack_vectors': ['Network', 'RDP Protocol'],
                'required_privileges': 'None',
                'exploit_complexity': 'Low',
                'detection_difficulty': 'Medium',
                'common_weakness_enumeration': 'CWE-287',
                'cvss_vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'remediation_level': 'Official Fix',
                'report_confidence': 'Confirmed'
            }
        },
        
        # BlueKeep Vulnerability (CVE-2019-0708)
        'bluekeep': {
            'title': 'BlueKeep Vulnerability (CVE-2019-0708)',
            'description': 'The system is vulnerable to the BlueKeep RDP vulnerability, which could allow remote code execution without authentication.',
            'impact': 'Remote code execution with system-level privileges, potentially leading to full system compromise.',
            'recommendation': (
                '1. Apply Microsoft security update KB4499164, KB4499175, or later\n'
                '2. Enable Network Level Authentication (NLA)\n'
                '3. Block TCP port 3389 at the network perimeter if not needed\n'
                '4. Consider using a VPN for RDP access'
            ),
            'mitigation': (
                '1. Apply all available Windows updates\n'
                '2. Enable Network Level Authentication (NLA)\n'
                '3. Restrict RDP access using firewalls\n'
                '4. Monitor for exploit attempts'
            ),
            'category': 'Remote Code Execution',
            'cwe': ['CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer'],
            'mitre_attack': ['T1210: Exploitation of Remote Services'],
            'nist_controls': ['SI-2: Flaw Remediation', 'SI-3: Malicious Code Protection'],
            'exploit_available': True,
            'exploit_frameworks': ['Metasploit', 'Cobalt Strike', 'Custom Exploits'],
            'detection_methods': ['Network monitoring', 'IDS/IPS signatures', 'SIEM alerts'],
            'references': [
                {'title': 'CVE-2019-0708', 'url': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708'},
                {'title': 'Microsoft Advisory', 'url': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708'},
                {'title': 'MITRE ATT&CK T1210', 'url': 'https://attack.mitre.org/techniques/T1210/'}
            ],
            'technical_details': {
                'attack_vectors': ['Network'],
                'required_privileges': 'None',
                'exploit_complexity': 'Low',
                'detection_difficulty': 'Low',
                'common_weakness_enumeration': 'CWE-119',
                'cvss_vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'cvss_score': '9.8',
                'remediation_level': 'Official Fix',
                'report_confidence': 'Confirmed',
                'affected_versions': [
                    'Windows 7',
                    'Windows Server 2008 R2',
                    'Windows Server 2008',
                    'Windows XP',
                    'Windows Server 2003'
                ],
                'patched_versions': [
                    'Windows 7 with KB4499164',
                    'Windows Server 2008 R2 with KB4499175',
                    'Windows Server 2008 with KB4499180',
                    'Windows XP (End of Life)'
                ]
            }
        },
        
        # Session Hijacking
        'session_hijacking': {
            'title': 'RDP Session Hijacking',
            'description': 'The system is vulnerable to session hijacking attacks due to weak session management.',
            'impact': 'Attackers could take over active RDP sessions, potentially gaining unauthorized access to sensitive systems and data.',
            'recommendation': (
                '1. Enable Network Level Authentication (NLA)\n'
                '2. Implement session timeouts and automatic logoff\n'
                '3. Use Remote Desktop Gateway with proper security configurations\n'
                '4. Monitor for unusual session activities'
            ),
            'mitigation': (
                '1. Enable Network Level Authentication (NLA)\n'
                '2. Configure session timeouts and automatic logoff\n'
                '3. Implement account lockout policies\n'
                '4. Monitor and alert on suspicious session activities'
            ),
            'category': 'Session Security',
            'cwe': ['CWE-384: Session Fixation', 'CWE-613: Insufficient Session Expiration'],
            'mitre_attack': ['T1563: Remote Service Session Hijacking'],
            'nist_controls': ['AC-12: Session Termination', 'SI-4: System Monitoring'],
            'exploit_available': True,
            'exploit_frameworks': ['Metasploit', 'Custom Scripts'],
            'detection_methods': ['Session monitoring', 'Authentication logs', 'SIEM alerts'],
            'references': [
                {'title': 'CWE-384', 'url': 'https://cwe.mitre.org/data/definitions/384.html'},
                {'title': 'MITRE ATT&CK T1563', 'url': 'https://attack.mitre.org/techniques/T1563/'},
                {'title': 'Microsoft RDP Security', 'url': 'https://docs.microsoft.com/en-us/windows/security/remote-remote-desktop-services/remote-desktop-security-recommendations'}
            ],
            'technical_details': {
                'attack_vectors': ['Network', 'RDP Protocol'],
                'required_privileges': 'Valid user credentials (in some cases)',
                'exploit_complexity': 'Medium',
                'detection_difficulty': 'High',
                'common_weakness_enumeration': 'CWE-384',
                'cvss_vector': 'AV:N/AC:M/Au:N/C:P/I:P/A:P',
                'cvss_score': '6.8',
                'remediation_level': 'Official Fix',
                'report_confidence': 'Confirmed'
            }
        },
        
        # Weak Encryption
        'weak_encryption': {
            'title': 'Weak Encryption Configuration',
            'description': 'The RDP service is configured to use weak encryption protocols or cipher suites.',
            'impact': 'Sensitive data transmitted over RDP could be intercepted and decrypted by attackers.',
            'recommendation': (
                '1. Configure RDP to use strong encryption (128-bit or higher)\n'
                '2. Disable support for RC4 and other weak ciphers\n'
                '3. Enable FIPS compliance if required\n'
                '4. Regularly audit and update encryption settings'
            ),
            'mitigation': (
                '1. Update group policy to enforce strong encryption\n'
                '2. Disable support for legacy encryption methods\n'
                '3. Monitor for attempts to negotiate weak ciphers\n'
                '4. Consider using Remote Desktop Gateway with SSL/TLS encryption'
            ),
            'category': 'Encryption',
            'cwe': ['CWE-326: Inadequate Encryption Strength', 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'],
            'mitre_attack': ['T1573: Encrypted Channel'],
            'nist_controls': ['SC-13: Cryptographic Protection', 'SC-12: Cryptographic Key Management'],
            'exploit_available': True,
            'exploit_frameworks': ['Wireshark', 'Custom Scripts'],
            'detection_methods': ['Network scanning', 'Vulnerability scanning', 'SIEM monitoring'],
            'references': [
                {'title': 'CWE-326', 'url': 'https://cwe.mitre.org/data/definitions/326.html'},
                {'title': 'Microsoft RDP Encryption', 'url': 'https://docs.microsoft.com/en-us/windows/security/remote-remote-desktop-services/remote-desktop-security-recommendations#encryption'},
                {'title': 'NIST SP 800-52', 'url': 'https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final'}
            ],
            'technical_details': {
                'attack_vectors': ['Network'],
                'required_privileges': 'None',
                'exploit_complexity': 'Medium',
                'detection_difficulty': 'Low',
                'common_weakness_enumeration': 'CWE-326',
                'cvss_vector': 'AV:N/AC:M/Au:N/C:P/I:N/A:N',
                'cvss_score': '4.3',
                'remediation_level': 'Official Fix',
                'report_confidence': 'Confirmed'
            }
        },
        
        # Credential Theft via Pass-the-Hash
        'pass_the_hash': {
            'title': 'Credential Theft via Pass-the-Hash',
            'description': 'The system is vulnerable to Pass-the-Hash attacks, allowing attackers to authenticate without knowing the actual password.',
            'impact': 'Attackers could gain unauthorized access to systems using stolen password hashes without needing to crack them.',
            'recommendation': (
                '1. Enable Credential Guard on Windows 10/Server 2016+\n'
                '2. Implement Restricted Admin mode for RDP\n'
                '3. Use LSA Protection to prevent credential theft\n'
                '4. Monitor for suspicious authentication attempts'
            ),
            'mitigation': (
                '1. Enable Credential Guard\n'
                '2. Implement Restricted Admin mode\n'
                '3. Use LSA Protection\n'
                '4. Monitor for suspicious authentication patterns'
            ),
            'category': 'Credential Theft',
            'cwe': ['CWE-287: Improper Authentication', 'CWE-522: Insufficiently Protected Credentials'],
            'mitre_attack': ['T1550: Use Alternate Authentication Material'],
            'nist_controls': ['IA-5: Authenticator Management', 'IA-8: Identification and Authentication (Non-Organizational Users)'],
            'exploit_available': True,
            'exploit_frameworks': ['Mimikatz', 'Metasploit', 'Cobalt Strike'],
            'detection_methods': ['Authentication logs', 'Endpoint detection', 'SIEM monitoring'],
            'references': [
                {'title': 'MITRE ATT&CK T1550', 'url': 'https://attack.mitre.org/techniques/T1550/'},
                {'title': 'Microsoft Credential Guard', 'url': 'https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard'},
                {'title': 'Microsoft LSA Protection', 'url': 'https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection'}
            ],
            'technical_details': {
                'attack_vectors': ['Network', 'Local system'],
                'required_privileges': 'Local administrator',
                'exploit_complexity': 'Low',
                'detection_difficulty': 'Medium',
                'common_weakness_enumeration': 'CWE-287',
                'cvss_vector': 'AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
                'cvss_score': '7.2',
                'remediation_level': 'Official Fix',
                'report_confidence': 'Confirmed'
            }
        }
    }
    
    # Normalize the vulnerability type
    normalized_type = vuln_type.lower().replace(' ', '_')
    
    # Return matching vulnerability details or default
    result = vuln_db.get(normalized_type, details)
    
    # Update the severity if provided
    if severity:
        result['severity'] = severity.lower()
        result['cvss_score'] = get_cvss_score(severity)
    
    return result

def get_cvss_score(severity: str) -> dict:
    """Get CVSS score details based on severity.
    
    Args:
        severity: Severity level ('Critical', 'High', 'Medium', 'Low', 'Info')
        
    Returns:
        Dictionary containing CVSS score details
    """
    severity = (severity or '').lower()
    
    cvss_scores = {
        'critical': {
            'score': '9.0-10.0',
            'base_score': 9.5,
            'impact_score': 6.0,
            'exploitability_score': 3.5,
            'vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        },
        'high': {
            'score': '7.0-8.9',
            'base_score': 7.5,
            'impact_score': 5.0,
            'exploitability_score': 2.5,
            'vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
        },
        'medium': {
            'score': '4.0-6.9',
            'base_score': 5.5,
            'impact_score': 3.0,
            'exploitability_score': 2.5,
            'vector': 'AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N'
        },
        'low': {
            'score': '0.1-3.9',
            'base_score': 2.5,
            'impact_score': 1.0,
            'exploitability_score': 1.5,
            'vector': 'AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N'
        },
        'info': {
            'score': '0.0',
            'base_score': 0.0,
            'impact_score': 0.0,
            'exploitability_score': 0.0,
            'vector': 'N/A',
            'description': 'Informational finding with no direct security impact'
        }
    }
    
    return cvss_scores.get(severity, cvss_scores['info'])

def process_findings(findings: list) -> dict:
    """Process raw findings and organize them by severity and category.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Dictionary of processed findings organized by severity and category
    """
    processed = {
        'by_severity': {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        },
        'by_category': {},
        'total_count': 0,
        'severity_counts': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        },
        'risk_score': 0,
        'findings': []
    }
    
    for finding in findings:
        # Ensure finding has required fields
        if not isinstance(finding, dict):
            continue
            
        # Set default values if not present
        finding.setdefault('severity', 'info')
        finding.setdefault('category', 'Other')
        finding.setdefault('title', 'Untitled Finding')
        finding.setdefault('id', f"FND-{len(processed['findings']) + 1:04d}")
        
        # Add to findings list
        processed['findings'].append(finding)
        
        # Categorize by severity
        severity = finding['severity'].lower()
        if severity in processed['by_severity']:
            processed['by_severity'][severity].append(finding)
            processed['severity_counts'][severity] += 1
            
            # Calculate risk score (weighted by severity)
            weights = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
            processed['risk_score'] += weights.get(severity, 1)
        
        # Categorize by category
        category = finding['category']
        if category not in processed['by_category']:
            processed['by_category'][category] = []
        processed['by_category'][category].append(finding)
    
    processed['total_count'] = len(processed['findings'])
    
    # Calculate overall risk level
    if processed['severity_counts']['critical'] > 0 or processed['severity_counts']['high'] > 3:
        processed['overall_risk'] = 'Critical'
    elif processed['severity_counts']['high'] > 0 or processed['severity_counts']['medium'] > 3:
        processed['overall_risk'] = 'High'
    elif processed['severity_counts']['medium'] > 0 or processed['severity_counts']['low'] > 3:
        processed['overall_risk'] = 'Medium'
    elif processed['severity_counts']['low'] > 0:
        processed['overall_risk'] = 'Low'
    else:
        processed['overall_risk'] = 'Informational'
    
    return processed

def generate_risk_assessment(processed_findings: dict) -> str:
    """Generate risk assessment section of the report.
    
    Args:
        processed_findings: Processed findings dictionary
        
    Returns:
        HTML string for risk assessment section
    """
    risk_levels = {
        'Critical': {
            'color': '#dc3545',
            'description': 'Immediate action required. Critical vulnerabilities were found that could lead to complete system compromise.'
        },
        'High': {
            'color': '#e67e22',
            'description': 'High-risk vulnerabilities were found that should be addressed as soon as possible.'
        },
        'Medium': {
            'color': '#f39c12',
            'description': 'Moderate risk vulnerabilities were found that should be addressed in a timely manner.'
        },
        'Low': {
            'color': '#17a2b8',
            'description': 'Low-risk vulnerabilities were found that should be addressed as resources allow.'
        },
        'Informational': {
            'color': '#6c757d',
            'description': 'No critical issues found. Review informational items for potential improvements.'
        }
    }
    
    risk_level = processed_findings.get('overall_risk', 'Informational')
    risk_info = risk_levels.get(risk_level, risk_levels['Informational'])
    
    # Generate risk meter HTML
    risk_meter = f"""
    <div class="risk-meter">
        <div class="risk-level" style="background: {risk_color};">
            <span>{risk_level}</span>
        </div>
        <div class="risk-description">
            <p>{risk_info['description']}</p>
        </div>
    </div>
    """.format(
        risk_level=risk_level,
        risk_color=risk_info['color'],
        risk_description=risk_info['description']
    )
    
    # Generate severity distribution chart data
    severity_data = {
        'critical': processed_findings['severity_counts']['critical'],
        'high': processed_findings['severity_counts']['high'],
        'medium': processed_findings['severity_counts']['medium'],
        'low': processed_findings['severity_counts']['low'],
        'info': processed_findings['severity_counts']['info']
    }
    
    # Generate category distribution
    category_chart = ""
    if processed_findings['by_category']:
        category_chart = """
        <div class="chart-container">
            <h4>Vulnerabilities by Category</h4>
            <canvas id="categoryChart"></canvas>
        </div>
        """
    
    # Generate risk assessment HTML
    risk_assessment = f"""
    <div class="section">
        <h2><i class="fas fa-shield-alt"></i> Risk Assessment</h2>
        <div class="risk-summary">
            <div class="row">
                <div class="col-md-6">
                    <div class="risk-overview">
                        <h3>Overall Risk Level</h3>
                        {risk_meter}
                        <div class="severity-distribution">
                            <h4>Vulnerability Distribution</h4>
                            <div class="severity-bars">
                                <div class="severity-bar critical" 
                                     style="width: {critical_pct}%;">
                                    <span>Critical: {critical_count}</span>
                                </div>
                                <div class="severity-bar high" 
                                     style="width: {high_pct}%;">
                                    <span>High: {high_count}</span>
                                </div>
                                <div class="severity-bar medium" 
                                     style="width: {medium_pct}%;">
                                    <span>Medium: {medium_count}</span>
                                </div>
                                <div class="severity-bar low" 
                                     style="width: {low_pct}%;">
                                    <span>Low: {low_count}</span>
                                </div>
                                <div class="severity-bar info" 
                                     style="width: {info_pct}%;">
                                    <span>Info: {info_count}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="chart-container">
                        <h4>Vulnerabilities by Severity</h4>
                        <canvas id="severityChart"></canvas>
                    </div>
                    {category_chart}
                </div>
            </div>
        </div>
    </div>
    """.format(
        risk_meter=risk_meter,
        critical_count=severity_data['critical'],
        high_count=severity_data['high'],
        medium_count=severity_data['medium'],
        low_count=severity_data['low'],
        info_count=severity_data['info'],
        critical_pct=severity_data['critical'] / max(1, processed_findings['total_count']) * 100,
        high_pct=severity_data['high'] / max(1, processed_findings['total_count']) * 100,
        medium_pct=severity_data['medium'] / max(1, processed_findings['total_count']) * 100,
        low_pct=severity_data['low'] / max(1, processed_findings['total_count']) * 100,
        info_pct=severity_data['info'] / max(1, processed_findings['total_count']) * 100,
        category_chart=category_chart
    )
    
    return risk_assessment

def generate_detailed_findings(processed_findings: dict) -> str:
    """Generate the detailed findings section of the report.
    
    Args:
        processed_findings: Processed findings dictionary
        
    Returns:
        HTML string for detailed findings section
    """
    findings_sections = []
    
    # Generate sections for each severity level
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        findings = processed_findings['by_severity'].get(severity, [])
        if not findings:
            continue
            
        severity_section = f"""
        <div class="findings-section {severity}">
            <h3><i class="fas fa-{get_severity_icon(severity)}"></i> {severity.title()} Severity Findings</h3>
            <div class="findings-list">
        """
        
        for finding in findings:
            # Generate finding card
            finding_card = f"""
            <div class="finding {severity}" id="finding-{finding_id}">
                <div class="finding-header">
                    <h4>
                        <span class="finding-title">{title}</span>
                        <span class="finding-id">{finding_id}</span>
                        <span class="severity-badge {severity}">{severity.title()}</span>
                    </h4>
                    <div class="finding-meta">
                        <span class="meta-item"><i class="fas fa-tag"></i> {category}</span>
                        <span class="meta-item"><i class="fas fa-calendar"></i> {date}</span>
                        <span class="meta-item"><i class="fas fa-server"></i> {target}</span>
                        <span class="meta-item"><i class="fas fa-bug"></i> CVE-{cve}</span>
                    </div>
                </div>
                
                <div class="finding-body">
                    <div class="finding-description">
                        <h5><i class="fas fa-align-left"></i> Description</h5>
                        <p>{description}</p>
                    </div>
                    
                    <div class="finding-impact">
                        <h5><i class="fas fa-bolt"></i> Impact</h5>
                        <p>{impact}</p>
                    </div>
                    
                    <div class="finding-evidence">
                        <h5><i class="fas fa-clipboard-check"></i> Evidence</h5>
                        <pre><code>{evidence}</code></pre>
                    </div>
                    
                    <div class="finding-recommendation">
                        <h5><i class="fas fa-lightbulb"></i> Recommendation</h5>
                        <div class="recommendation-content">
                            {recommendation}
                        </div>
                    </div>
                    
                    <div class="finding-references">
                        <h5><i class="fas fa-book"></i> References</h5>
                        <ul class="references-list">
                            {references}
                        </ul>
                    </div>
                    
                    <div class="finding-technical">
                        <h5><i class="fas fa-code"></i> Technical Details</h5>
                        <div class="technical-details">
                            <table class="technical-table">
                                <tr>
                                    <th>CVSS Score</th>
                                    <td>{cvss_score} ({cvss_vector})</td>
                                </tr>
                                <tr>
                                    <th>Attack Vector</th>
                                    <td>{attack_vector}</td>
                                </tr>
                                <tr>
                                    <th>Complexity</th>
                                    <td>{complexity}</td>
                                </tr>
                                <tr>
                                    <th>Privileges Required</th>
                                    <td>{privileges}</td>
                                </tr>
                                <tr>
                                    <th>User Interaction</th>
                                    <td>{user_interaction}</td>
                                </tr>
                                <tr>
                                    <th>Scope</th>
                                    <td>{scope}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            """.format(
                finding_id=finding.get('id', 'N/A'),
                title=html.escape(finding.get('title', 'Untitled Finding')),
                severity=severity,
                category=html.escape(finding.get('category', 'Other')),
                date=finding.get('date', 'N/A'),
                target=html.escape(finding.get('target', 'N/A')),
                cve=finding.get('cve', 'N/A'),
                description=html.escape(finding.get('description', 'No description available.')),
                impact=html.escape(finding.get('impact', 'No impact information available.')),
                evidence=html.escape(finding.get('evidence', 'No evidence captured.')),
                recommendation=format_recommendation(finding.get('recommendation', 'No specific recommendation available.')),
                references='\n'.join([f'<li><a href="{ref}" target="_blank">{ref}</a></li>' for ref in finding.get('references', [])]),
                cvss_score=finding.get('cvss_score', 'N/A'),
                cvss_vector=finding.get('cvss_vector', 'N/A'),
                attack_vector=finding.get('attack_vector', 'Network'),
                complexity=finding.get('complexity', 'Low'),
                privileges=finding.get('privileges_required', 'None'),
                user_interaction=finding.get('user_interaction', 'None'),
                scope=finding.get('scope', 'Unchanged')
            )
            
            severity_section += finding_card
        
        severity_section += """
            </div>
        </div>
        """
        findings_sections.append(severity_section)
    
    # Combine all findings sections
    findings_html = ""
    if findings_sections:
        findings_html = """
        <div class="section">
            <h2><i class="fas fa-search"></i> Detailed Findings</h2>
            <div class="findings-container">
                {findings_content}
            </div>
        </div>
        """.format(findings_content='\n'.join(findings_sections))
    
    return findings_html

def generate_remediation_roadmap(processed_findings: dict) -> str:
    """Generate remediation roadmap section of the report.
    
    Args:
        processed_findings: Processed findings dictionary
        
    Returns:
        HTML string for remediation roadmap section
    """
    # Group findings by category and severity
    categories = {}
    for finding in processed_findings['findings']:
        category = finding.get('category', 'Other')
        severity = finding.get('severity', 'info').lower()
        
        if category not in categories:
            categories[category] = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            }
        
        if severity in categories[category]:
            categories[category][severity].append(finding)
    
    # Generate remediation steps
    remediation_steps = []
    
    # Immediate actions (Critical/High)
    immediate_actions = []
    for category, severities in categories.items():
        critical_high = severities['critical'] + severities['high']
        if critical_high:
            immediate_actions.append({
                'category': category,
                'findings': critical_high,
                'priority': 'Immediate',
                'timeline': 'Within 24-48 hours',
                'effort': 'High',
                'owner': 'Security Team'
            })
    
    # Short-term actions (Medium)
    short_term_actions = []
    for category, severities in categories.items():
        if severities['medium']:
            short_term_actions.append({
                'category': category,
                'findings': severities['medium'],
                'priority': 'High',
                'timeline': 'Within 1-2 weeks',
                'effort': 'Medium',
                'owner': 'System Admins'
            })
    
    # Long-term actions (Low/Info)
    long_term_actions = []
    for category, severities in categories.items():
        low_info = severities['low'] + severities['info']
        if low_info:
            long_term_actions.append({
                'category': category,
                'findings': low_info,
                'priority': 'Medium',
                'timeline': 'Within 1-3 months',
                'effort': 'Low',
                'owner': 'IT Team'
            })
    
    # Generate HTML for each action category
    def generate_action_table(actions, title):
        if not actions:
            return ''
            
        rows = ''
        for action in actions:
            finding_count = len(action['findings'])
            finding_links = ', '.join(
                f'<a href="#finding-{f.get("id", "")}">{f.get("id", "N/A")}</a>'
                for f in action['findings'][:3]  # Show first 3 finding IDs
            )
            if finding_count > 3:
                finding_links += f' and {finding_count - 3} more'
                
            rows += f"""
            <tr>
                <td>{html.escape(action['category'])}</td>
                <td>{finding_links}</td>
                <td>{action['priority']}</td>
                <td>{action['timeline']}</td>
                <td>{action['effort']}</td>
                <td>{action['owner']}</td>
            </tr>
            """
        
        return f"""
        <div class="remediation-category">
            <h4>{title}</h4>
            <div class="table-responsive">
                <table class="remediation-table">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Affected Findings</th>
                            <th>Priority</th>
                            <th>Timeline</th>
                            <th>Effort</th>
                            <th>Owner</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    # Generate the complete remediation roadmap
    roadmap_html = """
    <div class="section">
        <h2><i class="fas fa-tasks"></i> Remediation Roadmap</h2>
        <div class="remediation-intro">
            <p>This section provides a prioritized plan for addressing the identified vulnerabilities. 
            The roadmap is organized by priority level and includes recommended timelines and responsible parties.</p>
        </div>
        
        {immediate_actions}
        {short_term_actions}
        {long_term_actions}
        
        <div class="remediation-notes">
            <h4>Implementation Notes</h4>
            <ul>
                <li><strong>Immediate Actions:</strong> Critical and high severity issues that should be addressed as soon as possible, typically within 24-48 hours.</li>
                <li><strong>Short-term Actions:</strong> Medium severity issues that should be addressed within 1-2 weeks.</li>
                <li><strong>Long-term Actions:</strong> Low and informational findings that should be addressed as part of regular maintenance cycles.</li>
            </ul>
            <p><strong>Note:</strong> This is a recommended timeline. Adjust based on your organization's risk tolerance and operational constraints.</p>
        </div>
    </div>
    """.format(
        immediate_actions=generate_action_table(immediate_actions, 'Immediate Actions (Critical/High Severity)'),
        short_term_actions=generate_action_table(short_term_actions, 'Short-term Actions (Medium Severity)'),
        long_term_actions=generate_action_table(long_term_actions, 'Long-term Actions (Low/Informational)')
    )
    
    return roadmap_html

def generate_compliance_mapping(processed_findings: dict) -> str:
    """Generate compliance mapping section of the report.
    
    Args:
        processed_findings: Processed findings dictionary
        
    Returns:
        HTML string for compliance mapping section
    """
    # Map findings to compliance frameworks
    compliance_frameworks = {
        'NIST CSF': {
            'ID.AM': 'Asset Management',
            'PR.AC': 'Identity Management and Access Control',
            'PR.IP': 'Information Protection Processes and Procedures',
            'PR.PT': 'Protective Technology',
            'DE.CM': 'Security Continuous Monitoring'
        },
        'CIS Controls': {
            'CIS-4': 'Controlled Use of Administrative Privileges',
            'CIS-5': 'Secure Configuration for Hardware and Software',
            'CIS-11': 'Secure Configuration for Network Devices',
            'CIS-12': 'Boundary Defense',
            'CIS-16': 'Account Monitoring and Control'
        },
        'ISO 27001': {
            'A.9': 'Access Control',
            'A.12': 'Operations Security',
            'A.13': 'Communications Security',
            'A.14': 'System Acquisition, Development and Maintenance',
            'A.16': 'Information Security Incident Management'
        },
        'GDPR': {
            'Art. 5': 'Principles relating to processing of personal data',
            'Art. 25': 'Data protection by design and by default',
            'Art. 32': 'Security of processing',
            'Art. 33': 'Notification of a personal data breach'
        },
        'HIPAA': {
            '164.308': 'Administrative Safeguards',
            '164.310': 'Physical Safeguards',
            '164.312': 'Technical Safeguards',
            '164.314': 'Organizational Requirements'
        }
    }
    
    # Generate compliance mapping table
    compliance_rows = ''
    for framework, controls in compliance_frameworks.items():
        for control_id, control_name in controls.items():
            # Find relevant findings for this control
            relevant_findings = []
            for finding in processed_findings['findings']:
                # Simple keyword matching - in a real implementation, you'd want a more sophisticated mapping
                if (control_name.lower() in finding.get('title', '').lower() or 
                    control_name.lower() in finding.get('description', '').lower()):
                    relevant_findings.append(finding)
            
            if not relevant_findings:
                continue
                
            # Generate finding links
            finding_links = ', '.join(
                f'<a href="#finding-{f.get("id", "")}">{f.get("id", "N/A")}</a>'
                for f in relevant_findings[:3]  # Show first 3 finding IDs
            )
            if len(relevant_findings) > 3:
                finding_links += f' and {len(relevant_findings) - 3} more'
            
            # Calculate compliance status
            status = 'Compliant'
            status_class = 'compliant'
            for f in relevant_findings:
                if f.get('severity') in ['critical', 'high']:
                    status = 'Non-Compliant'
                    status_class = 'non-compliant'
                    break
                elif f.get('severity') == 'medium':
                    status = 'Partially Compliant'
                    status_class = 'partially-compliant'
            
            compliance_rows += f"""
            <tr>
                <td>{framework}</td>
                <td><strong>{control_id}</strong> - {control_name}</td>
                <td><span class="compliance-status {status_class}">{status}</span></td>
                <td>{finding_links}</td>
            </tr>
            """
    
    if not compliance_rows:
        return ''
    
    # Generate the complete compliance mapping section
    compliance_html = """
    <div class="section">
        <h2><i class="fas fa-clipboard-check"></i> Compliance Mapping</h2>
        <div class="compliance-intro">
            <p>This section maps the identified vulnerabilities to various compliance frameworks and regulations 
            to help demonstrate compliance requirements and identify gaps.</p>
        </div>
        
        <div class="table-responsive">
            <table class="compliance-table">
                <thead>
                    <tr>
                        <th>Framework</th>
                        <th>Control</th>
                        <th>Status</th>
                        <th>Related Findings</th>
                    </tr>
                </thead>
                <tbody>
                    {compliance_rows}
                </tbody>
            </table>
        </div>
        
        <div class="compliance-legend">
            <h4>Status Legend</h4>
            <ul class="legend-list">
                <li><span class="status-dot compliant"></span> Compliant - No critical/high severity issues</li>
                <li><span class="status-dot partially-compliant"></span> Partially Compliant - Medium severity issues present</li>
                <li><span class="status-dot non-compliant"></span> Non-Compliant - Critical/high severity issues present</li>
            </ul>
        </div>
    </div>
    """.format(compliance_rows=compliance_rows)
    
    return compliance_html

def generate_appendix(scan_results: dict, timestamp: str) -> str:
    """Generate the appendix section of the report.
    
    Args:
        scan_results: Original scan results
        timestamp: Report generation timestamp
        
    Returns:
        HTML string for appendix section
    """
    # Generate scan metadata
    scan_metadata = ''
    if 'scan_metadata' in scan_results:
        for key, value in scan_results['scan_metadata'].items():
            scan_metadata += f"""
            <tr>
                <td>{html.escape(str(key))}</td>
                <td>{html.escape(str(value))}</td>
            </tr>
            """
    
    # Generate glossary
    glossary_items = [
        ('RDP', 'Remote Desktop Protocol - A proprietary protocol developed by Microsoft that provides a user with a graphical interface to connect to another computer over a network connection.'),
        ('NLA', 'Network Level Authentication - A security feature that requires authentication before a full RDP session is established.'),
        ('TLS', 'Transport Layer Security - A cryptographic protocol designed to provide communications security over a computer network.'),
        ('CVE', 'Common Vulnerabilities and Exposures - A dictionary of publicly known information security vulnerabilities and exposures.'),
        ('CVSS', 'Common Vulnerability Scoring System - A framework for rating the severity of security vulnerabilities in software.'),
        ('MFA', 'Multi-Factor Authentication - A security system that requires more than one method of authentication from independent categories of credentials.')
    ]
    
    glossary_html = ''
    for term, definition in glossary_items:
        glossary_html += f"""
        <dt>{term}</dt>
        <dd>{definition}</dd>
        """
    
    # Generate references
    references = [
        ('Microsoft RDP Security Recommendations', 'https://docs.microsoft.com/en-us/windows/security/remote-remote-desktop-services/remote-desktop-security-recommendations'),
        ('CIS Microsoft Windows Server Benchmarks', 'https://www.cisecurity.org/benchmark/microsoft_windows_server/'),
        ('National Vulnerability Database (NVD)', 'https://nvd.nist.gov/'),
        ('MITRE ATT&CK Framework', 'https://attack.mitre.org/'),
        ('NIST SP 800-53 Security Controls', 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final'),
        ('OWASP Top 10', 'https://owasp.org/www-project-top-ten/')
    ]
    
    references_html = ''
    for title, url in references:
        references_html += f'<li><a href="{url}" target="_blank">{html.escape(title)}</a></li>\n'
    
    # Generate the complete appendix
    appendix_html = """
    <div class="section">
        <h2><i class="fas fa-book"></i> Appendix</h2>
        
        <div class="appendix-section">
            <h3>Scan Details</h3>
            <div class="table-responsive">
                <table class="appendix-table">
                    <tr>
                        <th>Report Generated</th>
                        <td>{timestamp}</td>
                    </tr>
                    <tr>
                        <th>Scanner Version</th>
                        <td>{scanner_version}</td>
                    </tr>
                    <tr>
                        <th>Scan Duration</th>
                        <td>{scan_duration}</td>
                    </tr>
                    {scan_metadata}
                </table>
            </div>
        </div>
        
        <div class="appendix-section">
            <h3>Glossary</h3>
            <dl class="glossary">
                {glossary_html}
            </dl>
        </div>
        
        <div class="appendix-section">
            <h3>References</h3>
            <ul class="references">
                {references_html}
            </ul>
        </div>
        
        <div class="appendix-section">
            <h3>Disclaimer</h3>
            <div class="disclaimer">
                <p>This report is provided for informational purposes only. The information contained in this report 
                represents the findings at the time of the assessment and may not reflect the current security 
                posture of the assessed systems. The recommendations provided should be reviewed and implemented 
                based on your organization's specific security requirements and risk tolerance.</p>
                
                <p>This report is confidential and intended solely for the use of the individual or entity to whom 
                it is addressed. Unauthorized use, disclosure, or distribution of this report is strictly prohibited.</p>
                
                <p>© {current_year} CyberArk Security Team. All rights reserved.</p>
            </div>
        </div>
    </div>
    """.format(
        timestamp=timestamp,
        scanner_version=scan_results.get('scanner_version', '1.0.0'),
        scan_duration=scan_results.get('scan_duration', 'N/A'),
        scan_metadata=scan_metadata,
        glossary_html=glossary_html,
        references_html=references_html,
        current_year=datetime.now().year
    )
    
    return appendix_html

def generate_executive_summary(processed_findings: dict, scan_results: dict) -> str:
    """Generate executive summary section of the report.
    
    Args:
        processed_findings: Processed findings dictionary
        scan_results: Original scan results
        
    Returns:
        HTML string for executive summary section
    """
    # Generate key metrics
    metrics = [
        {
            'title': 'Total Vulnerabilities',
            'value': processed_findings['total_count'],
            'icon': 'bug',
            'trend': 'up' if processed_findings['total_count'] > 0 else 'none'
        },
        {
            'title': 'Critical Issues',
            'value': processed_findings['severity_counts']['critical'],
            'icon': 'exclamation-triangle',
            'trend': 'up' if processed_findings['severity_counts']['critical'] > 0 else 'none',
            'class': 'critical'
        },
        {
            'title': 'High Risk Issues',
            'value': processed_findings['severity_counts']['high'],
            'icon': 'exclamation-circle',
            'trend': 'up' if processed_findings['severity_counts']['high'] > 0 else 'none',
            'class': 'high'
        },
        {
            'title': 'Affected Systems',
            'value': len(set(f.get('target', '') for f in processed_findings['findings'])),
            'icon': 'server',
            'trend': 'none'
        }
    ]
    
    # Generate metrics HTML
    metrics_html = ''
    for metric in metrics:
        trend_icon = ''
        if metric.get('trend') == 'up':
            trend_icon = '<i class="fas fa-arrow-up trend-up"></i>'
        elif metric.get('trend') == 'down':
            trend_icon = '<i class="fas fa-arrow-down trend-down"></i>'
            
        metrics_html += f"""
        <div class="metric-card {metric.get('class', '')}">
            <div class="metric-icon">
                <i class="fas fa-{metric['icon']}"></i>
            </div>
            <div class="metric-content">
                <div class="metric-value">
                    {metric['value']} {trend_icon}
                </div>
                <div class="metric-title">{metric['title']}</div>
            </div>
        </div>
        """
    
    # Generate top recommendations
    top_recommendations = []
    for severity in ['critical', 'high', 'medium']:
        for finding in processed_findings['by_severity'].get(severity, []):
            if 'recommendation' in finding and finding['recommendation']:
                rec_text = finding['recommendation'].split('\n')[0]  # Get first line of recommendation
                if rec_text not in [r['text'] for r in top_recommendations]:
                    top_recommendations.append({
                        'severity': severity,
                        'text': rec_text,
                        'title': finding.get('title', 'Untitled')
                    })
                    if len(top_recommendations) >= 5:  # Limit to top 5
                        break
        if len(top_recommendations) >= 5:
            break
    
    recommendations_html = ''
    for i, rec in enumerate(top_recommendations, 1):
        recommendations_html += f"""
        <div class="recommendation-item">
            <span class="rec-number">{i}.</span>
            <div class="rec-content">
                <div class="rec-title">{rec['title']} <span class="severity-badge {rec['severity']}">{rec['severity'].title()}</span></div>
                <div class="rec-text">{rec['text']}</div>
            </div>
        </div>
        """
    
    # Generate executive summary HTML
    executive_summary = f"""
    <div class="section">
        <h2><i class="fas fa-chart-line"></i> Executive Summary</h2>
        <div class="executive-overview">
            <p>This security assessment report provides a comprehensive analysis of the RDP security posture 
            for the target environment. The assessment was conducted on {scan_date} and identified 
            {total_findings} security findings, including {critical_count} critical and {high_count} high severity issues.</p>
            
            <div class="metrics-container">
                {metrics_html}
            </div>
            
            <h3>Key Findings</h3>
            <ul class="key-findings">
                {key_findings}
            </ul>
            
            <h3>Top Recommendations</h3>
            <div class="recommendations-list">
                {recommendations_html}
            </div>
        </div>
    </div>
    """.format(
        scan_date=scan_results.get('scan_date', 'N/A'),
        total_findings=processed_findings['total_count'],
        critical_count=processed_findings['severity_counts']['critical'],
        high_count=processed_findings['severity_counts']['high'],
        metrics_html=metrics_html,
        key_findings='\n'.join([
            f'<li>{finding}' for finding in [
                f"{processed_findings['severity_counts']['critical']} critical vulnerabilities requiring immediate attention" if processed_findings['severity_counts']['critical'] > 0 else None,
                f"{processed_findings['severity_counts']['high']} high-risk issues that should be prioritized" if processed_findings['severity_counts']['high'] > 0 else None,
                f"{len(processed_findings['by_category'])} different vulnerability categories identified" if processed_findings['by_category'] else None,
                "Multiple systems affected by similar vulnerabilities" if len(set(f.get('target', '') for f in processed_findings['findings'])) > 1 else None
            ] if finding
        ][:3]),  # Limit to top 3 key findings
        recommendations_html=recommendations_html or '<p>No specific recommendations available.</p>'
    )
    
    return executive_summary

def generate_html_report(json_file, output_file):
    """Generate HTML report from JSON analysis results
    
    Args:
        json_file: Path to the JSON results file
        output_file: Path where the HTML report should be saved
        
    Returns:
        bool: True if report was generated successfully, False otherwise
    """
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return False
    
    # Process findings for reporting
    processed_findings = process_findings(data.get('vulnerabilities', []))
    
    # Generate report sections
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate report sections
    executive_summary = generate_executive_summary(processed_findings, data)
    risk_assessment = generate_risk_assessment(processed_findings)
    detailed_findings = generate_detailed_findings(processed_findings)
    remediation_roadmap = generate_remediation_roadmap(processed_findings)
    compliance_mapping = generate_compliance_mapping(processed_findings)
    appendix = generate_appendix(data, timestamp)
    
    # Generate navigation menu
    nav_menu = """
    <nav id="report-nav" class="sticky-nav">
        <div class="nav-container">
            <a href="#executive-summary" class="nav-link" data-section="executive-summary">
                <i class="fas fa-chart-line"></i> Summary
            </a>
            <a href="#risk-assessment" class="nav-link" data-section="risk-assessment">
                <i class="fas fa-shield-alt"></i> Risk Assessment
            </a>
            <a href="#findings" class="nav-link" data-section="findings">
                <i class="fas fa-search"></i> Findings
            </a>
            <a href="#remediation" class="nav-link" data-section="remediation">
                <i class="fas fa-tasks"></i> Remediation
            </a>
            <a href="#compliance" class="nav-link" data-section="compliance">
                <i class="fas fa-clipboard-check"></i> Compliance
            </a>
            <a href="#appendix" class="nav-link" data-section="appendix">
                <i class="fas fa-book"></i> Appendix
            </a>
            <button id="print-report" class="print-btn" title="Print Report">
                <i class="fas fa-print"></i> Print
            </button>
            <button id="export-pdf" class="export-btn" title="Export as PDF">
                <i class="fas fa-file-pdf"></i> PDF
            </button>
        </div>
    </nav>"""
    
    # Generate severity distribution chart data
    severity_distribution = {
        'critical': processed_findings['severity_counts'].get('critical', 0),
        'high': processed_findings['severity_counts'].get('high', 0),
        'medium': processed_findings['severity_counts'].get('medium', 0),
        'low': processed_findings['severity_counts'].get('low', 0),
        'info': processed_findings['severity_counts'].get('info', 0)
    }
    
    # Generate category distribution data
    categories = list(processed_findings['by_category'].keys())[:10]  # Top 10 categories
    category_counts = [len(processed_findings['by_category'][cat]) for cat in categories]
    
    # Generate trend data (example: last 7 days)
    trend_dates = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(6, -1, -1)]
    trend_data = [random.randint(0, 10) for _ in range(7)]  # Example trend data
    
    # Count vulnerabilities by severity for the summary cards
    vuln_counts = {
        'Critical': processed_findings['severity_counts'].get('critical', 0),
        'High': processed_findings['severity_counts'].get('high', 0),
        'Medium': processed_findings['severity_counts'].get('medium', 0),
        'Low': processed_findings['severity_counts'].get('low', 0),
        'Info': processed_findings['severity_counts'].get('info', 0)
    }
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RDP Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; }}
        .card.danger {{ border-left-color: #dc3545; }}
        .card.warning {{ border-left-color: #ffc107; }}
        .card.success {{ border-left-color: #28a745; }}
        .section {{ margin-bottom: 30px; }}
        .vulnerability {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin-bottom: 10px; border-radius: 4px; }}
        .vulnerability.high {{ background: #f8d7da; border-color: #f5c6cb; }}
        .vulnerability.medium {{ background: #fff3cd; border-color: #ffeaa7; }}
        .vulnerability.low {{ background: #d1ecf1; border-color: #bee5eb; }}
        .recommendation {{ background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 5px; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .status-pass {{ color: #28a745; font-weight: bold; }}
        .status-fail {{ color: #dc3545; font-weight: bold; }}
        .status-warn {{ color: #ffc107; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RDP Security Analysis Report</h1>
            <p><strong>Analysis Date:</strong> {data.get('metadata', {}).get('analysis_time', 'N/A')}</p>
            <p><strong>Target:</strong> {data.get('metadata', {}).get('pcap_file', 'N/A')}</p>
        </div>
        
        <div class="summary">
            <div class="card danger">
                <h3>High Risk</h3>
                <p style="font-size: 2em; margin: 0;">{vuln_counts['High']}</p>
            </div>
            <div class="card warning">
                <h3>Medium Risk</h3>
                <p style="font-size: 2em; margin: 0;">{vuln_counts['Medium']}</p>
            </div>
            <div class="card success">
                <h3>Low Risk</h3>
                <p style="font-size: 2em; margin: 0;">{vuln_counts['Low']}</p>
            </div>
            <div class="card">
                <h3>Total Packets</h3>
                <p style="font-size: 2em; margin: 0;">{data.get('statistics', {}).get('total_packets', 0)}</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Security Vulnerabilities</h2>
    """
    
    # Add detailed vulnerability information
    for vuln in data.get('vulnerabilities', []):
        severity = vuln.get('severity', 'Low')
        severity_class = severity.lower()
        vuln_type = vuln.get('type', 'Unknown Vulnerability')
        
        # Get detailed vulnerability information
        vuln_details = get_vulnerability_details(vuln_type, severity)
        
        # Set severity color based on level
        severity_color = {
            'high': '#dc3545',
            'medium': '#ffc107',
            'low': '#28a745'
        }.get(severity_class, '#6c757d')
        
        # Build references section if they exist
        references_html = ''
        if vuln_details.get('references'):
            references_html = '<div style="margin-top: 15px;"><strong>References:</strong><ul style="margin: 5px 0 0 0; padding-left: 20px;">'
            references_html += ''.join(f'<li style="margin-bottom: 3px;">{ref}</li>' for ref in vuln_details.get('references', []))
            references_html += '</ul></div>'
        
        # Build test info section if it exists
        test_info_html = ''
        if vuln.get("test_id") or vuln.get("timestamp"):
            test_info_html = f'''
                <div style="margin-top: 10px; font-size: 0.9em; color: #6c757d;">
                    <strong>Test ID:</strong> {vuln.get("test_id", "N/A")} | 
                    <strong>Timestamp:</strong> {vuln.get("timestamp", "N/A")}
                </div>'''
        
        # Get technical details with safe defaults
        tech_details = vuln_details.get('technical_details', {})
        attack_vectors = ', '.join(tech_details.get('attack_vectors', ['N/A']))
        required_privs = tech_details.get('required_privileges', 'N/A')
        exploit_comp = tech_details.get('exploit_complexity', 'N/A')
        detect_diff = tech_details.get('detection_difficulty', 'N/A')
        
        # Prepare the vulnerability description with proper escaping
        description = vuln.get('description') or vuln_details.get('description', 'No description available')
        description = description.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
        
        # Prepare the impact text with proper escaping
        impact = vuln_details.get('impact', 'Impact not specified.')
        impact = impact.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
        
        # Prepare the mitigation text with proper escaping
        mitigation = vuln_details.get('mitigation', 'No specific mitigation provided.')
        mitigation = mitigation.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
        
        # Build the vulnerability card using string concatenation to avoid f-string issues
        vuln_card = (
            f'<div class="vulnerability {severity_class}" style="margin-bottom: 25px; padding: 20px; border-radius: 8px; border-left: 5px solid {severity_color};">' +
            f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">' +
            f'<h3 style="margin: 0; color: {severity_color};">{vuln_type}</h3>' +
            f'<span style="background: {severity_color}; color: white; padding: 3px 10px; border-radius: 20px; font-weight: bold; font-size: 0.9em;">' +
            f'{severity.upper()}' +
            '</span></div>' +
            f'<div style="background: rgba(0,0,0,0.03); padding: 15px; border-radius: 6px; margin-bottom: 15px;">' +
            '<h4 style="margin-top: 0; margin-bottom: 10px; color: #2c3e50;">Description</h4>' +
            f'<p style="margin: 0;">{description}</p></div>' +
            '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">' +
            '<div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">' +
            '<h4 style="margin-top: 0; margin-bottom: 10px; color: #2c3e50;">Impact</h4>' +
            f'<p style="margin: 0; color: #dc3545; font-weight: 500;">{impact}</p></div>' +
            '<div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">' +
            '<h4 style="margin-top: 0; margin-bottom: 10px; color: #2c3e50;">CVSS Score</h4>' +
            f'<p style="margin: 0; font-weight: 500;">{vuln_details.get("cvss_score", "N/A")}</p></div></div>' +
            '<div style="background: #e8f4fd; padding: 15px; border-radius: 6px; margin-bottom: 15px;">' +
            '<h4 style="margin-top: 0; margin-bottom: 10px; color: #0d6efd;">Mitigation Steps</h4>' +
            f'<div style="white-space: pre-line;">{mitigation}</div></div>' +
            '<div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">' +
            '<h4 style="margin-top: 0; margin-bottom: 10px; color: #2c3e50;">Technical Details</h4>' +
            '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.9em;">' +
            f'<div><strong>Attack Vectors:</strong> {attack_vectors}</div>' +
            f'<div><strong>Required Privileges:</strong> {required_privs}</div>' +
            f'<div><strong>Exploit Complexity:</strong> {exploit_comp}</div>' +
            f'<div><strong>Detection Difficulty:</strong> {detect_diff}</div>' +
            '</div></div>' +
            f'{references_html}' +
            f'{test_info_html}' +
            '</div>'
        )
        
        html_content += vuln_card
    
    # Close the vulnerabilities section
    html_content += """
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <p>This security assessment identified """ + str(len(data.get('vulnerabilities', []))) + """ potential security issues 
                in the RDP implementation. The findings are categorized by severity below:</p>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; margin-top: 15px;">
                    <div style="border-left: 4px solid #dc3545; padding-left: 15px;">
                        <h4 style="margin: 0 0 5px 0; color: #dc3545;">High Severity</h4>
                        <p style="margin: 0;">""" + str(vuln_counts.get('High', 0)) + """ critical issues requiring immediate attention</p>
                    </div>
                    <div style="border-left: 4px solid #ffc107; padding-left: 15px;">
                        <h4 style="margin: 0 0 5px 0; color: #ffc107;">Medium Severity</h4>
                        <p style="margin: 0;">""" + str(vuln_counts.get('Medium', 0)) + """ issues that should be addressed</p>
                    </div>
                    <div style="border-left: 4px solid #28a745; padding-left: 15px;">
                        <h4 style="margin: 0 0 5px 0; color: #28a745;">Low Severity</h4>
                        <p style="margin: 0;">""" + str(vuln_counts.get('Low', 0)) + """ issues to consider for improvement</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Key Recommendations</h2>
            <div style="background: #e7f5ff; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <ol style="margin: 0; padding-left: 20px;">
                    <li style="margin-bottom: 10px;">
                        <strong>Critical Priority:</strong> Address all High severity findings immediately, 
                        particularly those related to authentication and data exposure.
                    </li>
                    <li style="margin-bottom: 10px;">
                        <strong>Authentication Security:</strong> Implement MFA for all remote access and ensure 
                        proper account lockout policies are in place.
                    </li>
                    <li style="margin-bottom: 10px;">
                        <strong>Network Security:</strong> Restrict RDP access through a VPN and implement network 
                        segmentation to limit lateral movement.
                    </li>
                    <li style="margin-bottom: 10px;">
                        <strong>Monitoring:</strong> Enable comprehensive logging and monitoring for all RDP access 
                        and authentication attempts.
                    </li>
                    <li>
                        <strong>Patch Management:</strong> Ensure all systems are up-to-date with the latest security 
                        patches and updates.
                    </li>
                </ol>
            </div>
        </div>"""
    
    # Add statistics table
    html_content += f"""
        </div>
        
        <div class="section">
            <h2>Analysis Statistics</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Packets</td><td>{data.get('statistics', {}).get('total_packets', 0)}</td></tr>
                <tr><td>RDP Packets</td><td>{data.get('statistics', {}).get('rdp_packets', 0)}</td></tr>
                <tr><td>SSL Packets</td><td>{data.get('statistics', {}).get('ssl_packets', 0)}</td></tr>
                <tr><td>NTLM Packets</td><td>{data.get('statistics', {}).get('ntlm_packets', 0)}</td></tr>
                <tr><td>Vulnerabilities Found</td><td>{len(data.get('vulnerabilities', []))}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Test Results Summary</h2>
            <p>This report covers comprehensive RDP security testing including:</p>
            <ul>
                <li>Authentication Flow Testing</li>
                <li>Privilege Escalation Analysis</li>
                <li>Session Security Assessment</li>
                <li>Attack Pattern Detection</li>
            </ul>
        </div>
        
        <footer style="margin-top: 40px; text-align: center; color: #666;">
            <p>Generated by RDP Security Testing Suite - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
    """
    
    try:
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"HTML report generated: {output_file}")
        return True
    except Exception as e:
        print(f"Error writing HTML file: {e}")
        return False

def generate_summary_html(summary_data: dict, output_file: str) -> bool:
    """Generate an HTML summary report from multiple scan results.
    
    Args:
        summary_data: Dictionary containing summary data from multiple scans
        output_file: Path where the HTML report should be saved
        
    Returns:
        bool: True if report was generated successfully, False otherwise
    """
    # Sort targets by number of vulnerabilities (critical first)
    sorted_targets = sorted(summary_data['targets'], 
                          key=lambda x: (x['critical'], x['high'], x['medium'], x['low']), 
                          reverse=True)
    
    # Generate HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RDP Security Scan Summary Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary-card {{ 
            background: #fff; 
            border-radius: 5px; 
            box-shadow: 0 2px 5px rgba(0,0,0,0.1); 
            padding: 20px; 
            margin-bottom: 20px;
        }}
        .metrics {{ display: flex; flex-wrap: wrap; gap: 15px; margin: 15px 0; }}
        .metric {{ 
            flex: 1; 
            min-width: 120px; 
            text-align: center; 
            padding: 15px; 
            border-radius: 5px; 
            color: white;
        }}
        .critical {{ background-color: #dc3545; }}
        .high {{ background-color: #fd7e14; }}
        .medium {{ background-color: #ffc107; color: #000; }}
        .low {{ background-color: #28a745; }}
        .target-row {{ 
            display: flex; 
            justify-content: space-between; 
            padding: 10px; 
            border-bottom: 1px solid #eee;
            align-items: center;
        }}
        .target-row:hover {{ background-color: #f8f9fa; }}
        .vuln-count {{ 
            display: inline-block; 
            width: 25px; 
            height: 25px; 
            border-radius: 50%; 
            text-align: center; 
            line-height: 25px; 
            color: white; 
            font-weight: bold;
            margin-left: 5px;
        }}
        .timestamp {{ color: #6c757d; font-size: 0.9em; }}
        a {{ color: #007bff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>RDP Security Scan Summary Report</h1>
        <p class="timestamp">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary-card">
        <h2>Executive Summary</h2>
        <p>This report summarizes the results of RDP security scans across {summary_data['total_scans']} target(s).</p>
        
        <div class="metrics">
            <div class="metric critical">
                <h3>{summary_data['summary']['critical']}</h3>
                <p>Critical</p>
            </div>
            <div class="metric high">
                <h3>{summary_data['summary']['high']}</h3>
                <p>High</p>
            </div>
            <div class="metric medium">
                <h3>{summary_data['summary']['medium']}</h3>
                <p>Medium</p>
            </div>
            <div class="metric low">
                <h3>{summary_data['summary']['low']}</h3>
                <p>Low</p>
            </div>
        </div>
        
        <div class="metrics">
            <div class="metric" style="background-color: #6f42c1;">
                <h3>{summary_data['summary']['tests_run']}</h3>
                <p>Tests Run</p>
            </div>
            <div class="metric" style="background-color: #20c997;">
                <h3>{summary_data['summary']['tests_passed']}</h3>
                <p>Tests Passed</p>
            </div>
            <div class="metric" style="background-color: #6c757d;">
                <h3>{summary_data['summary']['tests_failed']}</h3>
                <p>Tests Failed</p>
            </div>
        </div>
    </div>
    
    <div class="summary-card">
        <h2>Scanned Targets</h2>
        <p>Click on a target to view its detailed report.</p>
        
        <div style="margin-top: 20px;">
            {''.join([
                f'''
                <div class="target-row">
                    <div>
                        <h3 style="margin: 0;">
                            <a href="{target['html_report']}">{target['target']}:{target['port']}</a>
                            <span class="vuln-count" style="background-color: #dc3545;">{target['critical']}</span>
                            <span class="vuln-count" style="background-color: #fd7e14;">{target['high']}</span>
                            <span class="vuln-count" style="background-color: #ffc107; color: #000;">{target['medium']}</span>
                            <span class="vuln-count" style="background-color: #28a745;">{target['low']}</span>
                        </h3>
                        <p class="timestamp">
                            Scanned on {datetime.fromisoformat(target['end_time']).strftime('%Y-%m-%d %H:%M:%S') if target.get('end_time') else 'N/A'}
                        </p>
                    </div>
                    <div>
                        <a href="{target['html_report']}" style="background-color: #007bff; color: white; padding: 5px 10px; border-radius: 3px; text-decoration: none;">View Report</a>
                    </div>
                </div>
                ''' for target in sorted_targets
            ])}
        </div>
    </div>
    
    <div class="summary-card">
        <h2>Recommendations</h2>
        <p>Based on the scan results, the following actions are recommended:</p>
        <ul>
            <li>Address all <span class="severity-critical">Critical</span> and <span class="severity-high">High</span> severity vulnerabilities first</li>
            <li>Review and remediate <span class="severity-medium">Medium</span> severity issues</li>
            <li>Consider addressing <span class="severity-low">Low</span> severity findings based on risk assessment</li>
            <li>Implement regular security scanning as part of your security program</li>
            <li>Ensure all systems are patched and up-to-date</li>
        </ul>
    </div>
    
    <footer style="margin-top: 40px; text-align: center; color: #6c757d; font-size: 0.9em;">
        <p>Report generated by RDP Security Testing Suite</p>
    </footer>
</body>
</html>
    """
    
    try:
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"Summary HTML report generated: {output_file}")
        return True
    except Exception as e:
        print(f"Error writing summary HTML file: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Generate HTML reports from RDP analysis')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Parser for single report generation
    single_parser = subparsers.add_parser('single', help='Generate a single HTML report')
    single_parser.add_argument('json_file', help='Input JSON analysis file')
    single_parser.add_argument('-o', '--output', help='Output HTML file', default='rdp_security_report.html')
    
    # Parser for summary report generation
    summary_parser = subparsers.add_parser('summary', help='Generate a summary HTML report from multiple scans')
    summary_parser.add_argument('summary_file', help='Input JSON summary file')
    summary_parser.add_argument('-o', '--output', help='Output HTML file', default='rdp_scan_summary.html')
    
    args = parser.parse_args()
    
    if args.command == 'single':
        if generate_html_report(args.json_file, args.output):
            print("Single report generation completed successfully")
        else:
            print("Single report generation failed")
            sys.exit(1)
    elif args.command == 'summary':
        try:
            with open(args.summary_file, 'r') as f:
                summary_data = json.load(f)
            if generate_summary_html(summary_data, args.output):
                print("Summary report generation completed successfully")
            else:
                print("Summary report generation failed")
                sys.exit(1)
        except Exception as e:
            print(f"Error loading summary file: {e}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
