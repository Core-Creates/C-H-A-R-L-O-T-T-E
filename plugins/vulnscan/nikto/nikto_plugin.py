#!/usr/bin/env python3
"""
CHARLOTTE Nikto Plugin

A comprehensive web vulnerability scanner plugin that integrates Nikto
with the CHARLOTTE security framework. Provides both interactive and
headless scanning capabilities with user-friendly interfaces.

Features:
- Interactive CLI for scan configuration
- Multiple scan types and tuning options
- Safe default targets for testing
- Comprehensive output parsing and reporting
- Integration with CHARLOTTE's triage system

Author: CHARLOTTE Security Framework
"""

import os
import sys
import json
import subprocess
import re
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

# Dynamically locate CHARLOTTE root and add to Python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Import CHARLOTTE utilities
try:
    from utils.paths import display_path
except ImportError:
    def display_path(path: str, base: str | None = None) -> str:
        return str(path).replace("\\", "/")

try:
    from utils.logger import log_plugin_event
except ImportError:
    def log_plugin_event(session_id: str, event: str, data: Dict = None):
        print(f"[LOG] {event}: {data}")

# Optional: rich table formatting
try:
    from tabulate import tabulate
except ImportError:
    tabulate = None

# ──────────────────────────────────────────────────────────────────────────────
# Configuration and Constants
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_TARGET = "https://public-firing-range.appspot.com"
DEFAULT_OUTPUT_DIR = "data/findings"
DEFAULT_TIMEOUT = 60  # 1 minute for testing

# Nikto scan types and their descriptions
SCAN_TYPES = {
    "1": {
        "name": "Basic Scan",
        "args": "-Tuning 1,2,3,4,5,6,7,8,9",
        "description": "Standard vulnerability checks (recommended for most scans)"
    },
    "2": {
        "name": "Comprehensive Scan", 
        "args": "-Tuning 0",
        "description": "All available checks (slower but thorough)"
    },
    "3": {
        "name": "Quick Scan",
        "args": "-Tuning 1,2,3",
        "description": "Fast scan with basic checks only (1-2 minutes)"
    },
    "4": {
        "name": "Test Scan",
        "args": "-Tuning 1",
        "description": "Very quick test scan (30-60 seconds)"
    },
    "5": {
        "name": "Custom Tuning",
        "args": "",
        "description": "Specify custom tuning options"
    }
}

# Nikto tuning options
TUNING_OPTIONS = {
    "0": "All Tests",
    "1": "Interesting File / Seen in logs",
    "2": "Misconfiguration / Default Files", 
    "3": "Information Disclosure",
    "4": "Injection (XSS/Script/HTML)",
    "5": "Remote File Retrieval - Inside Web Root",
    "6": "Denial of Service",
    "7": "Remote File Retrieval - Server Wide",
    "8": "Command Execution / Remote Shell",
    "9": "SQL Injection",
    "a": "Authentication Bypass",
    "b": "Software Identification",
    "c": "Remote Source Inclusion",
    "d": "Denial of Service (DoS)",
    "e": "Remote File Retrieval - Outside Web Root",
    "f": "Fingerprinting",
    "g": "Fuzzing",
    "h": "Backdoors",
    "i": "Information Disclosure",
    "j": "Remote File Retrieval - Inside Web Root",
    "k": "Remote File Retrieval - Server Wide",
    "l": "Remote File Retrieval - Outside Web Root",
    "m": "Miscellaneous",
    "n": "CGI (Common Gateway Interface)",
    "o": "OS (Operating System)",
    "p": "Proxies",
    "q": "Remote File Retrieval - Inside Web Root",
    "r": "Remote File Retrieval - Server Wide",
    "s": "Remote File Retrieval - Outside Web Root",
    "t": "Remote File Retrieval - Inside Web Root",
    "u": "Remote File Retrieval - Server Wide",
    "v": "Remote File Retrieval - Outside Web Root",
    "w": "Remote File Retrieval - Inside Web Root",
    "x": "Remote File Retrieval - Server Wide",
    "y": "Remote File Retrieval - Outside Web Root",
    "z": "Remote File Retrieval - Inside Web Root"
}

    # Output formats
OUTPUT_FORMATS = {
    "1": {"name": "TXT", "ext": "txt", "args": "", "reliable": True},
    "2": {"name": "XML", "ext": "xml", "args": "-Format xml", "reliable": True},
    "3": {"name": "HTML", "ext": "html", "args": "-Format htm", "reliable": True},
    "4": {"name": "CSV", "ext": "csv", "args": "-Format csv", "reliable": True},
    "5": {"name": "JSON", "ext": "json", "args": "-Format json", "reliable": False, "note": "Requires Perl JSON module"}
}

# ──────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ──────────────────────────────────────────────────────────────────────────────

def check_nikto_installed() -> Tuple[bool, str]:
    """Check if Nikto is installed and accessible."""
    try:
        result = subprocess.run(['nikto', '-Version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_info = result.stdout.strip()
            return True, version_info
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        pass
    
    return False, "Nikto not found"

def validate_url(url: str) -> bool:
    """Validate that the URL is properly formatted."""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return bool(url_pattern.match(url))

def display_scan_types():
    """Display available scan types."""
    print("\n[CHARLOTTE] Available Nikto Scan Types:\n")
    for key, scan in SCAN_TYPES.items():
        print(f"  {key}. {scan['name']} – {scan['description']}")

def display_tuning_options():
    """Display available tuning options."""
    print("\n[CHARLOTTE] Available Tuning Options:\n")
    for key, desc in TUNING_OPTIONS.items():
        print(f"  {key}: {desc}")

def display_output_formats():
    """Display available output formats."""
    print("\n[CHARLOTTE] Available Output Formats:\n")
    for key, fmt in OUTPUT_FORMATS.items():
        reliability_note = ""
        if not fmt.get('reliable', True):
            reliability_note = f" (⚠️  {fmt.get('note', 'May have issues')})"
        print(f"  {key}. {fmt['name']}{reliability_note}")

def get_user_choice(prompt: str, choices: Dict[str, Any], default: str = None) -> str:
    """Get user choice from a dictionary of options."""
    while True:
        choice = input(f"{prompt} ").strip()
        if choice in choices:
            return choice
        elif choice == "" and default:
            return default
        print("[!] Invalid choice. Please try again.")

def get_custom_tuning() -> str:
    """Get custom tuning options from user."""
    print("\n[CHARLOTTE] Custom Tuning Options:")
    display_tuning_options()
    print("\nEnter tuning options (comma-separated, e.g., 1,2,3,4,5):")
    tuning = input("Tuning: ").strip()
    
    if not tuning:
        return "1,2,3,4,5"  # Default to basic scan
    
    # Validate tuning options
    valid_options = set(TUNING_OPTIONS.keys())
    tuning_list = [opt.strip() for opt in tuning.split(",")]
    
    for opt in tuning_list:
        if opt not in valid_options:
            print(f"[!] Invalid tuning option: {opt}")
            return get_custom_tuning()
    
    return tuning

# ──────────────────────────────────────────────────────────────────────────────
# Core Scanning Functions
# ──────────────────────────────────────────────────────────────────────────────

def build_nikto_command(target: str, scan_type: str, output_file: str, 
                       tuning: str = "", format_args: str = "", 
                       additional_args: str = "") -> List[str]:
    """Build the Nikto command with all arguments."""
    cmd = ["nikto", "-h", target, "-output", output_file]
    
    # Add tuning options
    if tuning:
        cmd.extend(["-Tuning", tuning])
    
    # Add format options
    if format_args:
        cmd.extend(format_args.split())
    
    # Add additional arguments
    if additional_args:
        cmd.extend(additional_args.split())
    
    return cmd

def run_nikto_scan(target: str, scan_type: str, output_format: str, 
                  tuning: str = "", additional_args: str = "", 
                  timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, str, str]:
    """
    Run a Nikto scan and return results.
    
    Returns:
        (success, output_file, error_message)
    """
    # Validate target URL
    if not validate_url(target):
        return False, "", f"Invalid URL format: {target}"
    
    # Check if Nikto is installed
    nikto_available, version_info = check_nikto_installed()
    if not nikto_available:
        return False, "", f"Nikto not found. Please install Nikto first.\nRun: python installer/nikto/nikto_installer.py"
    
    print(f"[CHARLOTTE] Using Nikto {version_info}")
    
    # Create output directory
    os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
    
    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w\-_\.]', '_', target.replace('://', '_'))
    format_info = OUTPUT_FORMATS[output_format]
    output_file = os.path.join(DEFAULT_OUTPUT_DIR, f"nikto_{safe_target}_{timestamp}.{format_info['ext']}")

    print(f"[CHARLOTTE] Output file: {output_file}")
    
    # Get scan configuration
    scan_config = SCAN_TYPES[scan_type]
    format_config = OUTPUT_FORMATS[output_format]
    
    # Adjust timeout based on scan type
    if scan_type == "4":  # Test scan
        timeout = min(timeout, 60)  # Max 1 minute for test scan
    elif scan_type == "3":  # Quick scan
        timeout = min(timeout, 120)  # Max 2 minutes for quick scan
    
    # Build command
    if scan_type == "5":  # Custom tuning
        if not tuning:
            tuning = get_custom_tuning()
        tuning_args = tuning
    else:
        tuning_args = scan_config["args"].replace("-Tuning ", "")
    
    cmd = build_nikto_command(
        target=target,
        scan_type=scan_type,
        output_file=output_file,
        tuning=tuning_args,
        format_args=format_config["args"],
        additional_args=additional_args
    )
    
    print(f"[CHARLOTTE] Running Nikto scan on {target}")
    print(f"[CHARLOTTE] Command: {' '.join(cmd)}")
    print(f"[CHARLOTTE] Output: {output_file}")
    
    try:
        # Run Nikto scan with proper subprocess handling
        print(f"[CHARLOTTE] Executing: {' '.join(cmd)}")
        
        # Use Popen for better control and to avoid TTY issues
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=None if os.name == 'nt' else os.setsid  # Avoid TTY issues on Unix
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return_code = process.returncode
            
            print(f"[CHARLOTTE] Return code: {return_code}")
            if stdout:
                print(f"[CHARLOTTE] stdout: {stdout[:200]}...")
            if stderr:
                print(f"[CHARLOTTE] stderr: {stderr[:200]}...")
            
            # Check if output file was created and has content
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                # Check for JSON format issues
                if output_format == "5" and "Can't locate object method" in stderr:
                    print(f"[CHARLOTTE] Scan completed with warnings - JSON format may be incomplete due to missing Perl JSON module")
                    print(f"[CHARLOTTE] Consider using TXT format for reliable results")
                else:
                    print(f"[CHARLOTTE] Scan completed successfully!")
                return True, output_file, ""
            else:
                error_msg = f"Nikto scan failed - no output file created or file is empty"
                if stderr:
                    error_msg += f"\nError: {stderr}"
                return False, output_file, error_msg
                
        except subprocess.TimeoutExpired:
            # Kill the process and its children
            try:
                if os.name == 'nt':
                    # Windows: just terminate the process
                    process.terminate()  # noqa: unreachable
                else:
                    # Unix/Linux: kill the process group
                    os.killpg(os.getpgid(process.pid), 9)
                process.wait(timeout=5)
            except:
                pass
            
            # Try to create a partial output file from stdout
            try:
                stdout, stderr = process.communicate(timeout=1)
                if stdout:
                    # Create a partial output file
                    partial_file = output_file.replace('.txt', '_partial.txt')
                    with open(partial_file, 'w', encoding='utf-8') as f:
                        f.write(stdout)
                    print(f"[CHARLOTTE] Scan timed out, but created partial output: {partial_file}")
                    return True, partial_file, f"Scan timed out after {timeout} seconds, but partial results saved"
            except:
                pass
            
            return False, output_file, f"Scan timed out after {timeout} seconds"
            
    except Exception as e:
        return False, output_file, f"Unexpected error: {str(e)}"

def parse_nikto_txt(output_file: str) -> Dict[str, Any]:
    """Parse Nikto TXT output and convert to CHARLOTTE format."""
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        findings = []
        lines = content.split('\n')
        
        # Extract target information
        target = "unknown"
        for line in lines:
            if "Target IP:" in line:
                target = line.split("Target IP:")[1].strip()
                break
            elif "Target Hostname:" in line:
                target = line.split("Target Hostname:")[1].strip()
                break
        
        # Parse findings (lines starting with "+")
        for line in lines:
            if line.strip().startswith("+ ") and ":" in line:
                # Extract vulnerability information
                vuln_line = line[2:].strip()  # Remove "+ " prefix
                
                # Split by colon to get URL and description
                if ":" in vuln_line:
                    url_part, desc_part = vuln_line.split(":", 1)
                    url = url_part.strip()
                    description = desc_part.strip()
                else:
                    url = "/"
                    description = vuln_line
                
                # Determine severity based on keywords
                severity = "Low"
                desc_lower = description.lower()
                if any(keyword in desc_lower for keyword in ["vulnerable", "exploit", "injection", "xss", "sql"]):
                    severity = "High"
                elif any(keyword in desc_lower for keyword in ["warning", "issue", "problem", "risk"]):
                    severity = "Medium"
                
                finding = {
                    "id": f"nikto_{len(findings) + 1}",
                    "title": description[:100] + "..." if len(description) > 100 else description,
                    "description": description,
                    "severity": severity,
                    "url": url,
                    "method": "GET",
                    "parameter": "",
                    "evidence": description,
                    "plugin": "nikto",
                    "timestamp": datetime.now().isoformat(),
                    "source": "nikto_scan"
                }
                findings.append(finding)
        
        return {
            "plugin": "nikto",
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "high_severity": len([f for f in findings if f.get('severity', '').lower() == 'high']),
                "medium_severity": len([f for f in findings if f.get('severity', '').lower() == 'medium']),
                "low_severity": len([f for f in findings if f.get('severity', '').lower() == 'low'])
            }
        }
        
    except Exception as e:
        return {
            "plugin": "nikto",
            "error": f"Failed to parse Nikto output: {str(e)}",
            "findings": []
        }

def parse_nikto_json(output_file: str) -> Dict[str, Any]:
    """Parse Nikto JSON output and convert to CHARLOTTE format."""
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Convert Nikto JSON to CHARLOTTE format
        findings = []
        
        if 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                finding = {
                    "id": f"nikto_{vuln.get('id', 'unknown')}",
                    "title": vuln.get('title', 'Unknown vulnerability'),
                    "description": vuln.get('description', ''),
                    "severity": vuln.get('severity', 'Medium'),
                    "url": vuln.get('url', ''),
                    "method": vuln.get('method', 'GET'),
                    "parameter": vuln.get('parameter', ''),
                    "evidence": vuln.get('evidence', ''),
                    "plugin": "nikto",
                    "timestamp": datetime.now().isoformat(),
                    "source": "nikto_scan"
                }
                findings.append(finding)
        
        return {
            "plugin": "nikto",
            "target": data.get('host', 'unknown'),
            "scan_time": data.get('scan_time', ''),
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "high_severity": len([f for f in findings if f.get('severity', '').lower() == 'high']),
                "medium_severity": len([f for f in findings if f.get('severity', '').lower() == 'medium']),
                "low_severity": len([f for f in findings if f.get('severity', '').lower() == 'low'])
            }
        }
        
    except Exception as e:
        return {
            "plugin": "nikto",
            "error": f"Failed to parse Nikto output: {str(e)}",
            "findings": []
        }

def display_scan_results(results: Dict[str, Any]):
    """Display scan results in a user-friendly format."""
    print("\n" + "="*60)
    print("CHARLOTTE Nikto Scan Results")
    print("="*60)
    
    if "error" in results:
        print(f"[!] Error: {results['error']}")
        return
    
    print(f"Target: {results.get('target', 'Unknown')}")
    print(f"Scan Time: {results.get('scan_time', 'Unknown')}")
    
    summary = results.get('summary', {})
    print(f"\nSummary:")
    print(f"  Total Findings: {summary.get('total_findings', 0)}")
    print(f"  High Severity: {summary.get('high_severity', 0)}")
    print(f"  Medium Severity: {summary.get('medium_severity', 0)}")
    print(f"  Low Severity: {summary.get('low_severity', 0)}")
    
    findings = results.get('findings', [])
    if findings:
        print(f"\nTop Findings:")
        for i, finding in enumerate(findings[:10], 1):  # Show top 10
            severity = finding.get('severity', 'Unknown')
            title = finding.get('title', 'Unknown')
            url = finding.get('url', '')
            print(f"  {i}. [{severity}] {title}")
            if url:
                print(f"     URL: {url}")
    
    if len(findings) > 10:
        print(f"  ... and {len(findings) - 10} more findings")

# ──────────────────────────────────────────────────────────────────────────────
# Interactive Interface
# ──────────────────────────────────────────────────────────────────────────────

def run_interactive_scan():
    """Run an interactive Nikto scan with user prompts."""
    print("\n" + "="*60)
    print("CHARLOTTE Nikto Web Vulnerability Scanner")
    print("="*60)
    print("⚠️  IMPORTANT: Only scan targets you have permission to test!")
    print("Unauthorized scanning may violate laws and terms of service.\n")
    
    # Get target URL
    target = input(f"Enter target URL (default: {DEFAULT_TARGET}): ").strip()
    if not target:
        target = DEFAULT_TARGET
    
    if not validate_url(target):
        print(f"[!] Invalid URL format: {target}")
        return
    
    # Display scan types
    display_scan_types()
    scan_type = get_user_choice("Select scan type (1-4): ", SCAN_TYPES, "1")
    
    # Get tuning options for custom scan
    tuning = ""
    if scan_type == "4":
        tuning = get_custom_tuning()
    
    # Display output formats
    display_output_formats()
    output_format = get_user_choice("Select output format (1-5): ", OUTPUT_FORMATS, "1")
    
    # Additional arguments
    additional_args = input("Additional Nikto arguments (optional): ").strip()
    
    # Confirmation
    print(f"\n[CHARLOTTE] Scan Configuration:")
    print(f"  Target: {target}")
    print(f"  Scan Type: {SCAN_TYPES[scan_type]['name']}")
    print(f"  Output Format: {OUTPUT_FORMATS[output_format]['name']}")
    if tuning:
        print(f"  Tuning: {tuning}")
    if additional_args:
        print(f"  Additional Args: {additional_args}")
    
    confirm = input("\nProceed with scan? (y/N): ").strip().lower()
    if confirm not in ['y', 'yes']:
        print("[!] Scan cancelled.")
        return
    
    # Run the scan
    success, output_file, error = run_nikto_scan(
        target=target,
        scan_type=scan_type,
        output_format=output_format,
        tuning=tuning,
        additional_args=additional_args
    )
    
    if success:
        print(f"[+] Scan completed! Results saved to: {display_path(output_file)}")
        
        # Parse and display results based on output format
        if output_format == "1":  # TXT
            results = parse_nikto_txt(output_file)
            display_scan_results(results)
        elif output_format == "5":  # JSON
            results = parse_nikto_json(output_file)
            display_scan_results(results)
    else:
        print(f"[!] Scan failed: {error}")

# ──────────────────────────────────────────────────────────────────────────────
# Plugin Entry Points
# ──────────────────────────────────────────────────────────────────────────────

def run(args: Optional[Dict] = None) -> str:
    """
    Main plugin entry point for CHARLOTTE.
    
    Args:
        args: Dictionary containing scan parameters
        
    Returns:
        String result of the scan operation
    """
    if args is None:
        args = {}
    
    # Check if running in interactive mode
    if not args or args.get('interactive', True):
        run_interactive_scan()
        return "Interactive scan completed"
    
    # Headless mode - extract parameters from args
    target = args.get('target', DEFAULT_TARGET)
    scan_type = args.get('scan_type', '1')
    output_format = args.get('output_format', '1')
    tuning = args.get('tuning', '')
    additional_args = args.get('additional_args', '')
    timeout = args.get('timeout', DEFAULT_TIMEOUT)
    
    print(f"[CHARLOTTE] Running headless Nikto scan on {target}")
    
    # Run the scan
    success, output_file, error = run_nikto_scan(
        target=target,
        scan_type=scan_type,
        output_format=output_format,
        tuning=tuning,
        additional_args=additional_args,
        timeout=timeout
    )
    
    if success:
        result = f"Scan completed successfully. Output: {display_path(output_file)}"
        
        # Parse results based on output format
        if os.path.exists(output_file):
            if output_format == "1":  # TXT
                results = parse_nikto_txt(output_file)
            elif output_format == "5":  # JSON
                results = parse_nikto_json(output_file)
            else:
                results = {"findings": []}
            
            if "findings" in results:
                result += f"\nFound {len(results['findings'])} vulnerabilities"
        
        return result
    else:
        return f"Scan failed: {error}"

def run_plugin(args: Optional[Dict] = None) -> str:
    """Alternative entry point for compatibility."""
    return run(args)

# ──────────────────────────────────────────────────────────────────────────────
# Main execution
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # When run directly, use interactive mode
    run_interactive_scan()
