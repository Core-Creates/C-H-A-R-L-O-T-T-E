# CHARLOTTE Nikto Plugin

A comprehensive web vulnerability scanner plugin that integrates Nikto with the CHARLOTTE security framework.

## Overview

This plugin provides web vulnerability scanning capabilities using Nikto, a popular web server scanner that performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version-specific problems on over 450 servers.

## Features

- **Interactive CLI Interface**: User-friendly prompts for scan configuration
- **Multiple Scan Types**: Basic, Comprehensive, Quick, Test, and Custom tuning options
- **Multiple Output Formats**: TXT, XML, HTML, CSV, and JSON
- **Smart Timeout Handling**: Graceful timeout with partial result capture
- **Safe Defaults**: Uses safe testing targets by default
- **Security Warnings**: Clear guidance about authorized scanning only
- **Integration**: Seamless integration with CHARLOTTE's triage system

## Installation

### Prerequisites

1. **Install Nikto**: Run the CHARLOTTE Nikto installer:
   ```bash
   python installer/nikto/nikto_installer.py
   ```

2. **Verify Installation**:
   ```bash
   nikto -Version
   ```

### Plugin Registration

The plugin is automatically registered in Charlotte's plugin system and appears in the main menu as:
- **🔍 Nikto Web Vulnerability Scanner**

## Usage

### Interactive Mode

Run the plugin directly for interactive configuration:
```bash
python plugins/vulnscan/nikto/nikto_plugin.py
```

### Programmatic Usage

Use through Charlotte's plugin system:
```python
from core.plugin_manager import run_plugin

result = run_plugin('nikto_scan', {
    'target': 'https://example.com',
    'scan_type': '4',  # Test scan
    'output_format': '1',  # TXT
    'timeout': 60,
    'interactive': False
})
```

### Scan Types

1. **Basic Scan** - Standard vulnerability checks (recommended)
2. **Comprehensive Scan** - All available checks (slower but thorough)
3. **Quick Scan** - Fast scan with basic checks only (1-2 minutes)
4. **Test Scan** - Very quick test scan (30-60 seconds)
5. **Custom Tuning** - Specify custom tuning options

### Output Formats

1. **TXT** - Plain text output (default, most reliable)
2. **XML** - XML format
3. **HTML** - HTML report
4. **CSV** - CSV format
5. **JSON** - JSON format (may have compatibility issues)

## Configuration

### Default Settings

- **Default Target**: `https://public-firing-range.appspot.com` (safe testing site)
- **Default Timeout**: 60 seconds
- **Output Directory**: `data/findings/`
- **Default Format**: TXT

### Timeout Handling

The plugin includes smart timeout handling:
- **Test Scan**: Max 60 seconds
- **Quick Scan**: Max 120 seconds
- **Other Scans**: Configurable timeout (default 60 seconds)
- **Partial Results**: If scan times out, partial results are saved

## Security Considerations

⚠️ **Important Security Notice**:
- Only scan targets you have explicit permission to test
- Unauthorized scanning may violate laws and terms of service
- The plugin includes clear warnings and uses safe default targets
- Always obtain proper authorization before scanning

## Output Format

The plugin generates results in CHARLOTTE's standard format:

```json
{
  "plugin": "nikto",
  "target": "https://example.com",
  "scan_time": "2025-09-09T20:27:48",
  "findings": [
    {
      "id": "nikto_1",
      "title": "Missing X-Frame-Options header",
      "description": "The anti-clickjacking X-Frame-Options header is not present",
      "severity": "Medium",
      "url": "/",
      "method": "GET",
      "evidence": "See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
      "plugin": "nikto",
      "timestamp": "2025-09-09T20:27:48",
      "source": "nikto_scan"
    }
  ],
  "summary": {
    "total_findings": 11,
    "high_severity": 2,
    "medium_severity": 5,
    "low_severity": 4
  }
}
```

## Troubleshooting

### Common Issues

1. **Nikto not found**: Install Nikto using the provided installer
2. **Scan timeouts**: Use Test Scan (option 4) for quick testing
3. **Empty output files**: Check if scan completed or timed out
4. **Permission errors**: Ensure you have write access to the output directory

### Debug Mode

Enable debug output by setting environment variable:
```bash
export CHARLOTTE_DEBUG=1
python plugins/vulnscan/nikto/nikto_plugin.py
```

## Integration with CHARLOTTE

The plugin integrates seamlessly with Charlotte's ecosystem:
- **Plugin Registry**: Registered as `nikto_scan`
- **Menu Integration**: Appears in main menu under "Web Vulnerability Scanning"
- **Triage System**: Results can be processed by Charlotte's triage agent
- **Report Generation**: Compatible with Charlotte's report dispatcher

## Dependencies

- **External**: Nikto web scanner
- **Python**: subprocess, json, os, sys, datetime, pathlib
- **Perl Modules**: Net::SSLeay, LWP::UserAgent, HTTP::Cookies

## License

This plugin is part of the CHARLOTTE Security Framework and follows the same licensing terms.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the Nikto documentation: https://cirt.net/Nikto2
3. Check Charlotte's plugin documentation
4. Report issues through Charlotte's support channels
