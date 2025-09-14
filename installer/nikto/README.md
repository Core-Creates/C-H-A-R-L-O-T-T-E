# CHARLOTTE Nikto Installer

This directory contains installers for the Nikto web vulnerability scanner, required for the CHARLOTTE Nikto plugin.

## Overview

Nikto is a web server scanner that performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 450 servers.

## Installation Methods

### Automatic Installation

#### Python Installer (Cross-platform)
```bash
python installer/nikto/nikto_installer.py
```

#### Shell Script (Linux/macOS)
```bash
./installer/nikto/nikto_installer.sh
```

#### PowerShell Script (Windows)
```powershell
.\installer\nikto\nikto_installer.ps1
```

### Manual Installation

#### macOS
```bash
brew install nikto
```

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nikto
```

#### CentOS/RHEL
```bash
sudo yum install nikto
# or
sudo dnf install nikto
```

#### Windows (WSL)
```bash
# Install WSL first
wsl --install
# Then install Nikto in WSL
sudo apt install nikto
```

## Dependencies

Nikto requires Perl and several Perl modules:

- Net::SSLeay
- LWP::UserAgent
- HTTP::Cookies

Install these with:
```bash
cpan Net::SSLeay LWP::UserAgent HTTP::Cookies
```

## Verification

After installation, verify Nikto is working:

```bash
nikto -Version
```

## Usage with CHARLOTTE

Once installed, the Nikto plugin will be available in the CHARLOTTE menu under "Web Vulnerability Scanning" or similar category.

## Troubleshooting

### Common Issues

1. **Nikto not found**: Ensure Nikto is in your PATH or install it using the provided installers.

2. **Perl modules missing**: Install required Perl modules using cpan.

3. **Permission denied**: On Linux/macOS, you may need to use `sudo` for package installation.

4. **Windows issues**: Consider using WSL (Windows Subsystem for Linux) for better compatibility.

### Getting Help

- Check the [Nikto GitHub repository](https://github.com/sullo/nikto)
- Review the [Nikto documentation](https://cirt.net/Nikto2)
- Check CHARLOTTE plugin documentation

## Security Notice

⚠️ **Important**: Only scan targets you have explicit permission to test. Unauthorized scanning may violate laws and terms of service.

## License

This installer is part of the CHARLOTTE Security Framework and follows the same licensing terms.
