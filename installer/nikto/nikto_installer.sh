#!/bin/bash
#
# CHARLOTTE Nikto Installer Script
# 
# This script installs Nikto web vulnerability scanner
# for use with the CHARLOTTE Nikto plugin.
#
# Supported platforms: macOS, Ubuntu/Debian, CentOS/RHEL
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

# Check if Nikto is already installed
check_nikto_installed() {
    if command -v nikto &> /dev/null; then
        local version=$(nikto -Version 2>/dev/null | head -n1 || echo "unknown version")
        print_success "Nikto is already installed: $version"
        return 0
    fi
    
    # Check common installation paths
    local common_paths=("/usr/bin/nikto" "/usr/local/bin/nikto" "/opt/nikto/nikto.pl" "/usr/share/nikto/nikto.pl")
    for path in "${common_paths[@]}"; do
        if [[ -x "$path" ]]; then
            print_success "Nikto found at: $path"
            return 0
        fi
    done
    
    return 1
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt &> /dev/null; then
            echo "ubuntu"
        elif command -v yum &> /dev/null; then
            echo "centos"
        elif command -v dnf &> /dev/null; then
            echo "fedora"
        else
            echo "linux"
        fi
    else
        echo "unknown"
    fi
}

# Install on macOS via Homebrew
install_macos() {
    print_status "Installing Nikto on macOS via Homebrew..."
    
    if ! command -v brew &> /dev/null; then
        print_error "Homebrew not found. Please install Homebrew first:"
        echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        return 1
    fi
    
    print_success "Homebrew found"
    brew install nikto
    
    if check_nikto_installed; then
        print_success "Nikto installed successfully via Homebrew!"
        return 0
    else
        print_error "Nikto installation failed"
        return 1
    fi
}

# Install on Ubuntu/Debian via apt
install_ubuntu() {
    print_status "Installing Nikto on Ubuntu/Debian via apt..."
    
    if ! command -v apt &> /dev/null; then
        print_error "apt package manager not found"
        return 1
    fi
    
    print_success "apt package manager found"
    
    # Update package list
    print_status "Updating package list..."
    sudo apt update
    
    # Install Nikto
    print_status "Installing Nikto..."
    sudo apt install -y nikto
    
    if check_nikto_installed; then
        print_success "Nikto installed successfully via apt!"
        return 0
    else
        print_error "Nikto installation failed"
        return 1
    fi
}

# Install on CentOS/RHEL via yum
install_centos() {
    print_status "Installing Nikto on CentOS/RHEL via yum..."
    
    if ! command -v yum &> /dev/null; then
        print_error "yum package manager not found"
        return 1
    fi
    
    print_success "yum package manager found"
    
    # Install Nikto
    print_status "Installing Nikto..."
    sudo yum install -y nikto
    
    if check_nikto_installed; then
        print_success "Nikto installed successfully via yum!"
        return 0
    else
        print_error "Nikto installation failed"
        return 1
    fi
}

# Install on Fedora via dnf
install_fedora() {
    print_status "Installing Nikto on Fedora via dnf..."
    
    if ! command -v dnf &> /dev/null; then
        print_error "dnf package manager not found"
        return 1
    fi
    
    print_success "dnf package manager found"
    
    # Install Nikto
    print_status "Installing Nikto..."
    sudo dnf install -y nikto
    
    if check_nikto_installed; then
        print_success "Nikto installed successfully via dnf!"
        return 0
    else
        print_error "Nikto installation failed"
        return 1
    fi
}

# Check Perl dependencies
check_perl_dependencies() {
    print_status "Checking Perl dependencies..."
    
    local required_modules=("Net::SSLeay" "LWP::UserAgent" "HTTP::Cookies")
    local missing_modules=()
    
    for module in "${required_modules[@]}"; do
        if ! perl -M"$module" -e 1 &> /dev/null; then
            missing_modules+=("$module")
        fi
    done
    
    if [[ ${#missing_modules[@]} -gt 0 ]]; then
        print_warning "Missing Perl modules: ${missing_modules[*]}"
        print_status "Install them with: cpan ${missing_modules[*]}"
        return 1
    fi
    
    print_success "All required Perl modules are available"
    return 0
}

# Manual installation instructions
show_manual_install() {
    print_status "Manual installation instructions:"
    echo "1. Download Nikto from: https://github.com/sullo/nikto"
    echo "2. Extract the archive to a directory (e.g., /opt/nikto)"
    echo "3. Make sure nikto.pl is executable: chmod +x nikto.pl"
    echo "4. Add the directory to your PATH or create a symlink:"
    echo "   sudo ln -s /path/to/nikto/nikto.pl /usr/local/bin/nikto"
    echo "5. Install Perl dependencies if needed:"
    echo "   cpan Net::SSLeay LWP::UserAgent HTTP::Cookies"
}

# Main installation function
main() {
    echo "============================================================"
    echo "CHARLOTTE Nikto Installer"
    echo "============================================================"
    echo "This installer will help you install Nikto web vulnerability scanner"
    echo "for use with the CHARLOTTE Nikto plugin."
    echo ""
    
    # Check if Nikto is already installed
    if check_nikto_installed; then
        print_success "Nikto is already installed and ready to use!"
        exit 0
    fi
    
    print_status "Nikto not found. Proceeding with installation..."
    echo ""
    
    # Detect operating system
    local os=$(detect_os)
    print_status "Detected operating system: $os"
    
    # Install based on OS
    case "$os" in
        "macos")
            if install_macos; then
                exit 0
            fi
            ;;
        "ubuntu")
            if install_ubuntu; then
                exit 0
            fi
            ;;
        "centos")
            if install_centos; then
                exit 0
            fi
            ;;
        "fedora")
            if install_fedora; then
                exit 0
            fi
            ;;
        *)
            print_error "Unsupported operating system: $os"
            show_manual_install
            exit 1
            ;;
    esac
    
    # If we get here, automatic installation failed
    print_warning "Automatic installation failed. Showing manual installation instructions..."
    show_manual_install
    
    # Check Perl dependencies
    check_perl_dependencies
    
    echo ""
    echo "============================================================"
    echo "Installation process completed!"
    echo "Please verify Nikto installation by running: nikto -Version"
    echo "============================================================"
}

# Run main function
main "$@"
