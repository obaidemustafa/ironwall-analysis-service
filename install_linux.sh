#!/bin/bash
#
# Linux Installation Script for Binary Preprocessing Module
#
# Supports: Ubuntu/Debian (apt) and RHEL/CentOS (yum/dnf)
#
# Usage:
#   chmod +x install_linux.sh
#   ./install_linux.sh
#   # OR with sudo if you prefer system-wide installation:
#   sudo ./install_linux.sh

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# Detect Linux distribution
detect_distro() {
    if command -v apt-get &> /dev/null; then
        DISTRO="debian"
        PACKAGE_MANAGER="apt-get"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
    elif command -v yum &> /dev/null; then
        DISTRO="rhel"
        PACKAGE_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum update -y"
    elif command -v dnf &> /dev/null; then
        DISTRO="rhel"
        PACKAGE_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf update -y"
    else
        print_error "Unsupported Linux distribution"
        exit 1
    fi
    print_success "Detected: $DISTRO ($PACKAGE_MANAGER)"
}

# Check if running with appropriate privileges
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        SUDO=""
        print_success "Running as root"
    else
        SUDO="sudo"
        print_warning "Installing to user environment (no sudo)"
        print_info "Some tools may need system-wide installation"
    fi
}

# Main installation
print_header "BINARY PREPROCESSING MODULE - LINUX INSTALLATION"

# Step 1: Detect distribution
print_header "[Step 1/5] Detecting Linux Distribution"
detect_distro
check_privileges

# Step 2: Update package manager
print_header "[Step 2/5] Updating Package Manager"
print_info "Running: $UPDATE_CMD"
$SUDO $UPDATE_CMD > /dev/null 2>&1 || print_warning "Package manager update may have failed"
print_success "Package manager updated"

# Step 3: Install system tools
print_header "[Step 3/5] Installing System Tools"

# File utility (libmagic)
print_info "Installing file utility..."
if [ "$DISTRO" = "debian" ]; then
    $SUDO $INSTALL_CMD file libmagic-dev
else
    $SUDO $INSTALL_CMD file file-devel file-libs
fi
print_success "File utility installed"

# Binutils (includes strings)
print_info "Installing binutils..."
$SUDO $INSTALL_CMD binutils
print_success "Binutils/strings installed"

# Binwalk
print_info "Installing binwalk..."
if [ "$DISTRO" = "debian" ]; then
    $SUDO $INSTALL_CMD binwalk
else
    $SUDO $INSTALL_CMD binwalk
fi
print_success "Binwalk installed"

# ClamAV
print_info "Installing ClamAV..."
if [ "$DISTRO" = "debian" ]; then
    $SUDO $INSTALL_CMD clamav clamav-daemon
else
    $SUDO $INSTALL_CMD clamav clamd
fi
print_success "ClamAV installed"

# Update ClamAV database
print_info "Updating ClamAV virus database (this may take 5-10 minutes)..."
$SUDO freshclam
print_success "ClamAV database updated"

# Step 4: Install Java
print_header "[Step 4/5] Installing Java Development Kit"

print_info "Installing OpenJDK 17..."
if [ "$DISTRO" = "debian" ]; then
    $SUDO $INSTALL_CMD openjdk-17-jdk-headless
else
    $SUDO $INSTALL_CMD java-17-openjdk-devel
fi
print_success "Java installed"

# Configure JAVA_HOME
print_info "Configuring JAVA_HOME..."
JAVA_PATH=$(which java)
if [ -n "$JAVA_PATH" ]; then
    JAVA_HOME=$(dirname $(dirname $JAVA_PATH))
    
    # Add to ~/.bashrc if not already there
    if ! grep -q "export JAVA_HOME" ~/.bashrc 2>/dev/null; then
        echo "export JAVA_HOME=$JAVA_HOME" >> ~/.bashrc
        print_success "JAVA_HOME added to ~/.bashrc"
    else
        print_success "JAVA_HOME already configured"
    fi
    
    # Also set for current session
    export JAVA_HOME
    print_success "JAVA_HOME = $JAVA_HOME"
else
    print_warning "Java not found in PATH"
fi

# Step 5: Install Python packages
print_header "[Step 5/5] Installing Python Packages"

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
print_success "Python $python_version detected"

# Upgrade pip
print_info "Upgrading pip..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1

# Install packages
print_info "Installing Python packages..."
pip install capstone lief pefile pyelftools networkx ghidra-bridge rich loguru

if [ $? -eq 0 ]; then
    print_success "Python packages installed"
else
    print_error "Failed to install some Python packages"
    print_info "Try: pip install --user capstone lief pefile pyelftools networkx ghidra-bridge rich loguru"
fi

# Final verification
print_header "FINAL VERIFICATION"

print_info "Checking system tools..."
tools=("file" "binwalk" "strings" "clamscan" "java")
all_ok=true

for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        print_success "$tool found"
    else
        print_error "$tool NOT found"
        all_ok=false
    fi
done

print_info "Checking Python packages..."
packages=("capstone" "lief" "pefile" "elftools" "networkx")

for pkg in "${packages[@]}"; do
    if python3 -c "import ${pkg}" 2>/dev/null; then
        print_success "$pkg installed"
    else
        print_error "$pkg NOT installed"
        all_ok=false
    fi
done

# Summary
print_header "INSTALLATION SUMMARY"

if [ "$all_ok" = true ]; then
    print_success "ALL REQUIRED COMPONENTS INSTALLED!"
    echo ""
    echo "You can now run the binary preprocessing module:"
    echo "  python3 binary_preprocessing.py <binary_file> --json"
    echo ""
    echo "To verify all components:"
    echo "  python3 verify_all.py"
    echo ""
    echo "To see full installation report:"
    echo "  python3 verify_all.py --json"
else
    print_warning "Some components may be missing. Please review output above."
    echo ""
    echo "To identify all missing components:"
    echo "  python3 verify_all.py --install-help"
fi

echo ""
