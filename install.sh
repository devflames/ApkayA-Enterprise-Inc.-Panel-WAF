#!/bin/bash

# ============================================================
# Apkaya Panel WAF - Automated Installation Script
# Copyright (c) 2025-2026 Albert Camings
# Developed by: Albert Camings (Full Stack Developer)
# License: MIT License - Open Source
# Supports: Ubuntu 20.04+, Debian 10+, CentOS 8+, AlmaLinux
# ============================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/root/apkaya-panel-waf"
INSTALL_USER="root"
PYTHON_VERSION="3.12"
SERVICE_NAME="apkaya-panel"

# ============================================================
# Helper Functions
# ============================================================

print_header() {
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
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
    echo -e "${BLUE}ℹ $1${NC}"
}

# ============================================================
# Detect OS
# ============================================================

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        VER=$(lsb_release -sr)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    echo "$OS"
}

# ============================================================
# System Checks
# ============================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
    print_success "Root privileges confirmed"
}

check_disk_space() {
    available=$(df /root | tail -1 | awk '{print $4}')
    required=$((10 * 1024 * 1024))  # 10GB in KB
    
    if [[ $available -lt $required ]]; then
        print_error "Insufficient disk space. Required: 10GB, Available: $((available / 1024 / 1024))GB"
        exit 1
    fi
    print_success "Disk space check passed"
}

check_network() {
    if ! ping -c 1 google.com &> /dev/null; then
        print_error "No internet connection detected"
        exit 1
    fi
    print_success "Internet connection confirmed"
}

# ============================================================
# Dependency Installation
# ============================================================

install_dependencies() {
    OS=$(detect_os)
    
    print_header "Installing Dependencies for $OS"
    
    case "$OS" in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                python3.12 python3.12-venv python3.12-dev \
                curl wget git nginx mysql-server redis-server \
                build-essential libssl-dev libffi-dev \
                openssh-client certbot python3-certbot-nginx \
                supervisor logrotate
            print_success "Ubuntu/Debian dependencies installed"
            ;;
        centos|rhel|almalinux)
            yum install -y epel-release
            yum install -y \
                python3.12 python3.12-devel \
                curl wget git nginx mysql-server redis \
                gcc openssl-devel libffi-devel \
                openssh-clients certbot python3-certbot-nginx \
                supervisor
            print_success "CentOS/RHEL dependencies installed"
            ;;
        *)
            print_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# ============================================================
# Python Setup
# ============================================================

setup_python_env() {
    print_header "Setting Up Python Environment"
    
    # Check Python version
    if ! command -v python3.12 &> /dev/null; then
        print_error "Python 3.12 not found"
        exit 1
    fi
    
    python_version=$(python3.12 --version)
    print_success "Found: $python_version"
    
    # Create virtual environment
    print_info "Creating virtual environment..."
    python3.12 -m venv "$INSTALL_DIR/venv"
    print_success "Virtual environment created"
    
    # Activate and upgrade pip
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --upgrade pip setuptools wheel
    print_success "Pip upgraded"
}

# ============================================================
# Application Installation
# ============================================================

install_application() {
    print_header "Installing Apkaya Panel WAF"
    
    # Clone or prepare application
    if [[ ! -d "$INSTALL_DIR" ]]; then
        print_info "Cloning repository..."
        git clone https://github.com/apkaya/apkaya-panel-waf.git "$INSTALL_DIR"
    else
        print_info "Updating existing installation..."
        cd "$INSTALL_DIR" && git pull origin main
    fi
    
    # Create directories
    mkdir -p "$INSTALL_DIR"/{config,data,logs,backup,ssl}
    
    # Install Python dependencies
    print_info "Installing Python dependencies..."
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --no-cache-dir -r "$INSTALL_DIR/requirements.txt"
    print_success "Python dependencies installed"
}

# ============================================================
# Database Setup
# ============================================================

setup_database() {
    print_header "Configuring Database"
    
    # Check if MySQL is running
    if ! systemctl is-active --quiet mysql && ! systemctl is-active --quiet mariadb; then
        print_info "Starting MySQL/MariaDB..."
        systemctl start mysql || systemctl start mariadb
    fi
    
    # Create database and user
    print_info "Creating database..."
    
    DB_PASSWORD=$(openssl rand -base64 12)
    
    mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS apkaya_panel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'apkaya_user'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON apkaya_panel.* TO 'apkaya_user'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    print_success "Database created: apkaya_panel"
    print_success "Database user created: apkaya_user"
    
    # Save credentials
    cat > "$INSTALL_DIR/config/.db_credentials" <<EOF
DB_HOST=localhost
DB_PORT=3306
DB_USER=apkaya_user
DB_PASSWORD=$DB_PASSWORD
DB_NAME=apkaya_panel
EOF
    
    chmod 600 "$INSTALL_DIR/config/.db_credentials"
    print_success "Credentials saved to config/.db_credentials"
}

# ============================================================
# Service Configuration
# ============================================================

setup_systemd_service() {
    print_header "Setting Up Systemd Service"
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=Apkaya Panel WAF Control Panel
After=network.target mysql.service redis.service

[Service]
Type=simple
User=$INSTALL_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
Environment="FLASK_DEBUG=false"
Environment="FLASK_ENV=production"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/run.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=apkaya-panel

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    print_success "Systemd service configured"
}

# ============================================================
# Firewall Configuration
# ============================================================

configure_firewall() {
    print_header "Configuring Firewall"
    
    if command -v ufw &> /dev/null; then
        ufw --force enable
        ufw allow 22/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 72323/tcp
        print_success "UFW firewall rules configured"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --permanent --add-port=72323/tcp
        firewall-cmd --reload
        print_success "Firewalld rules configured"
    else
        print_warning "No firewall management tool found (ufw/firewalld)"
    fi
}

# ============================================================
# SSL Certificate Setup
# ============================================================

setup_ssl() {
    print_header "Setting Up SSL Certificate"
    
    read -p "Enter your domain name (e.g., panel.example.com): " domain_name
    
    if [[ -z "$domain_name" ]]; then
        print_warning "Skipping SSL setup. Configure manually later."
        return
    fi
    
    print_info "Obtaining Let's Encrypt certificate..."
    
    if certbot certonly --standalone -d "$domain_name" -n --agree-tos -m admin@example.com; then
        print_success "SSL certificate obtained for $domain_name"
        print_info "Certificate path: /etc/letsencrypt/live/$domain_name/fullchain.pem"
    else
        print_warning "SSL certificate setup failed. Configure manually later."
    fi
}

# ============================================================
# Initial Configuration
# ============================================================

create_initial_config() {
    print_header "Creating Initial Configuration"
    
    # Generate admin password
    ADMIN_PASSWORD=$(openssl rand -base64 12)
    
    # Create config file
    cat > "$INSTALL_DIR/config/app.config" <<EOF
{
    "admin_user": "admin",
    "admin_email": "admin@localhost",
    "admin_password_hash": "$ADMIN_PASSWORD",
    "panel_title": "Apkaya Panel WAF",
    "panel_url": "http://localhost:72323",
    "language": "en",
    "timezone": "UTC",
    "debug": false
}
EOF
    
    chmod 600 "$INSTALL_DIR/config/app.config"
    
    print_success "Initial configuration created"
    print_warning "IMPORTANT: Save your admin credentials:"
    print_warning "  Username: admin"
    print_warning "  Password: $ADMIN_PASSWORD"
    print_warning "  Email: admin@localhost"
}

# ============================================================
# Start Application
# ============================================================

start_application() {
    print_header "Starting Application"
    
    systemctl start "$SERVICE_NAME"
    
    # Wait for service to start
    sleep 5
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "Application started successfully"
    else
        print_error "Failed to start application"
        journalctl -u "$SERVICE_NAME" -n 20
        exit 1
    fi
}

# ============================================================
# Installation Summary
# ============================================================

print_summary() {
    print_header "Installation Complete!"
    
    echo ""
    echo "📊 Apkaya Panel WAF is now installed and running!"
    echo ""
    echo "Quick Start:"
    echo "  • Access Control Panel: http://your-server-ip:72323"
    echo "  • Default Username: admin"
    echo "  • Change password immediately in Settings → Profile"
    echo ""
    echo "Service Management:"
    echo "  • Start:   systemctl start $SERVICE_NAME"
    echo "  • Stop:    systemctl stop $SERVICE_NAME"
    echo "  • Status:  systemctl status $SERVICE_NAME"
    echo "  • Logs:    journalctl -u $SERVICE_NAME -f"
    echo ""
    echo "Configuration:"
    echo "  • Config Directory: $INSTALL_DIR/config"
    echo "  • Data Directory:   $INSTALL_DIR/data"
    echo "  • Logs Directory:   $INSTALL_DIR/logs"
    echo "  • Backup Directory: $INSTALL_DIR/backup"
    echo ""
    echo "Next Steps:"
    echo "  1. Change default admin password"
    echo "  2. Enable 2FA for security"
    echo "  3. Configure SSL certificate"
    echo "  4. Set up firewall rules"
    echo "  5. Configure backup schedule"
    echo "  6. Add your first website"
    echo ""
    echo "Documentation: https://docs.apkaya.com"
    echo "Support: support@apkaya.com"
    echo ""
}

# ============================================================
# Main Execution
# ============================================================

main() {
    print_header "Apkaya Panel WAF Installation"
    
    check_root
    check_disk_space
    check_network
    
    install_dependencies
    setup_python_env
    install_application
    setup_database
    setup_systemd_service
    configure_firewall
    setup_ssl
    create_initial_config
    start_application
    
    print_summary
}

# Run main function
main "$@"
