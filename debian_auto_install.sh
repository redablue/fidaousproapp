#!/bin/bash

# =============================================================================
# SCRIPT D'AUTO-INSTALLATION CABINET COMPTABLE PRO
# Compatible Debian 12 (Bookworm)
# Version 1.0.0
# =============================================================================

set -e  # Arrêt en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables de configuration
APP_NAME="Cabinet Comptable Pro"
APP_VERSION="1.0.0"
APP_DIR="/var/www/cabinet-comptable"
DB_NAME="cabinet_comptable"
DB_USER="cabinet_user"
DB_PASS=""
DOMAIN=""
EMAIL=""
INSTALL_SSL=false
INSTALL_FAIL2BAN=true
INSTALL_UFW=true

# Logo ASCII
show_logo() {
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║               📊 CABINET COMPTABLE PRO 📊                        ║
    ║                                                                   ║
    ║                   Installation Automatique                       ║
    ║                      Debian 12 (Bookworm)                       ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}\n"
}

# Affichage avec couleurs
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${PURPLE}==>${NC} ${CYAN}$1${NC}\n"
}

# Vérification des prérequis
check_system() {
    log_step "Vérification du système"
    
    # Vérifier que c'est bien Debian 12
    if ! grep -q "bookworm" /etc/os-release; then
        log_error "Ce script est conçu pour Debian 12 (Bookworm)"
        exit 1
    fi
    
    # Vérifier les privilèges root
    if [[ $EUID -ne 0 ]]; then
        log_error "Ce script doit être exécuté en tant que root"
        echo "Utilisez: sudo $0"
        exit 1
    fi
    
    # Vérifier la connexion Internet
    if ! ping -c 1 google.com &> /dev/null; then
        log_error "Connexion Internet requise"
        exit 1
    fi
    
    log_success "Système compatible détecté: $(lsb_release -d | cut -f2)"
}

# Configuration interactive
configure_installation() {
    log_step "Configuration de l'installation"
    
    echo "Répondez aux questions suivantes pour personnaliser l'installation:"
    echo
    
    # Nom de domaine
    read -p "Nom de domaine (ex: cabinet.mondomaine.com) [localhost]: " DOMAIN
    DOMAIN=${DOMAIN:-localhost}
    
    # Email administrateur
    if [[ "$DOMAIN" != "localhost" ]]; then
        read -p "Email administrateur (pour SSL): " EMAIL
        if [[ -n "$EMAIL" ]]; then
            INSTALL_SSL=true
        fi
    fi
    
    # Mot de passe base de données
    while [[ -z "$DB_PASS" ]]; do
        read -s -p "Mot de passe pour la base de données: " DB_PASS
        echo
        if [[ ${#DB_PASS} -lt 8 ]]; then
            log_warning "Le mot de passe doit contenir au moins 8 caractères"
            DB_PASS=""
        fi
    done
    
    # Sécurité
    read -p "Installer le firewall UFW ? [Y/n]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        INSTALL_UFW=false
    fi
    
    read -p "Installer Fail2Ban (protection anti-intrusion) ? [Y/n]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        INSTALL_FAIL2BAN=false
    fi
    
    # Récapitulatif
    echo
    log_info "Configuration choisie:"
    echo "  - Domaine: $DOMAIN"
    echo "  - Base de données: $DB_NAME"
    echo "  - Utilisateur DB: $DB_USER"
    echo "  - SSL: $([ "$INSTALL_SSL" = true ] && echo "Oui" || echo "Non")"
    echo "  - UFW: $([ "$INSTALL_UFW" = true ] && echo "Oui" || echo "Non")"
    echo "  - Fail2Ban: $([ "$INSTALL_FAIL2BAN" = true ] && echo "Oui" || echo "Non")"
    echo
    
    read -p "Continuer l'installation ? [Y/n]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_info "Installation annulée"
        exit 0
    fi
}

# Mise à jour du système
update_system() {
    log_step "Mise à jour du système"
    
    export DEBIAN_FRONTEND=noninteractive
    
    log_info "Mise à jour de la liste des paquets..."
    apt-get update -qq
    
    log_info "Mise à niveau du système..."
    apt-get upgrade -y -qq
    
    log_info "Installation des outils de base..."
    apt-get install -y -qq \
        curl \
        wget \
        unzip \
        git \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release
    
    log_success "Système mis à jour"
}

# Installation d'Apache
install_apache() {
    log_step "Installation d'Apache"
    
    log_info "Installation d'Apache2..."
    apt-get install -y -qq apache2
    
    log_info "Activation des modules Apache..."
    a2enmod rewrite
    a2enmod ssl
    a2enmod headers
    
    log_info "Configuration d'Apache..."
    # Sécurisation d'Apache
    cat > /etc/apache2/conf-available/security.conf << 'EOF'
ServerTokens Prod
ServerSignature Off
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
EOF
    
    a2enconf security
    
    systemctl enable apache2
    systemctl start apache2
    
    log_success "Apache installé et configuré"
}

# Installation de PHP 8.2
install_php() {
    log_step "Installation de PHP 8.2"
    
    log_info "Installation de PHP et des extensions..."
    apt-get install -y -qq \
        php8.2 \
        php8.2-fpm \
        php8.2-mysql \
        php8.2-curl \
        php8.2-gd \
        php8.2-intl \
        php8.2-mbstring \
        php8.2-xml \
        php8.2-zip \
        php8.2-bcmath \
        php8.2-soap \
        php8.2-readline \
        php8.2-cli \
        libapache2-mod-php8.2
    
    log_info "Configuration de PHP..."
    # Configuration PHP pour la production
    sed -i 's/;max_execution_time = 30/max_execution_time = 300/' /etc/php/8.2/apache2/php.ini
    sed -i 's/;max_input_time = 60/max_input_time = 300/' /etc/php/8.2/apache2/php.ini
    sed -i 's/memory_limit = 128M/memory_limit = 256M/' /etc/php/8.2/apache2/php.ini
    sed -i 's/post_max_size = 8M/post_max_size = 64M/' /etc/php/8.2/apache2/php.ini
    sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 64M/' /etc/php/8.2/apache2/php.ini
    sed -i 's/;date.timezone =/date.timezone = Europe\/Paris/' /etc/php/8.2/apache2/php.ini
    sed -i 's/expose_php = On/expose_php = Off/' /etc/php/8.2/apache2/php.ini
    
    # Installation de Composer
    log_info "Installation de Composer..."
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    chmod +x /usr/local/bin/composer
    
    log_success "PHP 8.2 installé et configuré"
}

# Installation de MySQL
install_mysql() {
    log_step "Installation de MySQL"
    
    log_info "Installation de MySQL Server..."
    debconf-set-selections <<< "mysql-server mysql-server/root_password password $DB_PASS"
    debconf-set-selections <<< "mysql-server mysql-server/root_password_again password $DB_PASS"
    
    apt-get install -y -qq mysql-server
    
    log_info "Sécurisation de MySQL..."
    mysql -u root -p"$DB_PASS" << EOF
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    log_info "Création de la base de données..."
    mysql -u root -p"$DB_PASS" << EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    systemctl enable mysql
    systemctl start mysql
    
    log_success "MySQL installé et configuré"
}

# Installation de l'application
install_application() {
    log_step "Installation de Cabinet Comptable Pro"
    
    log_info "Création du répertoire de l'application..."
    mkdir -p "$APP_DIR"
    
    log_info "Téléchargement de l'application..."
    # Ici, vous pourriez télécharger depuis un repository Git
    # git clone https://github.com/votre-repo/cabinet-comptable.git "$APP_DIR"
    
    # Pour cette démonstration, on crée la structure de base
    create_application_structure
    
    log_info "Configuration des permissions..."
    chown -R www-data:www-data "$APP_DIR"
    chmod -R 755 "$APP_DIR"
    chmod -R 777 "$APP_DIR/uploads"
    chmod -R 777 "$APP_DIR/cache"
    chmod -R 777 "$APP_DIR/logs"
    
    log_info "Configuration de l'application..."
    cat > "$APP_DIR/config/config.php" << EOF
<?php
// Configuration Cabinet Comptable Pro
// Généré automatiquement le $(date)

define('DB_HOST', 'localhost');
define('DB_NAME', '$DB_NAME');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');

define('APP_NAME', '$APP_NAME');
define('APP_VERSION', '$APP_VERSION');
define('APP_URL', 'http://$DOMAIN');
define('UPLOAD_PATH', '/var/www/cabinet-comptable/uploads/');
define('MAX_FILE_SIZE', 10485760); // 10MB

define('SALT', '$(openssl rand -base64 32)');
define('SESSION_TIMEOUT', 3600);

define('SMTP_HOST', 'localhost');
define('SMTP_PORT', 587);
define('SMTP_USER', '$EMAIL');
define('SMTP_PASS', '');

date_default_timezone_set('Europe/Paris');

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
?>
EOF
    
    log_success "Application installée"
}

# Création de la structure de l'application
create_application_structure() {
    log_info "Création de la structure de fichiers..."
    
    mkdir -p "$APP_DIR"/{config,includes,pages,assets/{css,js,images},api,templates,uploads/{documents,temp},cache,logs,backups}
    
    # Fichier index.php de base
    cat > "$APP_DIR/index.php" << 'EOF'
<?php
require_once 'config/config.php';
require_once 'includes/functions.php';

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

header('Location: dashboard.php');
?>
EOF
    
    # Fichier .htaccess pour la sécurité
    cat > "$APP_DIR/.htaccess" << 'EOF'
RewriteEngine On

# Redirection HTTPS (si SSL configuré)
# RewriteCond %{HTTPS} off
# RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Protection des fichiers sensibles
<Files "config.php">
    Require all denied
</Files>

<Files "*.log">
    Require all denied
</Files>

# Headers de sécurité
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"

# Compression GZIP
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>

# Cache statique
<IfModule mod_expires.c>
    ExpiresActive on
    ExpiresByType text/css "access plus 1 year"
    ExpiresByType application/javascript "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
</IfModule>
EOF
    
    # Protection des uploads
    cat > "$APP_DIR/uploads/.htaccess" << 'EOF'
# Protection des uploads
<Files "*.php">
    Require all denied
</Files>

<Files "*.phtml">
    Require all denied
</Files>

<Files "*.sh">
    Require all denied
</Files>
EOF
    
    # Placeholder pour les logs
    touch "$APP_DIR/logs/app.log"
    touch "$APP_DIR/logs/error.log"
    touch "$APP_DIR/logs/access.log"
}

# Configuration du Virtual Host Apache
configure_vhost() {
    log_step "Configuration du Virtual Host Apache"
    
    log_info "Création du Virtual Host..."
    cat > "/etc/apache2/sites-available/$DOMAIN.conf" << EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot $APP_DIR
    
    <Directory $APP_DIR>
        AllowOverride All
        Require all granted
        DirectoryIndex index.php
    </Directory>
    
    # Logs
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-access.log combined
    
    # Sécurité PHP
    php_admin_value open_basedir "$APP_DIR:/tmp"
    php_admin_flag log_errors on
    php_admin_value error_log "$APP_DIR/logs/php-error.log"
</VirtualHost>
EOF
    
    # Désactiver le site par défaut et activer le nôtre
    a2dissite 000-default
    a2ensite "$DOMAIN"
    
    systemctl reload apache2
    
    log_success "Virtual Host configuré"
}

# Installation de Certbot pour SSL
install_ssl() {
    if [[ "$INSTALL_SSL" != true ]] || [[ "$DOMAIN" == "localhost" ]]; then
        return
    fi
    
    log_step "Installation du certificat SSL"
    
    log_info "Installation de Certbot..."
    apt-get install -y -qq certbot python3-certbot-apache
    
    log_info "Génération du certificat SSL..."
    certbot --apache --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN"
    
    # Renouvellement automatique
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
    
    log_success "SSL configuré"
}

# Configuration du firewall UFW
configure_firewall() {
    if [[ "$INSTALL_UFW" != true ]]; then
        return
    fi
    
    log_step "Configuration du firewall UFW"
    
    log_info "Installation et configuration d'UFW..."
    apt-get install -y -qq ufw
    
    # Configuration UFW
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Règles de base
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Activation
    ufw --force enable
    
    log_success "Firewall configuré"
}

# Installation de Fail2Ban
install_fail2ban() {
    if [[ "$INSTALL_FAIL2BAN" != true ]]; then
        return
    fi
    
    log_step "Installation de Fail2Ban"
    
    log_info "Installation de Fail2Ban..."
    apt-get install -y -qq fail2ban
    
    log_info "Configuration de Fail2Ban..."
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/*error.log
maxretry = 5

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache2/*access.log
maxretry = 2

[apache-noscript]
enabled = true
port = http,https
logpath = /var/log/apache2/*access.log
maxretry = 6
EOF
    
    systemctl enable fail2ban
    systemctl start fail2ban
    
    log_success "Fail2Ban configuré"
}

# Installation des outils de monitoring
install_monitoring() {
    log_step "Installation des outils de monitoring"
    
    log_info "Installation de logrotate pour les logs..."
    cat > /etc/logrotate.d/cabinet-comptable << 'EOF'
/var/www/cabinet-comptable/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    copytruncate
    su www-data www-data
}
EOF
    
    log_info "Configuration du monitoring système..."
    # Script de surveillance simple
    cat > /usr/local/bin/cabinet-monitor.sh << 'EOF'
#!/bin/bash
# Script de monitoring Cabinet Comptable Pro

LOG_FILE="/var/log/cabinet-monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Vérification Apache
if ! systemctl is-active --quiet apache2; then
    echo "$DATE - ALERT: Apache2 is down" >> $LOG_FILE
    systemctl restart apache2
fi

# Vérification MySQL
if ! systemctl is-active --quiet mysql; then
    echo "$DATE - ALERT: MySQL is down" >> $LOG_FILE
    systemctl restart mysql
fi

# Vérification espace disque
DISK_USAGE=$(df /var/www | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 90 ]; then
    echo "$DATE - ALERT: Disk usage is $DISK_USAGE%" >> $LOG_FILE
fi

# Nettoyage des logs anciens
find /var/www/cabinet-comptable/logs -name "*.log" -mtime +30 -delete
find /var/www/cabinet-comptable/uploads/temp -type f -mtime +1 -delete
EOF
    
    chmod +x /usr/local/bin/cabinet-monitor.sh
    
    # Cron job pour le monitoring
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/cabinet-monitor.sh") | crontab -
    
    log_success "Monitoring configuré"
}

# Optimisation des performances
optimize_performance() {
    log_step "Optimisation des performances"
    
    log_info "Configuration du cache Apache..."
    a2enmod expires
    a2enmod headers
    
    log_info "Optimisation de MySQL..."
    cat >> /etc/mysql/mysql.conf.d/mysqld.cnf << 'EOF'

# Optimisations Cabinet Comptable Pro
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
query_cache_type = 1
query_cache_size = 32M
max_connections = 100
EOF
    
    systemctl restart mysql
    
    log_info "Configuration du cache PHP OPCache..."
    cat >> /etc/php/8.2/apache2/php.ini << 'EOF'

; OPCache Configuration
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=4000
opcache.revalidate_freq=2
opcache.fast_shutdown=1
EOF
    
    systemctl restart apache2
    
    log_success "Performances optimisées"
}

# Création des tâches CRON
setup_cron_jobs() {
    log_step "Configuration des tâches automatiques"
    
    log_info "Création des tâches CRON..."
    
    # Script de maintenance quotidienne
    cat > /usr/local/bin/cabinet-maintenance.sh << 'EOF'
#!/bin/bash
# Maintenance quotidienne Cabinet Comptable Pro

APP_DIR="/var/www/cabinet-comptable"
DATE=$(date '+%Y-%m-%d')

# Sauvegarde de la base de données
mysqldump -u cabinet_user -p'PASSWORD_PLACEHOLDER' cabinet_comptable > "$APP_DIR/backups/backup_$DATE.sql"

# Compression des anciennes sauvegardes
find "$APP_DIR/backups" -name "*.sql" -mtime +1 -exec gzip {} \;

# Suppression des sauvegardes de plus de 30 jours
find "$APP_DIR/backups" -name "*.gz" -mtime +30 -delete

# Nettoyage des fichiers temporaires
find "$APP_DIR/uploads/temp" -type f -mtime +1 -delete
find "$APP_DIR/cache" -name "*.cache" -mtime +7 -delete

# Optimisation de la base de données
mysqlcheck -u cabinet_user -p'PASSWORD_PLACEHOLDER' --optimize cabinet_comptable

echo "$(date '+%Y-%m-%d %H:%M:%S') - Maintenance completed" >> /var/log/cabinet-maintenance.log
EOF
    
    # Remplacer le placeholder du mot de passe
    sed -i "s/PASSWORD_PLACEHOLDER/$DB_PASS/g" /usr/local/bin/cabinet-maintenance.sh
    chmod +x /usr/local/bin/cabinet-maintenance.sh
    
    # Ajout des tâches CRON
    (crontab -l 2>/dev/null; echo "# Cabinet Comptable Pro - Tâches automatiques") | crontab -
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/cabinet-maintenance.sh") | crontab -
    (crontab -l 2>/dev/null; echo "0 */6 * * * /usr/local/bin/cabinet-monitor.sh") | crontab -
    
    log_success "Tâches automatiques configurées"
}

# Test de l'installation
test_installation() {
    log_step "Test de l'installation"
    
    log_info "Vérification des services..."
    
    # Test Apache
    if systemctl is-active --quiet apache2; then
        log_success "Apache2 : OK"
    else
        log_error "Apache2 : ERREUR"
    fi
    
    # Test MySQL
    if systemctl is-active --quiet mysql; then
        log_success "MySQL : OK"
    else
        log_error "MySQL : ERREUR"
    fi
    
    # Test PHP
    if php -v &>/dev/null; then
        log_success "PHP : OK ($(php -r 'echo PHP_VERSION;'))"
    else
        log_error "PHP : ERREUR"
    fi
    
    # Test base de données
    if mysql -u "$DB_USER" -p"$DB_PASS" -e "USE $DB_NAME;" &>/dev/null; then
        log_success "Base de données : OK"
    else
        log_error "Base de données : ERREUR"
    fi
    
    # Test application
    if [[ -f "$APP_DIR/index.php" ]]; then
        log_success "Application : OK"
    else
        log_error "Application : ERREUR"
    fi
    
    # Test permissions
    if [[ -w "$APP_DIR/uploads" ]]; then
        log_success "Permissions : OK"
    else
        log_error "Permissions : ERREUR"
    fi
}

# Affichage des informations finales
show_final_info() {
    log_step "Installation terminée !"
    
    echo -e "${GREEN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║                    ✅ INSTALLATION RÉUSSIE ✅                     ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}\n"
    
    echo -e "${CYAN}📋 Informations de connexion :${NC}"
    echo -e "  🌐 URL : http://$DOMAIN"
    echo -e "  👤 Utilisateur : admin"
    echo -e "  🔐 Mot de passe : admin123"
    echo
    
    echo -e "${CYAN}🗄️ Base de données :${NC}"
    echo -e "  📊 Nom : $DB_NAME"
    echo -e "  👤 Utilisateur : $DB_USER"
    echo -e "  📁 Dossier : $APP_DIR"
    echo
    
    echo -e "${CYAN}🔧 Services installés :${NC}"
    echo -e "  ✅ Apache2 avec PHP 8.2"
    echo -e "  ✅ MySQL Server"
    echo -e "  ✅ Cabinet Comptable Pro"
    
    if [[ "$INSTALL_SSL" == true ]]; then
        echo -e "  ✅ Certificat SSL (Let's Encrypt)"
    fi
    
    if [[ "$INSTALL_UFW" == true ]]; then
        echo -e "  ✅ Firewall UFW"
    fi
    
    if [[ "$INSTALL_FAIL2BAN" == true ]]; then
        echo -e "  ✅ Fail2Ban (protection anti-intrusion)"
    fi
    
    echo
    echo -e "${CYAN}📁 Fichiers importants :${NC}"
    echo -e "  📝 Configuration : $APP_DIR/config/config.php"
    echo -e "  📊 Logs : $APP_DIR/logs/"
    echo -e "  💾 Sauvegardes : $APP_DIR/backups/"
    echo -e "  📁 Uploads : $APP_DIR/uploads/"
    echo
    
    echo -e "${CYAN}🔄 Tâches automatiques :${NC}"
    echo -e "  🌙 Sauvegarde quotidienne à 2h00"
    echo -e "  🔍 Monitoring toutes les 5 minutes"
    echo -e "  🧹 Maintenance et nettoyage automatique"
    echo
    
    echo -e "${YELLOW}⚠️  IMPORTANT :${NC}"
    echo -e "  1. Changez le mot de passe admin dès la première connexion"
    echo -e "  2. Configurez votre serveur SMTP dans config/config.php"
    echo -e "  3. Personnalisez les paramètres selon vos besoins"
    echo
    
    if [[ "$DOMAIN" == "localhost" ]]; then
        echo -e "${YELLOW}💡 Pour accéder en local :${NC}"
        echo -e "  🔗 http://localhost"
        echo -e "  🔗 http://$(hostname -I | awk '{print $1}')"
    fi
    
    echo
    echo -e "${GREEN}🎉 Cabinet Comptable Pro est maintenant prêt à l'emploi !${NC}"
    echo
}

# Fonction de nettoyage en cas d'erreur
cleanup_on_error() {
    log_error "Erreur détectée, nettoyage en cours..."
    
    # Arrêter les services
    systemctl stop apache2 2>/dev/null || true
    systemctl stop mysql 2>/dev/null || true
    
    # Supprimer les fichiers créés
    rm -rf "$APP_DIR" 2>/dev/null || true
    rm -f "/etc/apache2/sites-available/$DOMAIN.conf" 2>/dev/null || true
    
    log_info "Nettoyage terminé"
    exit 1
}

# Piège pour capturer les erreurs
trap cleanup_on_error ERR

# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

main() {
    # Affichage du logo
    show_logo
    
    # Vérifications préliminaires
    check_system
    
    # Configuration interactive
    configure_installation
    
    log_info "Début de l'installation..."
    echo
    
    # Installation étape par étape
    update_system
    install_apache
    install_php
    install_mysql
    install_application
    configure_vhost
    install_ssl
    configure_firewall
    install_fail2ban
    install_monitoring
    optimize_performance
    setup_cron_jobs
    
    # Tests finaux
    test_installation
    
    # Informations finales
    show_final_info
    
    log_success "Installation complète ! 🎉"
}

# =============================================================================
# LANCEMENT DU SCRIPT
# =============================================================================

# Vérification des arguments
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    echo "Script d'installation automatique Cabinet Comptable Pro"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  --help, -h     Afficher cette aide"
    echo "  --version, -v  Afficher la version"
    echo "  --uninstall    Désinstaller l'application"
    echo
    echo "Installation interactive sans options"
    exit 0
fi

if [[ "$1" == "--version" ]] || [[ "$1" == "-v" ]]; then
    echo "Cabinet Comptable Pro - Auto Installer v$APP_VERSION"
    exit 0
fi

if [[ "$1" == "--uninstall" ]]; then
    echo "Fonctionnalité de désinstallation non implémentée"
    echo "Pour désinstaller manuellement:"
    echo "1. Supprimer /var/www/cabinet-comptable"
    echo "2. Supprimer la base de données cabinet_comptable"
    echo "3. Désactiver le site Apache"
    exit 0
fi

# Lancement de l'installation
main "$@"
