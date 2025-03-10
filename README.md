# doc-webserver

# Apache HTTP Server Reference Card

## Basic Components and Configuration

### Installation
```bash
# Debian/Ubuntu
sudo apt install apache2

# RHEL/CentOS/Fedora
sudo dnf install httpd

# Windows
# Download from https://www.apachelounge.com/download/
```

### Service Management
```bash
# Debian/Ubuntu
sudo systemctl start apache2
sudo systemctl stop apache2
sudo systemctl restart apache2
sudo systemctl reload apache2
sudo systemctl status apache2

# RHEL/CentOS/Fedora
sudo systemctl start httpd
sudo systemctl stop httpd
sudo systemctl restart httpd
sudo systemctl reload httpd
sudo systemctl status httpd
```

### Core Files and Directories

| Distribution | Configuration Path | Main Config File | Document Root | Logs |
|--------------|-------------------|------------------|---------------|------|
| Debian/Ubuntu | `/etc/apache2/` | `apache2.conf` | `/var/www/html/` | `/var/log/apache2/` |
| RHEL/CentOS | `/etc/httpd/` | `httpd.conf` | `/var/www/html/` | `/var/log/httpd/` |

### Basic Configuration Directives

```apache
# Server information
ServerName example.com
ServerAdmin admin@example.com
ServerRoot /etc/apache2

# Ports to listen on
Listen 80
Listen 443

# Document root configuration
DocumentRoot "/var/www/html"
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>

# Default file to serve
DirectoryIndex index.html index.php

# Logging configuration
ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined
LogLevel warn
```

## Virtual Hosts

### Name-based Virtual Hosts
```apache
<VirtualHost *:80>
    ServerName www.example.com
    ServerAlias example.com
    DocumentRoot /var/www/example.com
    ErrorLog ${APACHE_LOG_DIR}/example.com-error.log
    CustomLog ${APACHE_LOG_DIR}/example.com-access.log combined
</VirtualHost>
```

### IP-based Virtual Hosts
```apache
<VirtualHost 192.168.1.10:80>
    ServerName www.example.com
    DocumentRoot /var/www/example.com
</VirtualHost>

<VirtualHost 192.168.1.11:80>
    ServerName www.example.org
    DocumentRoot /var/www/example.org
</VirtualHost>
```

### SSL Virtual Host
```apache
<VirtualHost *:443>
    ServerName www.example.com
    DocumentRoot /var/www/example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key
    SSLCertificateChainFile /etc/ssl/certs/chain.crt
</VirtualHost>
```

## Modules and Extensions

### Essential Modules

| Module | Description | Configuration Example |
|--------|-------------|------------------------|
| `mod_ssl` | SSL/TLS support | `a2enmod ssl` |
| `mod_rewrite` | URL rewriting | `RewriteEngine On` |
| `mod_proxy` | Proxy/gateway | `ProxyPass /app http://localhost:8080/app` |
| `mod_headers` | HTTP header manipulation | `Header set X-Frame-Options "SAMEORIGIN"` |
| `mod_expires` | Content expiration | `ExpiresActive On` |
| `mod_deflate` | Content compression | `AddOutputFilterByType DEFLATE text/html` |
| `mod_security` | Web application firewall | Requires separate config file |

### Module Management

```bash
# Debian/Ubuntu
sudo a2enmod module_name
sudo a2dismod module_name

# RHEL/CentOS/Fedora (edit httpd.conf)
LoadModule module_name_module modules/mod_module_name.so
```

## Advanced Configuration

### URL Rewriting with mod_rewrite

```apache
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    
    # Redirect non-www to www
    RewriteCond %{HTTP_HOST} ^example\.com [NC]
    RewriteRule ^(.*)$ http://www.example.com/$1 [L,R=301]
    
    # Redirect HTTP to HTTPS
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
    
    # Pretty URLs for a CMS/framework
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^(.*)$ index.php?route=$1 [L,QSA]
</IfModule>
```

### Reverse Proxy Configuration

```apache
<IfModule mod_proxy.c>
    ProxyRequests Off
    ProxyPreserveHost On
    
    # Simple reverse proxy
    ProxyPass /app http://localhost:8080/app
    ProxyPassReverse /app http://localhost:8080/app
    
    # Load balancing
    <Proxy balancer://mycluster>
        BalancerMember http://app1.example.com:8080
        BalancerMember http://app2.example.com:8080
        ProxySet lbmethod=byrequests
    </Proxy>
    ProxyPass "/app" "balancer://mycluster"
</IfModule>
```

### Content Caching

```apache
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresDefault "access plus 1 month"
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/gif "access plus 1 year"
    ExpiresByType application/pdf "access plus 1 month"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType text/javascript "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>

<IfModule mod_headers.c>
    <FilesMatch "\.(ico|jpg|jpeg|png|gif|css|js)$">
        Header set Cache-Control "max-age=2592000, public"
    </FilesMatch>
</IfModule>
```

### Content Compression

```apache
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
    
    # Older browsers
    BrowserMatch ^Mozilla/4 gzip-only-text/html
    BrowserMatch ^Mozilla/4\.0[678] no-gzip
    BrowserMatch \bMSIE !no-gzip !gzip-only-text/html
</IfModule>
```

### Basic Authentication

```apache
<Directory "/var/www/protected">
    AuthType Basic
    AuthName "Restricted Area"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>
```

Create password file:
```bash
sudo htpasswd -c /etc/apache2/.htpasswd username
```

### Access Control

```apache
# Allow from specific IPs/networks
<Directory "/var/www/admin">
    Require ip 192.168.1.0/24
    Require ip 10.0.0.5
</Directory>

# Deny access to sensitive files
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# Control by environment variable
SetEnvIf User-Agent "BadBot" bad_bot
<Directory "/var/www/html">
    Require all granted
    Require not env bad_bot
</Directory>
```

## Performance Tuning

### MPM Configuration (prefork)

```apache
<IfModule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers         10
    MaxRequestWorkers      150
    MaxConnectionsPerChild   0
</IfModule>
```

### MPM Configuration (worker)

```apache
<IfModule mpm_worker_module>
    StartServers             3
    MinSpareThreads         25
    MaxSpareThreads         75
    ThreadLimit             64
    ThreadsPerChild         25
    MaxRequestWorkers      400
    MaxConnectionsPerChild   0
</IfModule>
```

### MPM Configuration (event)

```apache
<IfModule mpm_event_module>
    StartServers             3
    MinSpareThreads         25
    MaxSpareThreads         75
    ThreadLimit             64
    ThreadsPerChild         25
    MaxRequestWorkers      400
    MaxConnectionsPerChild   0
</IfModule>
```

### Keepalive Settings

```apache
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
```

## Security Best Practices

### Hide Server Information

```apache
ServerTokens Prod
ServerSignature Off
```

### Disable Directory Indexing

```apache
Options -Indexes
```

### HTTPS Configuration

```apache
<IfModule mod_ssl.c>
    # Modern configuration (TLS 1.2+ only)
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder on
    SSLCompression off
    SSLSessionTickets off
    
    # Strong cipher suite
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    
    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
    SSLStaplingResponseMaxAge 86400
</IfModule>
```

### Security Headers

```apache
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
```

### Prevent Access to .git and Other Sensitive Directories

```apache
<DirectoryMatch "^/.*/\.git/">
    Require all denied
</DirectoryMatch>

<DirectoryMatch "^/.*/\.env">
    Require all denied
</DirectoryMatch>
```

## Troubleshooting

### Common Log Locations

- Access log: `/var/log/apache2/access.log` or `/var/log/httpd/access_log`
- Error log: `/var/log/apache2/error.log` or `/var/log/httpd/error_log`

### Debugging Tools

```bash
# Check configuration syntax
apache2ctl -t
apachectl -t

# Show compiled modules
apache2ctl -M
apachectl -M

# Check virtual hosts
apache2ctl -S
apachectl -S

# Check process status
apache2ctl status
apachectl status
```

### Common Issues and Solutions

1. **HTTP 403 Forbidden**
   - Check directory permissions (should be 755)
   - Check file permissions (should be 644)
   - Check SELinux context (if applicable)
   - Verify correct `Require` directives

2. **HTTP 500 Internal Server Error**
   - Check error logs for specific errors
   - Verify PHP/application configuration
   - Check file ownership and permissions

3. **Performance Issues**
   - Adjust MPM settings
   - Enable caching and compression
   - Consider using a CDN for static content
   - Optimize database queries (if applicable)

4. **SSL Certificate Problems**
   - Verify certificate chain is complete
   - Check certificate expiration date
   - Ensure private key matches certificate


# Nginx Complete Reference Card

## Table of Contents
1. [Basics](#basics)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [Configuration Structure](#configuration-structure)
5. [Server Blocks](#server-blocks)
6. [Location Blocks](#location-blocks)
7. [SSL/TLS Configuration](#ssltls-configuration)
8. [Load Balancing](#load-balancing)
9. [Caching](#caching)
10. [Reverse Proxy](#reverse-proxy)
11. [HTTP/2 & HTTP/3](#http2--http3)
12. [Security Best Practices](#security-best-practices)
13. [Performance Optimization](#performance-optimization)
14. [Rate Limiting](#rate-limiting)
15. [Logging](#logging)
16. [Monitoring](#monitoring)
17. [Troubleshooting](#troubleshooting)
18. [Advanced Examples](#advanced-examples)

## Basics

### What is Nginx?
Nginx (pronounced "engine x") is a high-performance HTTP server, reverse proxy, and load balancer designed for high concurrency and performance.

### Key Features
- Event-driven, asynchronous architecture
- High concurrency with low memory footprint
- Reverse proxy with caching
- Load balancing
- FastCGI support
- WebSockets support
- HTTP/2 and HTTP/3 (QUIC) support

## Installation

### Debian/Ubuntu
```bash
sudo apt update
sudo apt install nginx
```

### CentOS/RHEL
```bash
sudo yum install epel-release
sudo yum install nginx
```

### Alpine
```bash
apk add nginx
```

### From Source
```bash
wget https://nginx.org/download/nginx-1.24.0.tar.gz
tar zxf nginx-1.24.0.tar.gz
cd nginx-1.24.0
./configure --prefix=/usr/local/nginx
make
sudo make install
```

## Core Concepts

### Main Processes
- **Master Process**: Reads config, manages worker processes
- **Worker Processes**: Handle the actual request processing

### Key Directories
- **/etc/nginx/**: Configuration files
- **/etc/nginx/nginx.conf**: Main configuration
- **/etc/nginx/sites-available/**: Site configs
- **/etc/nginx/sites-enabled/**: Enabled site configs (symlinks)
- **/var/log/nginx/**: Log files
- **/var/www/html/**: Default document root

### Basic Commands
```bash
# Start nginx
sudo systemctl start nginx

# Stop nginx
sudo systemctl stop nginx

# Reload configuration without downtime
sudo nginx -s reload

# Test configuration syntax
sudo nginx -t

# Show version and build info
nginx -v

# Show detailed version and config info
nginx -V
```

## Configuration Structure

### Main Config File Structure
```nginx
# Main context
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    # Events context
    worker_connections 1024;
    multi_accept on;
}

http {
    # HTTP context
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Global settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    # Include other configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    
    # Server blocks go here or in included files
    server {
        # Server context
        # ...
    }
}

stream {
    # TCP/UDP load balancing context
    # ...
}
```

### Directive Types
- **Simple directives**: End with semicolon (`;`)
- **Block directives**: Enclosed in curly braces (`{}`)

### Context Hierarchy
1. Main (global) context
2. Events, HTTP, Mail, Stream contexts
3. Server context
4. Location context

## Server Blocks

### Basic Server Block
```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    
    root /var/www/example.com;
    index index.html index.htm index.php;
    
    # Default location block
    location / {
        try_files $uri $uri/ =404;
    }
}
```

### Multiple Server Blocks (Virtual Hosts)
```nginx
# First virtual host
server {
    listen 80;
    server_name site1.example.com;
    root /var/www/site1;
    # ...
}

# Second virtual host
server {
    listen 80;
    server_name site2.example.com;
    root /var/www/site2;
    # ...
}
```

### Default Server
```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    # ...
}
```

## Location Blocks

### Location Matching Types
```nginx
# Exact match
location = /exact/path {
    # ...
}

# Preferential prefix match
location ^~ /images/ {
    # ...
}

# Regex match (case sensitive)
location ~ \.php$ {
    # ...
}

# Regex match (case insensitive)
location ~* \.(jpg|jpeg|png|gif)$ {
    # ...
}

# Prefix match (lowest priority)
location /docs/ {
    # ...
}

# Default fallback location
location / {
    try_files $uri $uri/ /index.php?$args;
}
```

### Location Priorities (highest to lowest)
1. `=` exact match
2. `^~` preferential prefix match
3. `~` or `~*` regex match (first matching regex wins)
4. Prefix match (longest match wins)

### Try Files Directive
```nginx
location / {
    try_files $uri $uri/ /index.php?$query_string;
}
```

### Nested Locations
```nginx
location /api/ {
    # API-specific settings
    
    location ~ \.php$ {
        # Handle PHP files within API
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
```

## SSL/TLS Configuration

### Basic SSL Setup
```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    
    # ...
}
```

### Redirect HTTP to HTTPS
```nginx
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

### Modern SSL Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    
    # Modern SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # SSL Session caching
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # ...
}
```

### Let's Encrypt Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    
    # For certificate renewal
    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }
    
    # ...
}
```

## Load Balancing

### Basic HTTP Load Balancing
```nginx
upstream backend {
    server backend1.example.com weight=3;
    server backend2.example.com;
    server backend3.example.com backup;
}

server {
    listen 80;
    server_name example.com;
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Load Balancing Methods
```nginx
upstream backend {
    # Round Robin (default)
    server backend1.example.com;
    server backend2.example.com;
    
    # Least connections
    least_conn;
    
    # IP Hash (session persistence)
    ip_hash;
    
    # Generic Hash
    hash $request_uri consistent;
    
    # Least time (requires NGINX Plus)
    # least_time header;
}
```

### Advanced Load Balancer Options
```nginx
upstream backend {
    server backend1.example.com max_fails=3 fail_timeout=30s;
    server backend2.example.com max_conns=1000;
    server unix:/var/run/backend3.sock;
    
    keepalive 32;
    queue 100 timeout=70;
}
```

### TCP/UDP Load Balancing
```nginx
stream {
    upstream mysql_backend {
        server db1.example.com:3306 weight=5;
        server db2.example.com:3306;
        least_conn;
    }
    
    server {
        listen 3306;
        proxy_pass mysql_backend;
    }
}
```

## Caching

### Basic Cache Configuration
```nginx
http {
    # Cache configuration
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m inactive=60m max_size=1g;
    
    server {
        # ...
        
        location / {
            proxy_cache my_cache;
            proxy_cache_valid 200 302 10m;
            proxy_cache_valid 404 1m;
            proxy_pass http://backend;
        }
    }
}
```

### Cache Control Headers
```nginx
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 30d;
    add_header Cache-Control "public, no-transform";
}

location / {
    proxy_cache my_cache;
    proxy_cache_bypass $http_cache_control;
    add_header X-Cache-Status $upstream_cache_status;
    
    # Don't cache if client sends these headers
    proxy_no_cache $http_pragma $http_authorization;
    
    # ...
}
```

### Conditional Caching
```nginx
map $request_method $no_cache {
    default 0;
    POST    1;
    PUT     1;
    DELETE  1;
}

server {
    # ...
    
    location / {
        proxy_cache my_cache;
        proxy_cache_bypass $no_cache;
        proxy_no_cache $no_cache;
        # ...
    }
}
```

### Microcaching
```nginx
http {
    proxy_cache_path /var/cache/nginx/microcache levels=1:2 keys_zone=microcache:10m max_size=500m inactive=60m;
    
    server {
        # ...
        
        location / {
            proxy_cache microcache;
            proxy_cache_valid 200 1s;
            proxy_cache_key "$scheme$request_method$host$request_uri";
            proxy_cache_methods GET HEAD;
            proxy_cache_bypass $http_pragma;
            proxy_pass http://backend;
        }
    }
}
```

## Reverse Proxy

### Basic Proxy Setup
```nginx
server {
    listen 80;
    server_name app.example.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Proxy Multiple Applications
```nginx
server {
    listen 80;
    server_name example.com;
    
    # Frontend application
    location / {
        proxy_pass http://localhost:3000;
        # proxy headers...
    }
    
    # API requests
    location /api/ {
        proxy_pass http://localhost:8080/;  # Note: trailing slash removes /api
        # proxy headers...
    }
    
    # Admin panel
    location /admin {
        proxy_pass http://localhost:4000;
        # proxy headers...
    }
}
```

### WebSockets Proxy
```nginx
server {
    # ...
    
    location /ws/ {
        proxy_pass http://websocket_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### FastCGI Proxy (PHP-FPM)
```nginx
server {
    listen 80;
    server_name example.com;
    root /var/www/example.com;
    
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        # or fastcgi_pass 127.0.0.1:9000;
        fastcgi_index index.php;
    }
}
```

### Buffering and Timeouts
```nginx
location /api/ {
    proxy_pass http://backend;
    
    # Buffering settings
    proxy_buffering on;
    proxy_buffer_size 8k;
    proxy_buffers 8 32k;
    proxy_busy_buffers_size 64k;
    
    # Timeout settings
    proxy_connect_timeout 60s;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
}
```

## HTTP/2 & HTTP/3

### HTTP/2 Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    
    # Other SSL settings...
    
    http2_max_field_size 16k;
    http2_max_header_size 32k;
    http2_max_requests 1000;
    
    # ...
}
```

### HTTP/3 (QUIC) Configuration
```nginx
# Requires nginx compiled with --with-http_v3_module
server {
    listen 443 ssl http2;
    listen 443 quic reuseport;  # UDP listener for QUIC+HTTP/3
    
    server_name example.com;
    
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    
    # HTTP/3 specific
    quic_retry on;
    ssl_early_data on;
    
    # Add Alt-Svc header to inform clients of HTTP/3 support
    add_header Alt-Svc 'h3=":443"; ma=86400';
    
    # ...
}
```

## Security Best Practices

### Security Headers
```nginx
server {
    # ...
    
    # Security Headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://trusted-cdn.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self';" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()" always;
    
    # HSTS (only on HTTPS)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

### Prevent Information Disclosure
```nginx
# In http context
server_tokens off;
fastcgi_hide_header X-Powered-By;
proxy_hide_header X-Powered-By;
proxy_hide_header X-AspNet-Version;
```

### Access Restrictions
```nginx
# IP restriction
location /admin/ {
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
    
    # ...
}

# Basic auth
location /protected/ {
    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    # ...
}
```

### DoS Protection
```nginx
# Limit req module
http {
    limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
    
    server {
        # ...
        
        location /login/ {
            limit_req zone=one burst=5 nodelay;
            # ...
        }
    }
}

# Connection limits
http {
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    
    server {
        # ...
        
        location / {
            limit_conn conn_limit_per_ip 10;
            # ...
        }
    }
}
```

### Block Bad User Agents and Referrers
```nginx
# Block bad bots
map $http_user_agent $bad_bot {
    default 0;
    ~*crawl|~*bot|~*spider|~*scanner 1;
    ~*tracker|~*harvester|~*grabber 1;
}

# Block unwanted referrers
map $http_referer $bad_referer {
    default 0;
    ~*spam\.com|~*malware\.org 1;
}

server {
    # ...
    
    if ($bad_bot = 1) {
        return 444;
    }
    
    if ($bad_referer = 1) {
        return 403;
    }
}
```

## Performance Optimization

### Worker Process Configuration
```nginx
# Auto-detect CPU cores
worker_processes auto;

# Optimized worker connections
events {
    worker_connections 10240;
    multi_accept on;
    use epoll;
}
```

### Buffer Optimization
```nginx
http {
    # Buffers
    client_body_buffer_size 10K;
    client_header_buffer_size 1k;
    client_max_body_size 8m;
    large_client_header_buffers 2 1k;
    
    # Connection optimization
    keepalive_timeout 65;
    keepalive_requests 100;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    
    # ...
}
```

### File I/O Optimization
```nginx
http {
    sendfile on;
    sendfile_max_chunk 512k;
    tcp_nopush on;  # Optimize full TCP packets
    tcp_nodelay on; # Reduce latency for small packets
    
    # Optimize aio on Linux
    aio threads;
    directio 512;   # For files larger than 512 bytes
    
    # Optimized open_file_cache
    open_file_cache max=1000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
}
```

### Gzip Compression
```nginx
http {
    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_min_length 256;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/wasm
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/css
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;
}
```

### Brotli Compression (if module installed)
```nginx
http {
    brotli on;
    brotli_comp_level 6;
    brotli_static on;
    brotli_types
        application/atom+xml
        application/javascript
        application/json
        application/rss+xml
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/svg+xml
        image/x-icon
        text/css
        text/plain
        text/x-component;
}
```

### Static File Serving
```nginx
server {
    # ...
    
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2|ttf|svg|eot)$ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
        access_log off;
        tcp_nodelay off;
        
        # Enable sendfile for better performance
        sendfile on;
    }
}
```

## Rate Limiting

### Basic Rate Limiting
```nginx
http {
    # Define limit zone
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
    
    server {
        # ...
        
        location / {
            # Apply rate limiting
            limit_req zone=mylimit burst=20 nodelay;
            
            # ...
        }
    }
}
```

### Different Limits for Different Locations
```nginx
http {
    # API limit zone (strict)
    limit_req_zone $binary_remote_addr zone=apilimit:10m rate=5r/s;
    
    # General limit zone (more lenient)
    limit_req_zone $binary_remote_addr zone=generallimit:10m rate=20r/s;
    
    server {
        # API endpoints
        location /api/ {
            limit_req zone=apilimit burst=10 nodelay;
            # ...
        }
        
        # Static files
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            limit_req zone=generallimit burst=100;
            # ...
        }
    }
}
```

### Connection Limits
```nginx
http {
    # Limit connections per IP
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Limit connections per server
    limit_conn_zone $server_name zone=perserver:10m;
    
    server {
        # ...
        
        location / {
            limit_conn addr 10;      # Max 10 connections per IP
            limit_conn perserver 100; # Max 100 total connections to server
            
            # ...
        }
    }
}
```

### Custom Response for Rate Limiting
```nginx
http {
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
    
    # Custom error page for rate limiting
    server {
        # ...
        
        error_page 429 /rate_limit.html;
        
        location = /rate_limit.html {
            root /var/www/html;
            internal;
        }
        
        location / {
            limit_req zone=mylimit burst=20 nodelay;
            limit_req_status 429;  # Return 429 instead of default 503
            
            # ...
        }
    }
}
```

## Logging

### Basic Logging
```nginx
http {
    # Log formats
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    log_format detailed '$remote_addr - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent" '
                         '$request_time $upstream_response_time $pipe';
    
    # Access log
    access_log /var/log/nginx/access.log main;
    
    # Error log
    error_log /var/log/nginx/error.log warn;
    
    server {
        # Server-specific logs
        access_log /var/log/nginx/example.com.access.log detailed;
        error_log /var/log/nginx/example.com.error.log;
        
        # ...
    }
}
```

### JSON Logging
```nginx
http {
    log_format json_combined escape=json
        '{'
        '"time_local":"$time_local",'
        '"remote_addr":"$remote_addr",'
        '"remote_user":"$remote_user",'
        '"request":"$request",'
        '"status": "$status",'
        '"body_bytes_sent":"$body_bytes_sent",'
        '"request_time":"$request_time",'
        '"http_referrer":"$http_referer",'
        '"http_user_agent":"$http_user_agent"'
        '}';
    
    access_log /var/log/nginx/access.log json_combined;
    
    # ...
}
```

### Conditional Logging
```nginx
http {
    map $status $loggable {
        ~^[23]  0;  # Don't log 2xx and 3xx
        default 1;  # Log other status codes
    }
    
    server {
        # ...
        
        access_log /var/log/nginx/example.com.access.log main if=$loggable;
        
        # Don't log requests for static files
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            access_log off;
            # ...
        }
    }
}
```

### Log Rotation
Using logrotate (/etc/logrotate.d/nginx):
```
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ ! -f /var/run/nginx.pid ] || kill -USR1 `cat /var/run/nginx.pid`
    endscript
}
```

## Monitoring

### Stub Status Module
```nginx
server {
    # ...
    
    # Restricted access to status page
    location /nginx_status {
        stub_status on;
        allow 127.0.0.1;
        allow 192.168.1.0/24;
        deny all;
    }
}
```

### Custom Metrics
```nginx
location = /metrics {
    allow 127.0.0.1;
    allow 192.168.1.0/24;
    deny all;
    
    default_type text/plain;
    return 200 "nginx_up 1\nnginx_requests $connection_requests\nnginx_connections_active $connections_active\n";
}
```

### HTTP Response Time
```nginx
log_format perf '$remote_addr - $remote_user [$time_local] '
                '"$request" $status $body_bytes_sent '
                '"$http_referer" "$http_user_agent" '
                '$request_time $upstream_connect_time $upstream_header_time $upstream_response_time';

server {
    # ...
    access_log /var/log/nginx/perf.log perf;
}
```

## Troubleshooting

### Common Debug Techniques
```bash
# Test configuration syntax
nginx -t

# Dump configuration
nginx -T

# Increase log verbosity
error_log /var/log/nginx/error.log debug;

# Check open files and connections
lsof -p `pidof nginx`

# Check connections
netstat -tuln | grep nginx

# Watch log in real-time
tail -f /var/log/nginx/error.log

# Check for SELinux issues
audit2allow -a
```

### Common Issues and Solutions
```nginx
# 413 Request Entity Too Large
client_max_body_size 100M;

# 504 Gateway Timeout
proxy_connect_timeout 75s;
proxy_read_timeout 300s;
proxy_send_timeout 300s;

# 502 Bad Gateway
fastcgi_buffer_size 32k;
fastcgi_buffers 16 32k;
fastcgi_busy_buffers_size 64k;

# Fix for "upstream sent too big header"
fastcgi_buffer_size 32k;
proxy_buffer_size 128k;
proxy_buffers 4 256k;
proxy_busy_buffers_size 256k;
```

## Advanced Examples

### Complete HTTPS Server with HTTP/2, Optimizations, and Security
```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;
    root /var/www/example.
```



# Deploying a Streamlit Web App with Docker on Ubuntu

Here's a step-by-step guide to deploy your Streamlit application in production mode using Docker on an Ubuntu server:

## 1. Set up your Ubuntu server

First, update your server:
```bash
sudo apt-get update
sudo apt-get upgrade -y
```

## 2. Install Docker

Install Docker on your Ubuntu server:
```bash
sudo apt-get install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io
```

Verify Docker is running:
```bash
sudo systemctl status docker
```

Add your user to the docker group (optional, for convenience):
```bash
sudo usermod -aG docker $USER
```
Log out and back in for this to take effect.

## 3. Prepare your Streamlit application

Create a directory for your project:
```bash
mkdir -p ~/streamlit-app
cd ~/streamlit-app
```

## 4. Create a Dockerfile

Create a Dockerfile in your project directory:
```bash
nano Dockerfile
```

Add the following content:
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

# Use this for production mode
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.enableCORS=false", "--server.enableXsrfProtection=false", "--server.enableWebsocketCompression=false"]
```

## 5. Create requirements.txt

Create a requirements.txt file with your dependencies:
```bash
nano requirements.txt
```

At minimum, include:
```
streamlit==1.22.0
```
Add other dependencies your app needs.

## 6. Add your Streamlit app files

Create your main streamlit app file (app.py) and any other needed files in this directory.

## 7. Build and run your Docker container

Build the Docker image:
```bash
docker build -t streamlit-app .
```

Run the container:
```bash
docker run -d -p 8501:8501 --name streamlit-app streamlit-app
```

Your Streamlit app should now be running at http://your-server-ip:8501

## 8. Additional production considerations

### Set up Nginx as a reverse proxy (recommended)

Install Nginx:
```bash
sudo apt-get install nginx
```

Create a Nginx configuration:
```bash
sudo nano /etc/nginx/sites-available/streamlit
```

Add the following content:
```
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

We can enforce SSL encryption by using the following changes

```nginx
server {
    listen 80;
    server_name streamlit.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name streamlit.yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/streamlit.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/streamlit.yourdomain.com/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Streamlit specific settings
    location / {
        proxy_pass http://localhost:8501/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/streamlit /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx
```

### Set up SSL with Let's Encrypt

Install Certbot:
```bash
sudo apt-get install certbot python3-certbot-nginx
```

Obtain SSL certificate:
```bash
sudo certbot --nginx -d your-domain.com
```

### Docker Compose (optional)

For more complex setups, create a docker-compose.yml file:
```yaml
version: '3'
services:
  streamlit:
    build: .
    ports:
      - "8501:8501"
    restart: always
```

Run with:
```bash
docker-compose up -d
```

Does this cover what you need for your deployment, or would you like more details on any specific aspect?




# Configuring Multiple Top-Level Domains with Docker Apps

If you want to use entirely different domains (e.g., `domain-one.com` and `domain-two.com`) for different applications, the approach is similar to using subdomains, but with some key differences. Here's how to set it up:

## Step 1: DNS Configuration

Configure each domain to point to your server's IP address:
- `domain-one.com` → Your server IP
- `domain-two.com` → Your server IP
- `domain-three.com` → Your server IP (if you have a third app)

## Step 2: Obtain SSL Certificates for Each Domain

Get certificates for each domain separately:

```bash
sudo certbot --nginx -d domain-one.com
sudo certbot --nginx -d domain-two.com
sudo certbot --nginx -d domain-three.com
```

## Step 3: Create Separate Nginx Server Blocks

Create a separate configuration file for each domain:

### For Streamlit (`/etc/nginx/sites-available/domain-one`):

```nginx
server {
    listen 80;
    server_name domain-one.com www.domain-one.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name domain-one.com www.domain-one.com;
    
    ssl_certificate /etc/letsencrypt/live/domain-one.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain-one.com/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Streamlit app
    location / {
        proxy_pass http://localhost:8501/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### For Shiny (`/etc/nginx/sites-available/domain-two`):

```nginx
server {
    listen 80;
    server_name domain-two.com www.domain-two.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name domain-two.com www.domain-two.com;
    
    ssl_certificate /etc/letsencrypt/live/domain-two.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain-two.com/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Shiny app
    location / {
        proxy_pass http://localhost:3838/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
    }
}
```

### For Django (`/etc/nginx/sites-available/domain-three`):

```nginx
server {
    listen 80;
    server_name domain-three.com www.domain-three.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name domain-three.com www.domain-three.com;
    
    ssl_certificate /etc/letsencrypt/live/domain-three.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain-three.com/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Django app
    location / {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Serve Django static files (if needed)
    location /static/ {
        alias /path/to/your/django/static/;
    }
}
```

## Step 4: Enable the New Configurations

```bash
sudo ln -s /etc/nginx/sites-available/domain-one /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/domain-two /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/domain-three /etc/nginx/sites-enabled/

# Remove any old configurations
sudo rm -f /etc/nginx/sites-enabled/default
sudo rm -f /etc/nginx/sites-enabled/multi-app

# Test and reload Nginx
sudo nginx -t
sudo systemctl restart nginx
```

## Step 5: Update Application Configurations

### For Django:
Update `settings.py` to recognize the new domain:

```python
ALLOWED_HOSTS = ['domain-three.com', 'www.domain-three.com']
CSRF_TRUSTED_ORIGINS = ['https://domain-three.com', 'https://www.domain-three.com']
```

### For Streamlit (if needed):
If you're using custom base URLs, you might need to update the Streamlit configuration.

## Step 6: Docker Compose Configuration

Your `docker-compose.yml` remains largely the same, but you can add labels for documentation:

```yaml
version: '3'

services:
  streamlit:
    build: ./streamlit-app
    ports:
      - "8501:8501"
    restart: always
    container_name: streamlit-app
    labels:
      - "app.domain=domain-one.com"

  shiny:
    build: ./shiny-app
    ports:
      - "3838:3838"
    restart: always
    container_name: shiny-app
    labels:
      - "app.domain=domain-two.com"

  django:
    build: ./django-app
    ports:
      - "8000:8000"
    restart: always
    container_name: django-app
    labels:
      - "app.domain=domain-three.com"
```

## Additional Considerations

1. **DNS Management**: If all domains are registered through the same provider, you can manage them together. Otherwise, you'll need to update each domain's DNS settings separately.

2. **Certificate Renewal**: Ensure Let's Encrypt can renew all certificates. The standard certbot cron job will handle this automatically.

3. **SEO and Branding**: Using separate domains works well if the applications serve completely different purposes or brands.

4. **Shared Services**: If your apps need to share backend services, you may need to configure cross-origin resource sharing (CORS).

5. **Domain Redirects**: You might want to set up domain redirects (e.g., redirect `www.domain-one.com` to `domain-one.com`) for consistency.

Each application will now be accessible on its own dedicated domain with SSL encryption:
- Streamlit: `https://domain-one.com`
- Shiny: `https://domain-two.com`
- Django: `https://domain-three.com`


    
