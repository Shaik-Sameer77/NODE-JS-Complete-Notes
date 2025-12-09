# Node.js Deployment: Comprehensive Guide

## 📚 Table of Contents
1. [Deploy to AWS EC2](#1-deploy-to-aws-ec2)
2. [Dockerize Node.js](#2-dockerize-nodejs)
3. [Using PM2](#3-using-pm2)
4. [Nginx Reverse Proxy](#4-nginx-reverse-proxy)
5. [SSL Certificates](#5-ssl-certificates)
6. [Environment Variable Setup](#6-environment-variable-setup)
7. [CI/CD with GitHub Actions](#7-cicd-with-github-actions)
8. [Railway / Render / Fly.io](#8-railway--render--flyio)

---

## 1. Deploy to AWS EC2

### 📖 In-Depth Explanation

AWS EC2 (Elastic Compute Cloud) provides scalable virtual servers in the cloud. It's ideal for deploying Node.js applications with full control over the environment.

#### **Infrastructure as Code with Terraform**

```hcl
# infrastructure/main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Security Group
resource "aws_security_group" "node_app" {
  name        = "node-app-sg"
  description = "Security group for Node.js application"

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.my_ip}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "node-app-sg"
  }
}

# EC2 Instance
resource "aws_instance" "node_app" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  key_name               = aws_key_pair.deployer.key_name
  vpc_security_group_ids = [aws_security_group.node_app.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  user_data              = filebase64("${path.module}/user-data.sh")

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name        = "node-production-app"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Elastic IP
resource "aws_eip" "node_app" {
  instance = aws_instance.node_app.id
  domain   = "vpc"

  tags = {
    Name = "node-app-eip"
  }
}

# Outputs
output "public_ip" {
  value = aws_eip.node_app.public_ip
}

output "instance_id" {
  value = aws_instance.node_app.id
}
```

#### **User Data Script for EC2 Initialization**

```bash
#!/bin/bash
# user-data.sh

# Update system
apt-get update -y
apt-get upgrade -y

# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Install PM2 globally
npm install -g pm2

# Install Nginx
apt-get install -y nginx

# Install Certbot for SSL
apt-get install -y certbot python3-certbot-nginx

# Install AWS CLI for secrets management
apt-get install -y awscli

# Create application directory
mkdir -p /var/www/node-app
chown -R ubuntu:ubuntu /var/www/node-app

# Set up systemd service for PM2
pm2 startup systemd -u ubuntu --hp /home/ubuntu

# Clone application (or use deployment script)
git clone https://github.com/your-org/node-app.git /var/www/node-app

# Install dependencies
cd /var/www/node-app
npm ci --only=production

# Set environment variables
echo "NODE_ENV=production" >> /etc/environment
echo "PORT=3000" >> /etc/environment

# Create .env file from AWS Secrets Manager
aws secretsmanager get-secret-value \
  --secret-id production/node-app/env \
  --query SecretString \
  --output text > /var/www/node-app/.env

# Start application with PM2
cd /var/www/node-app
pm2 start ecosystem.config.js
pm2 save

# Configure log rotation
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 30
pm2 set pm2-logrotate:compress true

# Enable firewall
ufw allow ssh
ufw allow 'Nginx Full'
ufw --force enable
```

#### **Application Directory Structure on EC2**

```
/var/www/node-app/
├── src/
│   ├── app.js
│   ├── routes/
│   └── middleware/
├── package.json
├── ecosystem.config.js
├── .env
├── logs/
│   ├── app-error.log
│   └── app-out.log
└── scripts/
    ├── deploy.sh
    ├── backup.sh
    └── health-check.sh
```

#### **Monitoring and Maintenance Scripts**

```bash
#!/bin/bash
# scripts/health-check.sh

# Health check endpoint
response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)

if [ $response -ne 200 ]; then
    echo "Health check failed with status: $response"
    
    # Restart application
    pm2 restart all
    
    # Send alert
    aws sns publish \
        --topic-arn arn:aws:sns:us-east-1:123456789012:alerts \
        --subject "Node.js App Restarted" \
        --message "Application was restarted due to failed health check"
    
    exit 1
fi

echo "Health check passed"
```

```bash
#!/bin/bash
# scripts/backup.sh

# Database backup
BACKUP_DIR="/var/backups/node-app"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup_$DATE.tar.gz"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup application files
tar -czf $BACKUP_FILE \
    --exclude='node_modules' \
    --exclude='*.log' \
    /var/www/node-app

# Upload to S3
aws s3 cp $BACKUP_FILE s3://my-backup-bucket/node-app/

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -type f -mtime +7 -delete

# Log rotation for application logs
find /var/www/node-app/logs -name "*.log" -mtime +30 -delete
```

### 🎯 Real-World Scenario: E-commerce Application Deployment
*You're deploying a high-traffic e-commerce application to AWS EC2. The application needs to handle 10,000 concurrent users during flash sales, maintain 99.9% uptime, and securely handle payment processing.*

**Interview Questions:**
1. How would you design the EC2 architecture for high availability?
2. What instance types would you choose and why?
3. How do you handle database connections and connection pooling?
4. What strategies would you implement for zero-downtime deployments?
5. How do you monitor and auto-scale based on traffic patterns?

**Technical Questions:**
1. How do you configure instance metadata service (IMDSv2) for security?
2. What are spot instances and when would you use them?
3. How do you implement instance refresh with Auto Scaling Groups?
4. What's the difference between EBS and instance store volumes?

---

## 2. Dockerize Node.js

### 📖 In-Depth Explanation

Docker containers package applications with dependencies, ensuring consistency across environments.

#### **Multi-stage Dockerfile for Production**

```dockerfile
# Dockerfile
# Stage 1: Build
FROM node:18-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++ git

# Copy package files
COPY package*.json ./
COPY tsconfig*.json ./

# Install ALL dependencies (including devDependencies)
RUN npm ci

# Copy source code
COPY src/ ./src/
COPY public/ ./public/

# Build application
RUN npm run build

# Run tests
RUN npm test

# Stage 2: Production
FROM node:18-alpine AS production

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

# Install production dependencies only
COPY --from=builder /app/package*.json ./
RUN npm ci --only=production --ignore-scripts

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/public ./public

# Copy necessary configuration files
COPY --chown=nodejs:nodejs .env.example .env
COPY --chown=nodejs:nodejs ecosystem.config.js .

# Switch to non-root user
USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => { \
    if (r.statusCode !== 200) process.exit(1) \
  }).on('error', () => process.exit(1))"

# Expose port
EXPOSE 3000

# Start application
CMD ["node", "dist/app.js"]
```

#### **Development Docker Configuration**

```dockerfile
# Dockerfile.dev
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Development command
CMD ["npm", "run", "dev"]
```

#### **Docker Compose for Local Development**

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://postgres:password@db:5432/app
      - REDIS_URL=redis://redis:6379
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      - db
      - redis
    networks:
      - app-network

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    networks:
      - app-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - ./nginx/logs:/var/log/nginx
    depends_on:
      - app
    networks:
      - app-network

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - app-network

  grafana:
    image: grafana/grafana:latest
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
    ports:
      - "3001:3000"
    networks:
      - app-network
    depends_on:
      - prometheus

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:

networks:
  app-network:
    driver: bridge
```

#### **Optimized Production Docker Compose**

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        order: start-first
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
        window: 120s
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    secrets:
      - database_password
    healthcheck:
      test: ["CMD", "node", "healthcheck.js"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    networks:
      - app-network

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - app
    networks:
      - app-network

secrets:
  database_password:
    external: true

networks:
  app-network:
    driver: overlay
    attachable: true
```

#### **Docker Optimizations for Node.js**

```dockerfile
# Dockerfile.optimized
FROM node:18-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY package.json package-lock.json* ./
RUN \
  if [ -f package-lock.json ]; then npm ci; \
  else echo "Lockfile not found." && exit 1; \
  fi

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production
ENV NEXT_TELEMETRY_DISABLED 1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public

# Set the correct permission for prerender cache
RUN mkdir .next
RUN chown nextjs:nodejs .next

# Automatically leverage output traces to reduce image size
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]
```

### 🎯 Real-World Scenario: Microservices Dockerization
*You have 15 Node.js microservices that need to be dockerized. Each has different dependencies, some use native modules, and they need to communicate with each other. You need optimal image sizes and fast build times.*

**Interview Questions:**
1. How would you structure Dockerfiles for multiple microservices?
2. What strategies would you use to reduce Docker image sizes?
3. How do you handle native modules that require compilation?
4. What's your approach to layer caching in CI/CD pipelines?
5. How do you manage secrets in Docker containers?

**Technical Questions:**
1. What's the difference between COPY and ADD in Docker?
2. How do multi-stage builds help reduce image size?
3. What are .dockerignore best practices?
4. How do you handle timezone and locale in Docker containers?

---

## 3. Using PM2

### 📖 In-Depth Explanation

PM2 is a production process manager for Node.js applications with load balancing, monitoring, and logging features.

#### **Advanced PM2 Configuration**

```javascript
// ecosystem.config.js
module.exports = {
  apps: [{
    // Basic Configuration
    name: 'api-server',
    script: 'dist/app.js',
    
    // Instance Management
    instances: 'max',              // Use all CPU cores
    exec_mode: 'cluster',          // Cluster mode for load balancing
    instance_var: 'INSTANCE_ID',   // Instance identifier
    
    // Environment Variables
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      NODE_OPTIONS: '--max-old-space-size=4096'
    },
    env_staging: {
      NODE_ENV: 'staging',
      PORT: 3001
    },
    
    // Logging Configuration
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    log_file: '/var/log/node-app/combined.log',
    error_file: '/var/log/node-app/error.log',
    out_file: '/var/log/node-app/out.log',
    
    // Process Management
    min_uptime: '60s',            // Minimum uptime before considered "up"
    max_restarts: 10,             // Maximum restarts in 60 seconds
    restart_delay: 4000,          // Delay between restarts
    kill_timeout: 5000,           // Time to wait before force kill
    listen_timeout: 3000,         // Timeout for app to listen
    
    // Monitoring
    watch: false,                  // Disable file watching in production
    ignore_watch: ['node_modules', 'logs', '.git'],
    
    // Advanced Settings
    max_memory_restart: '1G',     // Restart if memory exceeds 1GB
    node_args: [
      '--inspect=0.0.0.0:9229',   // Enable debugging
      '--trace-warnings',         // Show stack traces for warnings
      '--trace-deprecation'       // Show stack traces for deprecations
    ],
    
    // Source Map Support
    source_map_support: true,
    
    // Metrics Collection
    vizion: true,                  // Enable git integration
    post_update: ['npm install'], // Commands to run after pull
    
    // Custom Metrics
    metrics: true,                 // Enable PM2 metrics
    
    // Graceful Shutdown
    shutdown_with_message: true,
    kill_retry_time: 100,
    
    // Cron Restart (for memory leaks)
    cron_restart: '0 3 * * *',    // Daily restart at 3 AM
    
    // Interpreter
    interpreter: 'node',
    interpreter_args: '--harmony'
  }, {
    // Worker Process
    name: 'worker-queue',
    script: 'dist/workers/queue.js',
    instances: 4,
    exec_mode: 'cluster',
    max_memory_restart: '512M',
    autorestart: true,
    watch: false,
    env: {
      NODE_ENV: 'production',
      WORKER_TYPE: 'queue'
    }
  }, {
    // Scheduled Jobs
    name: 'cron-jobs',
    script: 'dist/workers/cron.js',
    instances: 1,
    autorestart: false,           // Don't restart if exits
    cron_restart: '*/5 * * * *',  // Run every 5 minutes
    env: {
      NODE_ENV: 'production',
      JOB_TYPE: 'scheduled'
    }
  }],
  
  // Deployment Configuration
  deploy: {
    production: {
      user: 'ubuntu',
      host: ['ec2-1-2-3-4.compute-1.amazonaws.com'],
      ref: 'origin/main',
      repo: 'git@github.com:your-org/node-app.git',
      path: '/var/www/node-app',
      'post-deploy': 'npm ci --production && pm2 reload ecosystem.config.js --env production',
      'pre-deploy-local': 'echo "Deploying to production"',
      env: {
        NODE_ENV: 'production'
      }
    },
    staging: {
      user: 'ubuntu',
      host: ['ec2-5-6-7-8.compute-1.amazonaws.com'],
      ref: 'origin/develop',
      repo: 'git@github.com:your-org/node-app.git',
      path: '/var/www/node-app-staging',
      'post-deploy': 'npm ci --production && pm2 reload ecosystem.config.js --env staging',
      env: {
        NODE_ENV: 'staging'
      }
    }
  }
};
```

#### **PM2 Management Scripts**

```bash
#!/bin/bash
# scripts/pm2-management.sh

# Start application with specific environment
start_app() {
    local env=${1:-production}
    
    echo "Starting application in $env mode..."
    
    # Load environment-specific configuration
    source /var/www/node-app/config/$env.env
    
    # Start PM2 with ecosystem file
    pm2 start ecosystem.config.js --env $env
    
    # Save PM2 process list
    pm2 save
    
    # Generate startup script
    pm2 startup
    
    echo "Application started in $env mode"
}

# Graceful restart
restart_app() {
    echo "Performing graceful restart..."
    
    # Send SIGINT to allow graceful shutdown
    pm2 reload all --update-env
    
    # Wait for processes to restart
    sleep 5
    
    # Check status
    pm2 status
    
    echo "Restart completed"
}

# Zero-downtime deployment
deploy_app() {
    local env=${1:-production}
    local branch=${2:-main}
    
    echo "Starting zero-downtime deployment..."
    
    # Pull latest code
    cd /var/www/node-app
    git fetch origin
    git checkout $branch
    git pull origin $branch
    
    # Install dependencies
    npm ci --only=production
    
    # Run database migrations
    npm run migrate:up
    
    # Reload application with zero downtime
    pm2 reload ecosystem.config.js --env $env --update-env
    
    # Wait and verify
    sleep 10
    pm2 status
    
    echo "Deployment completed successfully"
}

# Monitor application
monitor_app() {
    # Show real-time monitoring
    pm2 monit
    
    # Or show logs
    pm2 logs --lines 100 --timestamp
    
    # Show metrics
    pm2 show api-server
}

# Backup and restore PM2 state
backup_pm2() {
    local backup_dir="/var/backups/pm2"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    mkdir -p $backup_dir
    
    # Backup PM2 process list
    pm2 save
    cp ~/.pm2/dump.pm2 $backup_dir/dump_$timestamp.pm2
    
    # Backup logs
    tar -czf $backup_dir/logs_$timestamp.tar.gz /var/log/node-app/
    
    echo "PM2 backup created: $backup_dir/dump_$timestamp.pm2"
}

# Health check and auto-healing
health_check() {
    local status=$(pm2 jlist | jq -r '.[] | select(.name=="api-server") | .pm2_env.status')
    
    if [ "$status" != "online" ]; then
        echo "Application is not online. Current status: $status"
        echo "Attempting to restart..."
        
        pm2 restart api-server
        
        # Send alert
        send_alert "Application restarted" "PM2 auto-healing triggered"
    fi
}

# Memory leak detection and handling
handle_memory_leak() {
    local memory_threshold=800 # MB
    
    pm2 list | grep api-server | while read line; do
        local memory=$(echo $line | awk '{print $6}' | sed 's/MB//')
        local pid=$(echo $line | awk '{print $10}')
        
        if [ $memory -gt $memory_threshold ]; then
            echo "Memory leak detected in PID $pid (${memory}MB)"
            
            # Gracefully restart the specific instance
            pm2 restart $pid
            
            # Log the incident
            echo "$(date): Restarted PID $pid due to memory leak (${memory}MB)" >> /var/log/memory-leaks.log
        fi
    done
}
```

#### **PM2 with Docker Integration**

```dockerfile
# Dockerfile with PM2
FROM node:18-alpine

# Install PM2 globally
RUN npm install -g pm2

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY ecosystem.config.js ./

# Install dependencies
RUN npm ci --only=production

# Copy application
COPY dist/ ./dist/

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Start with PM2
CMD ["pm2-runtime", "start", "ecosystem.config.js", "--env", "production"]
```

#### **PM2 Module System**

```bash
# Install PM2 modules
pm2 install pm2-logrotate          # Log rotation
pm2 install pm2-server-monit       # Server monitoring
pm2 install pm2-log-rotate         # Alternative log rotation
pm2 install pm2-webshell           # Web interface
pm2 install pm2-io-apm             # Application performance monitoring

# Configure log rotation
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 7
pm2 set pm2-logrotate:compress true
pm2 set pm2-logrotate:dateFormat YYYY-MM-DD_HH-mm-ss
pm2 set pm2-logrotate:workerInterval 30
pm2 set pm2-logrotate:rotateInterval 0 0 * * *

# Enable monitoring
pm2 set pm2-server-monit:interval 10000
```

### 🎯 Real-World Scenario: High-Traffic API Server
*You're managing a Node.js API server handling 50,000 requests per minute. The server experiences memory leaks under load and needs zero-downtime deployments. PM2 needs to be configured for optimal performance and reliability.*

**Interview Questions:**
1. How would you configure PM2 for maximum throughput?
2. What strategies would you implement for memory leak detection and handling?
3. How do you ensure zero-downtime deployments with PM2?
4. What monitoring and alerting would you set up with PM2?
5. How do you handle application crashes and automatic recovery?

**Technical Questions:**
1. What's the difference between `pm2 start` and `pm2-runtime`?
2. How does PM2 cluster mode work with Node.js?
3. What are the best practices for PM2 logging configuration?
4. How do you manage environment variables with PM2?

---

## 4. Nginx Reverse Proxy

### 📖 In-Depth Explanation

Nginx acts as a reverse proxy, load balancer, and web server, providing SSL termination, caching, and security features.

#### **Advanced Nginx Configuration**

```nginx
# nginx/nginx.conf
# Main context
user nginx;
worker_processes auto;
worker_rlimit_nofile 100000;  # Maximum number of open files

error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;  # Connections per worker
    multi_accept on;          # Accept multiple connections at once
    use epoll;                # Use epoll for Linux
}

http {
    # Basic Settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance Optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 1000;
    reset_timedout_connection on;
    client_body_timeout 10;
    send_timeout 2;
    
    # Buffer Sizes
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    client_max_body_size 10m;
    large_client_header_buffers 4 4k;
    
    # Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;
    
    # Cache Settings
    open_file_cache max=200000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
    
    # Security Headers
    map $sent_http_content_type $security_headers {
        default "";
        "~*text/html" "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;";
    }
    
    # Log Format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';
    
    access_log /var/log/nginx/access.log main buffer=32k flush=5s;
    
    # Include site configurations
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

#### **Node.js Application Configuration**

```nginx
# nginx/sites-available/node-app
upstream node_backend {
    # Load balancing methods:
    # least_conn - least connections
    # ip_hash - session persistence
    # hash $remote_addr consistent;
    
    least_conn;
    
    # Server definitions
    server 127.0.0.1:3000 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3001 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3002 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:3003 max_fails=3 fail_timeout=30s;
    
    # Keepalive connections to backend
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name api.example.com www.api.example.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.example.com www.api.example.com;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/live/api.example.com/privkey.pem;
    
    # SSL Optimization
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/nginx/ssl/live/api.example.com/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy $security_headers always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    
    # Root directory
    root /var/www/html;
    index index.html;
    
    # Gzip compression for API responses
    gzip on;
    gzip_types application/json;
    
    # API Rate Limiting
    limit_req zone=api burst=20 nodelay;
    
    # Health check endpoint (no rate limiting)
    location = /health {
        access_log off;
        limit_req off;
        
        proxy_pass http://node_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Main API location
    location /api/ {
        # Rate limiting
        limit_req zone=api burst=20 nodelay;
        
        # CORS headers
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
        
        add_header 'Access-Control-Allow-Origin' '*';
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range';
        
        # Proxy configuration
        proxy_pass http://node_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
        
        # Cache static responses
        location ~* /api/static/ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
        
        # No cache for dynamic endpoints
        location ~* /api/(users|orders|payments)/ {
            add_header Cache-Control "no-cache, no-store, must-revalidate";
            add_header Pragma "no-cache";
            add_header Expires "0";
        }
    }
    
    # Authentication endpoints (stricter rate limiting)
    location /api/auth/ {
        limit_req zone=auth burst=5 nodelay;
        
        proxy_pass http://node_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # WebSocket support
    location /api/ws/ {
        proxy_pass http://node_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # WebSocket timeouts
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    
    # Static files
    location /static/ {
        root /var/www/node-app/public;
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
        
        # Security for static files
        location ~* \.(php|phtml)$ {
            deny all;
        }
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
    
    # Logging per location
    location /api/health {
        access_log off;
    }
    
    location /api/metrics {
        access_log /var/log/nginx/metrics.log main;
    }
}
```

#### **Load Balancing Configuration**

```nginx
# nginx/load-balancer.conf
upstream backend {
    zone backend 64k;
    
    # Health checks
    server backend1.example.com:3000 max_fails=3 fail_timeout=30s;
    server backend2.example.com:3000 max_fails=3 fail_timeout=30s;
    server backend3.example.com:3000 max_fails=3 fail_timeout=30s backup;
    
    # Session persistence (optional)
    hash $remote_addr consistent;
    
    # Active health checks
    health_check interval=5s fails=3 passes=2 uri=/health match=status_ok;
}

match status_ok {
    status 200;
    body ~ "ok";
}

server {
    listen 80;
    
    location / {
        proxy_pass http://backend;
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_next_upstream_tries 3;
        proxy_next_upstream_timeout 10s;
        
        # Circuit breaker pattern
        proxy_intercept_errors on;
        error_page 500 502 503 504 = @fallback;
    }
    
    location @fallback {
        # Fallback response
        return 503 "Service Temporarily Unavailable";
    }
}
```

#### **Nginx Security Configuration**

```nginx
# nginx/security.conf
# Prevent information disclosure
server_tokens off;

# Clickjacking protection
add_header X-Frame-Options "SAMEORIGIN" always;

# XSS Protection
add_header X-XSS-Protection "1; mode=block" always;

# Content Type Options
add_header X-Content-Type-Options "nosniff" always;

# Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions Policy
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# Limit request methods
if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$) {
    return 405;
}

# Block suspicious user agents
if ($http_user_agent ~* (nmap|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|libwww-perl) ) {
    return 403;
}

# Block SQL injection attempts
set $block_sql_injections 0;
if ($query_string ~ "union.*select.*\(") {
    set $block_sql_injections 1;
}
if ($query_string ~ "union.*all.*select.*") {
    set $block_sql_injections 1;
}
if ($query_string ~ "concat.*\(") {
    set $block_sql_injections 1;
}
if ($block_sql_injections = 1) {
    return 403;
}

# Block file injection attempts
if ($query_string ~ "[a-zA-Z0-9_]=http://") {
    return 403;
}
if ($query_string ~ "[a-zA-Z0-9_]=(\.\.//?)+") {
    return 403;
}
if ($query_string ~ "[a-zA-Z0-9_]=/([a-z0-9_.]//?)+") {
    return 403;
}

# Limit connections per IP
limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
limit_conn conn_limit_per_ip 20;
```

### 🎯 Real-World Scenario: E-commerce Platform Load Balancer
*You're setting up Nginx as a load balancer for an e-commerce platform handling Black Friday traffic. The platform has multiple Node.js servers, needs WebSocket support for real-time updates, and must handle DDoS attacks.*

**Interview Questions:**
1. How would you configure Nginx for handling 100,000 concurrent connections?
2. What load balancing algorithm would you choose and why?
3. How do you implement rate limiting for API endpoints?
4. What security measures would you implement at the Nginx level?
5. How do you handle WebSocket connections through Nginx?

**Technical Questions:**
1. What's the difference between `proxy_pass` and `fastcgi_pass`?
2. How do you configure HTTP/2 and HTTP/3 in Nginx?
3. What are upstream keepalive connections and why are they important?
4. How do you implement circuit breaking in Nginx?

---

## 5. SSL Certificates

### 📖 In-Depth Explanation

SSL/TLS certificates encrypt communication between clients and servers, ensuring data confidentiality and integrity.

#### **Automated SSL with Certbot**

```bash
#!/bin/bash
# scripts/ssl-setup.sh

# Install Certbot
sudo apt-get update
sudo apt-get install -y certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx \
  -d api.example.com \
  -d www.api.example.com \
  --email admin@example.com \
  --agree-tos \
  --no-eff-email \
  --redirect \
  --hsts \
  --uir \
  --staple-ocsp

# Test renewal
sudo certbot renew --dry-run

# Set up auto-renewal cron job
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -

# Configure SSL settings in Nginx
sudo tee /etc/nginx/snippets/ssl-params.conf << 'EOF'
# SSL Configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
ssl_ecdh_curve secp384r1;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# Security Headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
EOF

# Configure SSL for Node.js application
sudo tee /etc/nginx/sites-available/node-app << 'EOF'
server {
    listen 80;
    server_name api.example.com www.api.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.example.com www.api.example.com;
    
    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;
    include snippets/ssl-params.conf;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Test and reload Nginx
sudo nginx -t
sudo systemctl reload nginx

# Monitor certificate expiration
echo "SSL certificates will expire on:"
sudo openssl x509 -in /etc/letsencrypt/live/api.example.com/cert.pem -noout -dates
```

#### **SSL Configuration for Node.js (Direct HTTPS)**

```javascript
// ssl/server.js
import https from 'https';
import fs from 'fs';
import app from './app.js';

const sslOptions = {
  // Certificate files
  key: fs.readFileSync('/etc/ssl/private/private-key.pem'),
  cert: fs.readFileSync('/etc/ssl/certs/certificate.pem'),
  ca: fs.readFileSync('/etc/ssl/certs/ca-bundle.pem'),
  
  // SSL/TLS Configuration
  minVersion: 'TLSv1.2',
  ciphers: [
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-SHA384',
    'ECDHE-RSA-AES256-SHA',
    'DHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES256-SHA256',
    'DHE-RSA-AES256-SHA'
  ].join(':'),
  
  // Enable OCSP stapling
  honorCipherOrder: true,
  requestCert: false,
  rejectUnauthorized: true,
  
  // Session caching
  sessionTimeout: 300,
  ticketKeys: Buffer.from(/* 48-byte key */),
  
  // SNI (Server Name Indication) support
  SNICallback: (servername, cb) => {
    // Handle multiple domains
    if (servername === 'api.example.com') {
      cb(null, sslOptions);
    } else {
      cb(new Error('No certificate for ' + servername));
    }
  }
};

// Create HTTPS server
const server = https.createServer(sslOptions, app);

// Enable HTTP/2 if available
if (typeof server.setTimeout === 'function') {
  server.setTimeout(30000); // 30 seconds
}

// Start server
const PORT = process.env.PORT || 443;
server.listen(PORT, () => {
  console.log(`HTTPS server running on port ${PORT}`);
  
  // Log SSL information
  console.log('SSL/TLS Configuration:');
  console.log('- Protocol: TLSv1.2+');
  console.log('- Ciphers: ECDHE-RSA-AES256-GCM-SHA384');
  console.log('- OCSP Stapling: Enabled');
  console.log('- HSTS: Enabled via Nginx');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing HTTPS server');
  server.close(() => {
    console.log('HTTPS server closed');
    process.exit(0);
  });
});
```

#### **SSL Monitoring and Renewal Script**

```bash
#!/bin/bash
# scripts/ssl-monitor.sh

# Check SSL certificate expiration
check_cert_expiry() {
    local domain=$1
    local cert_file="/etc/letsencrypt/live/$domain/cert.pem"
    
    if [ ! -f "$cert_file" ]; then
        echo "Certificate file not found for $domain"
        return 1
    fi
    
    local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_date" +%s)
    local now_epoch=$(date +%s)
    local days_until_expiry=$(( (expiry_epoch - now_epoch) / 86400 ))
    
    echo "Certificate for $domain expires in $days_until_expiry days ($expiry_date)"
    
    if [ $days_until_expiry -lt 7 ]; then
        echo "WARNING: Certificate for $domain expires in less than 7 days!"
        
        # Attempt renewal
        sudo certbot renew --cert-name $domain --force-renewal
        
        # Reload Nginx if renewal successful
        if [ $? -eq 0 ]; then
            sudo systemctl reload nginx
            echo "Certificate renewed and Nginx reloaded"
        else
            echo "Certificate renewal failed"
            # Send alert
            send_alert "SSL Certificate Renewal Failed" "Domain: $domain, Expires in: $days_until_expiry days"
        fi
    fi
}

# Check certificate chain
check_cert_chain() {
    local domain=$1
    
    echo "Checking certificate chain for $domain..."
    
    # Verify chain
    openssl verify -verify_hostname $domain \
        -CAfile /etc/letsencrypt/live/$domain/chain.pem \
        /etc/letsencrypt/live/$domain/cert.pem
    
    if [ $? -ne 0 ]; then
        echo "ERROR: Certificate chain verification failed for $domain"
        return 1
    fi
    
    echo "Certificate chain is valid"
}

# Check OCSP stapling
check_ocsp() {
    local domain=$1
    
    echo "Checking OCSP stapling for $domain..."
    
    local response=$(echo QUIT | openssl s_client -connect $domain:443 -status 2>/dev/null | grep -A 17 'OCSP response:')
    
    if echo "$response" | grep -q "successful"; then
        echo "OCSP stapling is working"
    else
        echo "WARNING: OCSP stapling is not working"
    fi
}

# Test SSL/TLS configuration
test_ssl_config() {
    local domain=$1
    
    echo "Testing SSL/TLS configuration for $domain..."
    
    # Test with SSL Labs API (requires curl and jq)
    local result=$(curl -s "https://api.ssllabs.com/api/v3/analyze?host=$domain")
    local grade=$(echo $result | jq -r '.endpoints[0].grade')
    
    echo "SSL Labs grade for $domain: $grade"
    
    # Test specific protocols
    echo "Testing protocols..."
    for protocol in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
        local test_result=$(echo QUIT | openssl s_client -connect $domain:443 -$protocol 2>/dev/null | grep -q "CONNECTED" && echo "Supported" || echo "Not supported")
        echo "- $protocol: $test_result"
    done
}

# Main monitoring function
monitor_ssl() {
    local domains=("api.example.com" "www.example.com")
    
    for domain in "${domains[@]}"; do
        echo "=== Monitoring $domain ==="
        
        check_cert_expiry "$domain"
        check_cert_chain "$domain"
        check_ocsp "$domain"
        
        # Only run full test once a day
        if [ $(date +%H) -eq 2 ]; then  # At 2 AM
            test_ssl_config "$domain"
        fi
        
        echo ""
    done
}

# Run monitoring
monitor_ssl

# Log results
echo "SSL monitoring completed at $(date)" >> /var/log/ssl-monitor.log
```

#### **SSL with Docker**

```dockerfile
# Dockerfile with SSL
FROM nginx:alpine

# Install certbot and openssl
RUN apk add --no-cache certbot certbot-nginx openssl

# Create SSL directory
RUN mkdir -p /etc/nginx/ssl

# Generate self-signed certificate for development
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/selfsigned.key \
    -out /etc/nginx/ssl/selfsigned.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Copy Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY ssl-params.conf /etc/nginx/ssl-params.conf

# Copy SSL certificates (mount volume in production)
COPY ssl/ /etc/nginx/ssl/

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
```

### 🎯 Real-World Scenario: Multi-domain SSL Management
*You manage 50 domains with SSL certificates, all with different renewal dates. You need to automate renewal, monitor expiration, and ensure all domains maintain A+ SSL ratings.*

**Interview Questions:**
1. How would you automate SSL certificate management for 50 domains?
2. What monitoring would you implement for SSL certificate expiration?
3. How do you handle certificate renewal for zero-downtime?
4. What are the security considerations for SSL certificate storage?
5. How do you implement OCSP stapling and why is it important?

**Technical Questions:**
1. What's the difference between DV, OV, and EV certificates?
2. How does Let's Encrypt ACME protocol work?
3. What are certificate transparency logs?
4. How do you implement SSL pinning in mobile apps?

---

## 6. Environment Variable Setup

### 📖 In-Depth Explanation

Environment variables provide configuration to applications without hardcoding sensitive information.

#### **Advanced Environment Management**

```javascript
// config/env.js
import dotenv from 'dotenv';
import Joi from 'joi';
import fs from 'fs';
import path from 'path';

// Load environment variables based on NODE_ENV
const envFile = `.env.${process.env.NODE_ENV || 'development'}`;
const envPath = path.resolve(process.cwd(), envFile);

if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
} else {
  dotenv.config();
}

// Environment schema validation
const envVarsSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test', 'staging')
    .default('development'),
  
  PORT: Joi.number()
    .default(3000),
  
  // Database
  DATABASE_URL: Joi.string()
    .required()
    .description('Database connection URL'),
  
  DATABASE_POOL_MIN: Joi.number()
    .default(2),
  
  DATABASE_POOL_MAX: Joi.number()
    .default(10),
  
  // Redis
  REDIS_URL: Joi.string()
    .required()
    .description('Redis connection URL'),
  
  REDIS_TTL: Joi.number()
    .default(3600),
  
  // JWT
  JWT_SECRET: Joi.string()
    .required()
    .min(32)
    .description('JWT secret key'),
  
  JWT_EXPIRES_IN: Joi.string()
    .default('7d'),
  
  // AWS
  AWS_ACCESS_KEY_ID: Joi.string()
    .required(),
  
  AWS_SECRET_ACCESS_KEY: Joi.string()
    .required(),
  
  AWS_REGION: Joi.string()
    .default('us-east-1'),
  
  AWS_S3_BUCKET: Joi.string()
    .required(),
  
  // Email
  SMTP_HOST: Joi.string()
    .required(),
  
  SMTP_PORT: Joi.number()
    .default(587),
  
  SMTP_USER: Joi.string()
    .required(),
  
  SMTP_PASS: Joi.string()
    .required(),
  
  // External APIs
  STRIPE_SECRET_KEY: Joi.string()
    .required(),
  
  SENDGRID_API_KEY: Joi.string()
    .required(),
  
  // Feature flags
  FEATURE_NEW_CHECKOUT: Joi.boolean()
    .default(false),
  
  FEATURE_BETA_FEATURES: Joi.boolean()
    .default(false),
  
  // Monitoring
  SENTRY_DSN: Joi.string()
    .uri(),
  
  NEW_RELIC_LICENSE_KEY: Joi.string(),
  
  // Rate limiting
  RATE_LIMIT_WINDOW: Joi.number()
    .default(15),
  
  RATE_LIMIT_MAX: Joi.number()
    .default(100),
  
  // Security
  CORS_ORIGIN: Joi.string()
    .default('*'),
  
  TRUST_PROXY: Joi.number()
    .default(1),
  
  // Application
  APP_NAME: Joi.string()
    .default('Node.js App'),
  
  APP_VERSION: Joi.string()
    .default('1.0.0'),
  
  LOG_LEVEL: Joi.string()
    .valid('error', 'warn', 'info', 'debug', 'trace')
    .default('info'),
  
  // Encryption
  ENCRYPTION_KEY: Joi.string()
    .required()
    .min(32),
  
  // Session
  SESSION_SECRET: Joi.string()
    .required()
    .min(32),
  
  SESSION_TTL: Joi.number()
    .default(86400),
  
  // Cache
  CACHE_TTL: Joi.number()
    .default(300),
  
  CACHE_ENABLED: Joi.boolean()
    .default(true),
}).unknown();

const { value: envVars, error } = envVarsSchema.validate(process.env, {
  abortEarly: false,
  stripUnknown: true,
});

if (error) {
  throw new Error(`Environment validation error: ${error.message}`);
}

// Export configuration
export default {
  env: envVars.NODE_ENV,
  port: envVars.PORT,
  
  database: {
    url: envVars.DATABASE_URL,
    pool: {
      min: envVars.DATABASE_POOL_MIN,
      max: envVars.DATABASE_POOL_MAX,
    },
  },
  
  redis: {
    url: envVars.REDIS_URL,
    ttl: envVars.REDIS_TTL,
  },
  
  jwt: {
    secret: envVars.JWT_SECRET,
    expiresIn: envVars.JWT_EXPIRES_IN,
  },
  
  aws: {
    accessKeyId: envVars.AWS_ACCESS_KEY_ID,
    secretAccessKey: envVars.AWS_SECRET_ACCESS_KEY,
    region: envVars.AWS_REGION,
    s3Bucket: envVars.AWS_S3_BUCKET,
  },
  
  email: {
    smtp: {
      host: envVars.SMTP_HOST,
      port: envVars.SMTP_PORT,
      auth: {
        user: envVars.SMTP_USER,
        pass: envVars.SMTP_PASS,
      },
    },
  },
  
  apis: {
    stripe: {
      secretKey: envVars.STRIPE_SECRET_KEY,
    },
    sendgrid: {
      apiKey: envVars.SENDGRID_API_KEY,
    },
  },
  
  features: {
    newCheckout: envVars.FEATURE_NEW_CHECKOUT,
    betaFeatures: envVars.FEATURE_BETA_FEATURES,
  },
  
  monitoring: {
    sentry: {
      dsn: envVars.SENTRY_DSN,
    },
    newRelic: {
      licenseKey: envVars.NEW_RELIC_LICENSE_KEY,
    },
  },
  
  security: {
    rateLimit: {
      window: envVars.RATE_LIMIT_WINDOW,
      max: envVars.RATE_LIMIT_MAX,
    },
    cors: {
      origin: envVars.CORS_ORIGIN,
    },
    trustProxy: envVars.TRUST_PROXY,
  },
  
  app: {
    name: envVars.APP_NAME,
    version: envVars.APP_VERSION,
    logLevel: envVars.LOG_LEVEL,
  },
  
  encryption: {
    key: envVars.ENCRYPTION_KEY,
  },
  
  session: {
    secret: envVars.SESSION_SECRET,
    ttl: envVars.SESSION_TTL,
  },
  
  cache: {
    ttl: envVars.CACHE_TTL,
    enabled: envVars.CACHE_ENABLED,
  },
  
  // Helper methods
  isDevelopment: () => envVars.NODE_ENV === 'development',
  isProduction: () => envVars.NODE_ENV === 'production',
  isTest: () => envVars.NODE_ENV === 'test',
  isStaging: () => envVars.NODE_ENV === 'staging',
};
```

#### **AWS Secrets Manager Integration**

```javascript
// config/secrets.js
import AWS from 'aws-sdk';
import { config } from './env.js';

class SecretsManager {
  constructor() {
    this.client = new AWS.SecretsManager({
      region: config.aws.region,
      credentials: {
        accessKeyId: config.aws.accessKeyId,
        secretAccessKey: config.aws.secretAccessKey,
      },
    });
    
    this.cache = new Map();
    this.cacheTtl = 300000; // 5 minutes
  }
  
  async getSecret(secretName, useCache = true) {
    const cacheKey = `secret:${secretName}`;
    
    // Check cache
    if (useCache && this.cache.has(cacheKey)) {
      const cached = this.cache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTtl) {
        return cached.value;
      }
    }
    
    try {
      const response = await this.client.getSecretValue({
        SecretId: secretName,
      }).promise();
      
      let secretValue;
      if ('SecretString' in response) {
        secretValue = JSON.parse(response.SecretString);
      } else {
        secretValue = JSON.parse(
          Buffer.from(response.SecretBinary, 'base64').toString('ascii')
        );
      }
      
      // Cache the result
      this.cache.set(cacheKey, {
        value: secretValue,
        timestamp: Date.now(),
      });
      
      return secretValue;
    } catch (error) {
      console.error(`Error retrieving secret ${secretName}:`, error);
      throw error;
    }
  }
  
  async updateSecret(secretName, secretValue) {
    try {
      await this.client.updateSecret({
        SecretId: secretName,
        SecretString: JSON.stringify(secretValue),
      }).promise();
      
      // Invalidate cache
      this.cache.delete(`secret:${secretName}`);
      
      console.log(`Secret ${secretName} updated successfully`);
    } catch (error) {
      console.error(`Error updating secret ${secretName}:`, error);
      throw error;
    }
  }
  
  async loadSecrets() {
    const secretsToLoad = [
      'production/database/credentials',
      'production/redis/credentials',
      'production/jwt/secret',
      'production/third-party/keys',
    ];
    
    const loadedSecrets = {};
    
    for (const secretName of secretsToLoad) {
      try {
        const secret = await this.getSecret(secretName);
        loadedSecrets[secretName] = secret;
        
        // Merge into process.env
        Object.entries(secret).forEach(([key, value]) => {
          process.env[key.toUpperCase()] = String(value);
        });
      } catch (error) {
        console.error(`Failed to load secret ${secretName}:`, error);
        // Continue with other secrets
      }
    }
    
    return loadedSecrets;
  }
}

// Singleton instance
export const secretsManager = new SecretsManager();

// Usage in application
import { secretsManager } from './config/secrets.js';

async function initializeApp() {
  // Load secrets during startup
  await secretsManager.loadSecrets();
  
  // Now process.env has all the secrets
  console.log('Database URL:', process.env.DATABASE_URL);
  console.log('JWT Secret loaded:', !!process.env.JWT_SECRET);
  
  // Start application
  app.listen(config.port, () => {
    console.log(`Server running on port ${config.port}`);
  });
}
```

#### **Docker Compose with Environment Variables**

```yaml
# docker-compose.yml with environment management
version: '3.8'

services:
  app:
    build: .
    environment:
      - NODE_ENV=${NODE_ENV:-development}
      - PORT=3000
    env_file:
      - .env
      - .env.${NODE_ENV:-development}
    # Environment variable expansion
    environment:
      DATABASE_URL: postgresql://${DB_USER}:${DB_PASSWORD}@db:5432/${DB_NAME}
      REDIS_URL: redis://redis:6379
    secrets:
      - jwt_secret
      - encryption_key
    configs:
      - source: app_config
        target: /app/config/production.json

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    env_file:
      - .env.db

  redis:
    image: redis:7-alpine
    environment:
      REDIS_PASSWORD: ${REDIS_PASSWORD}
    command: redis-server --requirepass ${REDIS_PASSWORD}

secrets:
  jwt_secret:
    external: true
  encryption_key:
    file: ./secrets/encryption_key.txt

configs:
  app_config:
    file: ./config/production.json

volumes:
  postgres_data:
```

#### **Environment Variable Encryption**

```javascript
// utils/encryption.js
import crypto from 'crypto';

class EnvironmentEncryption {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.ivLength = 16;
    this.saltLength = 64;
    this.tagLength = 16;
    this.keyLength = 32;
  }
  
  deriveKey(password, salt) {
    return crypto.pbkdf2Sync(
      password,
      salt,
      100000,
      this.keyLength,
      'sha512'
    );
  }
  
  encrypt(text, password) {
    const salt = crypto.randomBytes(this.saltLength);
    const iv = crypto.randomBytes(this.ivLength);
    const key = this.deriveKey(password, salt);
    
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    const encrypted = Buffer.concat([
      cipher.update(text, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64');
  }
  
  decrypt(encryptedData, password) {
    const data = Buffer.from(encryptedData, 'base64');
    
    const salt = data.slice(0, this.saltLength);
    const iv = data.slice(this.saltLength, this.saltLength + this.ivLength);
    const tag = data.slice(
      this.saltLength + this.ivLength,
      this.saltLength + this.ivLength + this.tagLength
    );
    const encrypted = data.slice(this.saltLength + this.ivLength + this.tagLength);
    
    const key = this.deriveKey(password, salt);
    
    const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    decipher.setAuthTag(tag);
    
    return decipher.update(encrypted) + decipher.final('utf8');
  }
  
  encryptEnvironment(envObject, password) {
    const encrypted = {};
    
    Object.entries(envObject).forEach(([key, value]) => {
      if (this.isSensitive(key)) {
        encrypted[key] = this.encrypt(String(value), password);
      } else {
        encrypted[key] = value;
      }
    });
    
    return encrypted;
  }
  
  decryptEnvironment(encryptedEnv, password) {
    const decrypted = {};
    
    Object.entries(encryptedEnv).forEach(([key, value]) => {
      try {
        decrypted[key] = this.decrypt(value, password);
      } catch (error) {
        // If decryption fails, assume it's not encrypted
        decrypted[key] = value;
      }
    });
    
    return decrypted;
  }
  
  isSensitive(key) {
    const sensitivePatterns = [
      /password/i,
      /secret/i,
      /key$/i,
      /token/i,
      /credential/i,
      /private/i,
    ];
    
    return sensitivePatterns.some(pattern => pattern.test(key));
  }
}

// Usage
const envEncryption = new EnvironmentEncryption();
const masterPassword = process.env.MASTER_PASSWORD;

// Encrypt sensitive environment variables
const sensitiveEnv = {
  DATABASE_PASSWORD: 'supersecret123',
  JWT_SECRET: 'jwtsecretkey1234567890',
  AWS_SECRET_ACCESS_KEY: 'awssecretkey123',
};

const encryptedEnv = envEncryption.encryptEnvironment(sensitiveEnv, masterPassword);

// Store encrypted values in .env.encrypted
// DATABASE_PASSWORD="gAAAAABf8KJ..."
// JWT_SECRET="gAAAAABf8KL..."

// Decrypt at runtime
const decryptedEnv = envEncryption.decryptEnvironment(encryptedEnv, masterPassword);
```

### 🎯 Real-World Scenario: Multi-environment Configuration
*You have applications running in development, staging, and production environments across multiple regions. Each environment has different configurations, and you need to manage secrets securely while allowing developers to run the app locally.*

**Interview Questions:**
1. How would you manage environment variables across multiple environments?
2. What strategies would you use for secret rotation?
3. How do you handle environment-specific configurations?
4. What tools would you use for environment variable management?
5. How do you prevent secrets from being exposed in logs or error messages?

**Technical Questions:**
1. What's the difference between .env files and environment variables?
2. How do you validate environment variables at startup?
3. What are the security considerations for .env files?
4. How do you handle environment variables in containerized applications?

---

## 7. CI/CD with GitHub Actions

### 📖 In-Depth Explanation

GitHub Actions automates build, test, and deployment workflows directly from your GitHub repository.

#### **Complete CI/CD Pipeline**

```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main, develop ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
  NODE_VERSION: '18'
  DOCKER_BUILDKIT: 1

# Job dependencies and workflow
jobs:
  # Code Quality Checks
  lint-and-format:
    name: Lint & Format
    runs-on: ubuntu-latest
    timeout-minutes: 10
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run ESLint
      run: npm run lint
    
    - name: Run Prettier check
      run: npm run format:check
    
    - name: Run TypeScript check
      run: npm run type-check
    
    - name: Run dependency audit
      run: npm audit --audit-level=high

  # Unit Tests
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest
    needs: lint-and-format
    timeout-minutes: 15
    
    strategy:
      matrix:
        node-version: [16, 18, 20]
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run unit tests
      run: npm run test:unit
      env:
        NODE_ENV: test
        DATABASE_URL: postgresql://test:test@localhost/test
    
    - name: Upload test results
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: test-results-${{ matrix.node-version }}
        path: |
          coverage/
          junit.xml
        retention-days: 30
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      if: success()
      with:
        files: ./coverage/lcov.info
        flags: unittests
        name: codecov-umbrella

  # Integration Tests
  integration-tests:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: unit-tests
    timeout-minutes: 30
    
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run database migrations
      run: npm run migrate:up
      env:
        DATABASE_URL: postgresql://test:test@localhost:5432/test
    
    - name: Run integration tests
      run: npm run test:integration
      env:
        NODE_ENV: test
        DATABASE_URL: postgresql://test:test@localhost:5432/test
        REDIS_URL: redis://localhost:6379
    
    - name: Run E2E tests
      run: npm run test:e2e
      env:
        NODE_ENV: test
        DATABASE_URL: postgresql://test:test@localhost:5432/test

  # Build and Push Docker Image
  build-and-push:
    name: Build & Push Docker Image
    runs-on: ubuntu-latest
    needs: integration-tests
    if: github.event_name == 'push' && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop')
    timeout-minutes: 20
    
    outputs:
      image_tag: ${{ steps.meta.outputs.tags }}
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata (tags, labels)
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
          type=sha,prefix={{branch}}-
        labels: |
          org.opencontainers.image.title=${{ github.event.repository.name }}
          org.opencontainers.image.description=${{ github.event.repository.description }}
          org.opencontainers.image.url=${{ github.event.repository.html_url }}
          org.opencontainers.image.source=${{ github.event.repository.clone_url }}
          org.opencontainers.image.version=${{ github.ref_name }}
          org.opencontainers.image.created=${{ github.event.repository.created_at }}
          org.opencontainers.image.revision=${{ github.sha }}
          org.opencontainers.image.licenses=${{ github.event.repository.license.spdx_id }}
    
    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        platforms: linux/amd64,linux/arm64
    
    - name: Scan image for vulnerabilities
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.meta.outputs.version }}
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: 'trivy-results.sarif'

  # Deploy to Staging
  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == 'refs/heads/develop'
    environment: staging
    timeout-minutes: 15
    
    steps:
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID_STAGING }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY_STAGING }}
        aws-region: us-east-1
    
    - name: Download task definition
      run: |
        aws ecs describe-task-definition \
          --task-definition node-app-staging \
          --query taskDefinition \
          > task-definition.json
    
    - name: Update task definition with new image
      id: update-task-def
      uses: aws-actions/amazon-ecs-render-task-definition@v1
      with:
        task-definition: task-definition.json
        container-name: node-app
        image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
    
    - name: Deploy to ECS
      uses: aws-actions/amazon-ecs-deploy-task-definition@v1
      with:
        task-definition: ${{ steps.update-task-def.outputs.task-definition }}
        service: node-app-staging
        cluster: staging-cluster
        wait-for-service-stability: true
    
    - name: Run smoke tests
      run: |
        npm run test:smoke \
          --url=https://staging-api.example.com \
          --token=${{ secrets.STAGING_API_TOKEN }}
    
    - name: Notify Slack on success
      uses: 8398a7/action-slack@v3
      if: success()
      with:
        status: success
        text: 'Staging deployment successful!'
        fields: repo,message,commit,author,action,eventName,ref,workflow,job,took
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}

  # Deploy to Production
  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: 
      - build-and-push
      - deploy-staging
    if: github.ref == 'refs/heads/main'
    environment: production
    timeout-minutes: 30
    
    steps:
    - name: Wait for approval
      uses: trstringer/manual-approval@v1
      with:
        secret: ${{ github.token }}
        approvers: ${{ secrets.PRODUCTION_APPROVERS }}
        minimum-approvals: 2
        issue-title: 'Production Deployment Approval'
        issue-body: 'Please review and approve this production deployment.'
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-east-1
    
    - name: Deploy with blue-green strategy
      run: |
        # Deploy new task set
        aws ecs create-task-set \
          --cluster production-cluster \
          --service node-app-production \
          --task-definition node-app-production:${{ github.sha }} \
          --launch-type FARGATE \
          --network-configuration file://network-config.json
        
        # Wait for new task set to stabilize
        sleep 60
        
        # Update service primary task set
        aws ecs update-service-primary-task-set \
          --cluster production-cluster \
          --service node-app-production \
          --primary-task-set arn:aws:ecs:us-east-1:123456789012:task-set/production-cluster/node-app-production/abcdef
        
        # Delete old task set
        aws ecs delete-task-set \
          --cluster production-cluster \
          --service node-app-production \
          --task-set arn:aws:ecs:us-east-1:123456789012:task-set/production-cluster/node-app-production/oldabcdef
    
    - name: Run canary tests
      run: |
        # Send 10% of traffic to new version
        for i in {1..100}; do
          curl -s https://api.example.com/health > /dev/null
          sleep 0.1
        done
        
        # Monitor error rates
        npm run test:canary \
          --url=https://api.example.com \
          --threshold=0.01
    
    - name: Rollback if tests fail
      if: failure()
      run: |
        echo "Canary tests failed, initiating rollback..."
        aws ecs update-service \
          --cluster production-cluster \
          --service node-app-production \
          --task-definition node-app-production:previous
        
        # Send rollback notification
        curl -X POST ${{ secrets.SLACK_WEBHOOK_URL }} \
          -H 'Content-type: application/json' \
          -d '{"text":"Production rollback initiated due to failed canary tests"}'
    
    - name: Update deployment status
      if: success()
      run: |
        curl -X POST https://api.github.com/repos/${{ github.repository }}/deployments/${{ github.deployment_id }}/statuses \
          -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" \
          -H "Accept: application/vnd.github.ant-man-preview+json" \
          -d '{"state":"success","environment_url":"https://api.example.com"}'
    
    - name: Notify Slack on production deployment
      uses: 8398a7/action-slack@v3
      if: success()
      with:
        status: success
        text: 'Production deployment successful! :rocket:'
        fields: repo,message,commit,author,action,eventName,ref,workflow,job,took
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}

  # Security Scanning
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    needs: [unit-tests, integration-tests]
    timeout-minutes: 10
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Run Snyk to check for vulnerabilities
      uses: snyk/actions/node@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        args: --severity-threshold=high
    
    - name: Run OWASP Dependency Check
      uses: dependency-check/Dependency-Check_Action@main
      with:
        project: 'node-app'
        path: '.'
        format: 'HTML'
        args: >
          --failOnCVSS 7
          --enableRetired
    
    - name: Run secret scanning
      uses: gitleaks/gitleaks-action@v2
      with:
        config-path: .gitleaks.toml
    
    - name: Run SAST with CodeQL
      uses: github/codeql-action/analyze@v2
      with:
        category: '/language:javascript'

  # Performance Testing
  performance-test:
    name: Performance Test
    runs-on: ubuntu-latest
    needs: deploy-staging
    if: github.ref == 'refs/heads/develop'
    timeout-minutes: 20
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Run k6 performance tests
      uses: grafana/k6-action@v0.3.1
      with:
        filename: tests/performance/load-test.js
        flags: --out json=test-results.json --summary-export=summary.json
    
    - name: Upload performance test results
      uses: actions/upload-artifact@v4
      with:
        name: performance-results
        path: |
          test-results.json
          summary.json
    
    - name: Check performance thresholds
      run: |
        node scripts/check-performance.js summary.json
```

#### **Docker Build Optimization**

```yaml
# .github/workflows/docker-optimized.yml
name: Optimized Docker Build

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        platform: [linux/amd64, linux/arm64]
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
      with:
        driver-opts: |
          image=moby/buildkit:master
          network=host
    
    - name: Cache Docker layers
      uses: actions/cache@v3
      with:
        path: /tmp/.buildx-cache
        key: ${{ runner.os }}-buildx-${{ github.sha }}
        restore-keys: |
          ${{ runner.os }}-buildx-
    
    - name: Login to DockerHub
      uses: docker/login-action@v3
      with:
        username: ${{ secrets.DOCKERHUB_USERNAME }}
        password: ${{ secrets.DOCKERHUB_TOKEN }}
    
    - name: Build and push
      uses: docker/build-push-action@v5
      with:
        context: .
        platforms: ${{ matrix.platform }}
        push: true
        tags: |
          user/app:latest
          user/app:${{ github.sha }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        outputs: type=image,name=user/app,push=true
```

#### **Rollback Workflow**

```yaml
# .github/workflows/rollback.yml
name: Rollback Deployment

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to rollback'
        required: true
        default: 'staging'
        type: choice
        options:
        - staging
        - production
      version:
        description: 'Version to rollback to (leave empty for previous)'
        required: false
        type: string

jobs:
  rollback:
    runs-on: ubuntu-latest
    environment: ${{ github.event.inputs.environment }}
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-east-1
    
    - name: Get previous task definition
      id: get-previous
      run: |
        # Get current task definition ARN
        CURRENT_TASK_DEF=$(aws ecs describe-services \
          --cluster ${{ github.event.inputs.environment }}-cluster \
          --services node-app-${{ github.event.inputs.environment }} \
          --query 'services[0].taskDefinition' \
          --output text)
        
        # Get previous task definition
        PREVIOUS_TASK_DEF=$(aws ecs describe-task-definition \
          --task-definition $(echo $CURRENT_TASK_DEF | cut -d: -f1-2) \
          --query 'taskDefinition.revision' \
          --output text)
        
        PREVIOUS_REVISION=$((PREVIOUS_TASK_DEF - 1))
        
        echo "previous_revision=$PREVIOUS_REVISION" >> $GITHUB_OUTPUT
    
    - name: Rollback to previous version
      run: |
        aws ecs update-service \
          --cluster ${{ github.event.inputs.environment }}-cluster \
          --service node-app-${{ github.event.inputs.environment }} \
          --task-definition node-app-${{ github.event.inputs.environment }}:${{ steps.get-previous.outputs.previous_revision }} \
          --force-new-deployment
    
    - name: Notify rollback
      uses: 8398a7/action-slack@v3
      with:
        status: custom
        fields: workflow,job,commit,author
        custom_payload: |
          {
            "attachments": [{
              "color": "#FF0000",
              "title": "Rollback Initiated",
              "text": "Rolled back ${{ github.event.inputs.environment }} to previous version",
              "fields": [
                {
                  "title": "Environment",
                  "value": "${{ github.event.inputs.environment }}",
                  "short": true
                },
                {
                  "title": "Initiator",
                  "value": "${{ github.actor }}",
                  "short": true
                }
              ]
            }]
          }
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### 🎯 Real-World Scenario: Enterprise CI/CD Pipeline
*You're building a CI/CD pipeline for a financial services application with strict compliance requirements. The pipeline must include security scanning, compliance checks, audit trails, and approval workflows.*

**Interview Questions:**
1. How would you design a CI/CD pipeline for regulated industries?
2. What security scanning tools would you integrate?
3. How do you implement approval workflows for production deployments?
4. What strategies would you use for rollbacks and disaster recovery?
5. How do you maintain audit trails of all deployments?

**Technical Questions:**
1. How do you handle secret management in GitHub Actions?
2. What are matrix builds and when should you use them?
3. How do you optimize Docker layer caching in CI/CD?
4. What's the difference between blue-green and canary deployments?

---

## 8. Railway / Render / Fly.io

### 📖 In-Depth Explanation

Platform-as-a-Service (PaaS) solutions simplify deployment by abstracting infrastructure management.

#### **Railway Deployment Configuration**

```json
// railway.json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS",
    "buildCommand": "npm run build",
    "watchPatterns": ["src/**", "package.json"],
    "nixpacksConfig": {
      "phases": {
        "setup": {
          "aptPkgs": ["python3", "make", "g++"]
        },
        "install": {
          "cmd": "npm ci"
        },
        "build": {
          "cmd": "npm run build"
        }
      },
      "startCmd": "npm start"
    }
  },
  "deploy": {
    "numReplicas": 2,
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 3,
    "healthcheckPath": "/health",
    "healthcheckTimeout": 5,
    "sleepApplication": false
  },
  "variables": {
    "NODE_ENV": "production",
    "PORT": "3000",
    "DATABASE_URL": {
      "description": "PostgreSQL connection string",
      "required": true
    },
    "REDIS_URL": {
      "description": "Redis connection URL",
      "required": false
    },
    "JWT_SECRET": {
      "description": "Secret for JWT tokens",
      "generator": "secret"
    }
  },
  "plugins": [
    {
      "name": "postgresql",
      "type": "postgresql",
      "version": "15",
      "variables": {
        "POSTGRES_DB": "appdb",
        "POSTGRES_USER": "appuser"
      }
    },
    {
      "name": "redis",
      "type": "redis",
      "version": "7"
    }
  ],
  "crons": [
    {
      "command": "node scripts/cleanup.js",
      "schedule": "0 2 * * *"
    },
    {
      "command": "node scripts/backup.js",
      "schedule": "0 0 * * 0"
    }
  ]
}
```

#### **Render Blueprint Configuration**

```yaml
# render.yaml
services:
  # Node.js API Service
  - type: web
    name: node-api
    env: node
    region: oregon
    plan: starter
    numInstances: 2
    healthCheckPath: /health
    autoDeploy: true
    branch: main
    
    buildCommand: npm ci && npm run build
    startCommand: npm start
    
    envVars:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: 3000
      - key: DATABASE_URL
        fromDatabase:
          name: app-db
          property: connectionString
      - key: REDIS_URL
        fromService:
          type: redis
          name: app-redis
          property: connectionString
      - key: JWT_SECRET
        generateValue: true
      - key: SENTRY_DSN
        sync: false
    
    headers:
      - path: /*
        name: X-Frame-Options
        value: DENY
      - path: /*
        name: X-Content-Type-Options
        value: nosniff
      - path: /*
        name: X-XSS-Protection
        value: 1; mode=block
    
    scaling:
      minInstances: 2
      maxInstances: 10
      targetMemoryPercent: 80
      targetCPUPercent: 70
    
    disk:
      name: data
      mountPath: /data
      sizeGB: 10

  # PostgreSQL Database
  - type: pgsql
    name: app-db
    plan: starter
    ipAllowList: []
    databaseName: appdb
    user: appuser

  # Redis Instance
  - type: redis
    name: app-redis
    plan: starter
    ipAllowList: []
    maxmemoryPolicy: allkeys-lru

  # Static Site
  - type: static
    name: frontend
    env: static
    buildCommand: npm run build
    staticPublishPath: ./dist
    headers:
      - path: /*
        name: Cache-Control
        value: public, max-age=31536000, immutable
    routes:
      - type: rewrite
        source: /*
        destination: /index.html

  # Cron Job
  - type: cron
    name: cleanup-job
    schedule: "0 2 * * *"
    env: node
    buildCommand: npm ci
    startCommand: node scripts/cleanup.js
    envVars:
      - key: NODE_ENV
        value: production
      - key: DATABASE_URL
        fromDatabase:
          name: app-db
          property: connectionString

databases:
  - name: app-db-backup
    plan: starter
    databaseName: backupdb
    schedule: "0 0 * * 0"
    retentionPeriod: 30
```

#### **Fly.io Configuration**

```toml
# fly.toml
app = "node-api-production"
primary_region = "iad"
kill_signal = "SIGTERM"
kill_timeout = 5

[build]
  builder = "heroku/buildpacks:20"

[build.args]
  NODE_ENV = "production"

[http_service]
  internal_port = 3000
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 2
  
  [[http_service.checks]]
    interval = "10s"
    timeout = "2s"
    grace_period = "5s"
    method = "GET"
    path = "/health"
    protocol = "http"
    
    [http_service.checks.headers]
      Content-Type = "application/json"
    
  [[http_service.checks]]
    interval = "30s"
    timeout = "2s"
    method = "GET"
    path = "/metrics"
    protocol = "http"

[metrics]
  port = 3000
  path = "/metrics"

[env]
  NODE_ENV = "production"
  PORT = "3000"
  LOG_LEVEL = "info"

[experimental]
  cmd = ["node", "dist/app.js"]
  entrypoint = ["npm", "start"]
  auto_rollback = true

[[vm]]
  cpu_kind = "shared"
  cpus = 2
  memory_mb = 1024
  
  [vm.guest]
    cpu_kind = "shared"
    memory_mb = 1024
  
  [vm.processes]
    app = "npm start"

[mounts]
  source = "app_data"
  destination = "/data"

[[statics]]
  guest_path = "/app/public"
  url_prefix = "/static"

[services.concurrency]
  type = "connections"
  hard_limit = 1000
  soft_limit = 750

[[services.ports]]
  port = 443
  handlers = ["tls", "http"]

[[services.tcp_checks]]
  interval = "15s"
  timeout = "2s"
  grace_period = "1s"

[deploy]
  strategy = "rolling"
  max_unavailable = 0
  wait_health_checks = true

# Secrets management
# fly secrets set DATABASE_URL=postgres://... JWT_SECRET=...

# Scale configuration
# fly scale count 3
# fly scale memory 2048
```

#### **Dockerfile for PaaS Deployment**

```dockerfile
# Dockerfile.paas
# Multi-stage build optimized for PaaS
FROM node:18-alpine AS base

# Install dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    curl \
    tini

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application
COPY . .

# Build if needed
RUN if [ -f "package.json" ] && grep -q "\"build\"" package.json; then \
    npm run build; \
    fi

# Use tini as init process
ENTRYPOINT ["/sbin/tini", "--"]

# Run as non-root user
USER node

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => { \
        if (r.statusCode !== 200) process.exit(1) \
    }).on('error', () => process.exit(1))"

# Start application
CMD ["node", "dist/app.js"]
```

#### **Platform Comparison Table**

| Feature | Railway | Render | Fly.io |
|---------|---------|---------|--------|
| **Pricing** | Pay-as-you-go | Fixed plans + usage | Pay-as-you-go |
| **Scaling** | Auto-scaling | Manual/Auto | Auto-scaling |
| **Regions** | Multiple | Multiple | Global |
| **Database** | Built-in plugins | Built-in services | External only |
| **Redis** | Plugin available | Built-in service | External only |
| **CDN** | Built-in | Built-in | Global edge |
| **Deployment** | Git-based | Git-based | CLI-based |
| **WebSockets** | Supported | Supported | Supported |
| **Cron Jobs** | Supported | Supported | Worker processes |
| **File Storage** | Volumes | Persistent disks | Volumes |
| **Logging** | Built-in | Built-in | Built-in + external |
| **Monitoring** | Basic metrics | Basic metrics | Advanced metrics |
| **Support** | Community + Pro | Email + Priority | Community + Enterprise |

#### **Deployment Script for Multiple Platforms**

```bash
#!/bin/bash
# deploy.sh

set -e  # Exit on error

ENVIRONMENT=${1:-staging}
PLATFORM=${2:-railway}

deploy_railway() {
    echo "Deploying to Railway..."
    
    # Set environment
    if [ "$ENVIRONMENT" = "production" ]; then
        RAILWAY_ENVIRONMENT="production"
    else
        RAILWAY_ENVIRONMENT="staging"
    fi
    
    # Deploy using Railway CLI
    railway up \
        --environment $RAILWAY_ENVIRONMENT \
        --detach
    
    # Wait for deployment
    railway logs \
        --environment $RAILWAY_ENVIRONMENT \
        --follow \
        --tail 100
    
    # Run health check
    RAILWAY_URL=$(railway status --environment $RAILWAY_ENVIRONMENT --json | jq -r '.service.domain')
    
    echo "Deployment URL: https://$RAILWAY_URL"
    
    # Run smoke tests
    npm run test:smoke --url=https://$RAILWAY_URL
}

deploy_render() {
    echo "Deploying to Render..."
    
    # Deploy using Render CLI
    render deploy
    
    # Get deployment status
    DEPLOYMENT_ID=$(render deployments list --format json | jq -r '.[0].id')
    
    # Wait for deployment
    while true; do
        STATUS=$(render deployments info $DEPLOYMENT_ID --format json | jq -r '.status')
        echo "Deployment status: $STATUS"
        
        if [ "$STATUS" = "live" ]; then
            break
        elif [ "$STATUS" = "failed" ]; then
            echo "Deployment failed"
            exit 1
        fi
        
        sleep 5
    done
    
    # Get service URL
    SERVICE_URL=$(render services list --format json | jq -r '.[0].serviceDetails.url')
    
    echo "Deployment URL: $SERVICE_URL"
    
    # Run smoke tests
    npm run test:smoke --url=$SERVICE_URL
}

deploy_fly() {
    echo "Deploying to Fly.io..."
    
    # Set app name based on environment
    if [ "$ENVIRONMENT" = "production" ]; then
        FLY_APP="node-api-production"
    else
        FLY_APP="node-api-staging"
    fi
    
    # Deploy using Fly CLI
    fly deploy \
        --app $FLY_APP \
        --region iad \
        --strategy rolling \
        --wait-timeout 300
    
    # Get app info
    fly apps info --app $FLY_APP
    
    # Get app URL
    APP_URL=$(fly status --app $FLY_APP --json | jq -r '.Hostname')
    
    echo "Deployment URL: https://$APP_URL"
    
    # Scale if production
    if [ "$ENVIRONMENT" = "production" ]; then
        fly scale count 3 --app $FLY_APP
        fly scale memory 2048 --app $FLY_APP
    fi
    
    # Run smoke tests
    npm run test:smoke --url=https://$APP_URL
}

# Main deployment logic
case $PLATFORM in
    railway)
        deploy_railway
        ;;
    render)
        deploy_render
        ;;
    fly)
        deploy_fly
        ;;
    *)
        echo "Unknown platform: $PLATFORM"
        echo "Available platforms: railway, render, fly"
        exit 1
        ;;
esac

# Send deployment notification
send_notification() {
    local platform=$1
    local environment=$2
    local url=$3
    
    curl -X POST $SLACK_WEBHOOK_URL \
        -H 'Content-type: application/json' \
        -d "{
            \"text\": \"Deployment completed!\",
            \"blocks\": [
                {
                    \"type\": \"section\",
                    \"text\": {
                        \"type\": \"mrkdwn\",
                        \"text\": \"*Deployment Completed* :rocket:\"
                    }
                },
                {
                    \"type\": \"section\",
                    \"fields\": [
                        {
                            \"type\": \"mrkdwn\",
                            \"text\": \"*Platform:*\n$platform\"
                        },
                        {
                            \"type\": \"mrkdwn\",
                            \"text\": \"*Environment:*\n$environment\"
                        },
                        {
                            \"type\": \"mrkdwn\",
                            \"text\": \"*URL:*\n$url\"
                        },
                        {
                            \"type\": \"mrkdwn\",
                            \"text\": \"*Time:*\n$(date)\"
                        }
                    ]
                }
            ]
        }"
}

# Call notification
send_notification $PLATFORM $ENVIRONMENT $DEPLOYMENT_URL
```

### 🎯 Real-World Scenario: Startup Application Deployment
*You're a technical co-founder building a SaaS product. You need to deploy quickly, scale automatically, keep costs low, and focus on development rather than infrastructure management.*

**Interview Questions:**
1. Which PaaS would you choose for a startup and why?
2. How would you handle database backups and disaster recovery?
3. What cost optimization strategies would you implement?
4. How do you monitor application performance on PaaS?
5. What's your strategy for migrating from PaaS to your own infrastructure?

**Technical Questions:**
1. How do you handle file uploads on stateless PaaS platforms?
2. What are the limitations of PaaS compared to IaaS?
3. How do you implement zero-downtime deployments on PaaS?
4. What are the security considerations when using PaaS?

---

## 📊 Summary & Best Practices

### Deployment Strategy Checklist

1. **Infrastructure as Code**: Use Terraform/CloudFormation
2. **Containerization**: Docker for consistency
3. **Process Management**: PM2 for Node.js applications
4. **Reverse Proxy**: Nginx for SSL termination and load balancing
5. **SSL/TLS**: Automated certificates with Let's Encrypt
6. **Environment Management**: Centralized secrets management
7. **CI/CD**: Automated pipelines with GitHub Actions
8. **Monitoring**: Health checks, logging, and metrics
9. **Backup Strategy**: Automated database and file backups
10. **Disaster Recovery**: Rollback procedures and backups

### Cost Optimization

| Platform | Strategy | Estimated Monthly Cost* |
|----------|----------|------------------------|
| **AWS EC2** | Use spot instances, auto-scaling | $50-500 |
| **Railway** | Pay-as-you-go, auto-scaling | $20-200 |
| **Render** | Fixed plans + usage | $25-250 |
| **Fly.io** | Pay-as-you-go, global edge | $30-300 |

*For small to medium applications

### Security Checklist

1. ✅ Use non-root users in containers
2. ✅ Implement SSL/TLS with strong ciphers
3. ✅ Regular security updates and patches
4. ✅ Network security groups/firewalls
5. ✅ Secret management (not in code)
6. ✅ Regular vulnerability scanning
7. ✅ DDoS protection and rate limiting
8. ✅ Audit logging and monitoring
9. ✅ Backup encryption
10. ✅ Incident response plan

## 🚀 Quick Start Guide

### Option 1: Simple PaaS Deployment (5 minutes)

```bash
# Deploy to Railway
npm install -g @railway/cli
railway login
railway init
railway up

# Or deploy to Render
curl -o- https://cli.render.com/install.sh | bash
render deploy
```

### Option 2: Self-hosted on EC2 (30 minutes)

```bash
# Clone deployment scripts
git clone https://github.com/your-org/node-deployment
cd node-deployment

# Setup infrastructure
cd infrastructure
terraform init
terraform apply

# Deploy application
./scripts/deploy.sh production
```

### Option 3: Docker + CI/CD (15 minutes)

1. Push code to GitHub
2. GitHub Actions will automatically:
   - Run tests
   - Build Docker image
   - Push to registry
   - Deploy to your infrastructure

## 📚 Additional Resources

- [Node.js Production Best Practices](https://github.com/goldbergyoni/nodebestpractices)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Nginx Configuration Generator](https://nginxconfig.io/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [GitHub Actions Marketplace](https://github.com/marketplace?type=actions)
- [PM2 Documentation](https://pm2.keymetrics.io/docs/usage/pm2-doc-single-page/)

---

> **Note**: Always test deployment procedures in staging before production. Monitor application performance and costs regularly. Keep documentation updated with any changes to the deployment process.