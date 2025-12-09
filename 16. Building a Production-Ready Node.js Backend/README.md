# Production-Ready Node.js Backend Guide

## 📖 Table of Contents
1. [Logging & Log Rotation](#1-logging--log-rotation)
2. [PM2 Ecosystem File](#2-pm2-ecosystem-file)
3. [API Monitoring](#3-api-monitoring)
4. [Rate Limiting](#4-rate-limiting)
5. [Alerts](#5-alerts)
6. [Caching Architecture](#6-caching-architecture)
7. [Graceful Shutdown](#7-graceful-shutdown)
8. [Docker Containerization](#8-docker-containerization)
9. [CI/CD Pipelines](#9-cicd-pipelines)
10. [Nginx Reverse Proxy](#10-nginx-reverse-proxy)
11. [Health Checks](#11-health-checks)
12. [Scaling Node.js](#12-scaling-nodejs)
13. [Interview Questions](#13-interview-questions)

---

## 1. Logging & Log Rotation

### In-Depth Explanation
Production logging requires structured, queryable logs with automatic rotation to prevent disk exhaustion. Use Winston or Pino for structured logging and winston-daily-rotate-file for rotation.

### Implementation Example

```javascript
// logger.js
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new DailyRotateFile({
      filename: 'logs/application-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d',
      zippedArchive: true,
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Structured logging example
logger.info('User login', { 
  userId: '12345', 
  ip: '192.168.1.1',
  timestamp: new Date().toISOString()
});

module.exports = logger;
```

### Log Levels
- **ERROR**: Operational errors, failed dependencies
- **WARN**: Unusual situations that aren't errors
- **INFO**: Service lifecycle events, business transactions
- **DEBUG**: Detailed information for debugging
- **TRACE**: Most detailed information

---

## 2. PM2 Ecosystem File

### In-Depth Explanation
PM2 manages Node.js processes in production with features like clustering, zero-downtime reload, and monitoring. The ecosystem file configures deployment settings.

### Implementation Example

```javascript
// ecosystem.config.js
module.exports = {
  apps: [{
    name: 'api-server',
    script: './dist/server.js',
    instances: 'max', // Use all CPU cores
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 8080,
      NODE_OPTIONS: '--max-old-space-size=1024'
    },
    error_file: './logs/pm2-err.log',
    out_file: './logs/pm2-out.log',
    log_file: './logs/pm2-combined.log',
    time: true,
    merge_logs: true,
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    watch: false,
    max_memory_restart: '1G',
    kill_timeout: 5000,
    wait_ready: true,
    listen_timeout: 5000,
    autorestart: true,
    max_restarts: 10,
    restart_delay: 4000
  }],

  deploy: {
    production: {
      user: 'ubuntu',
      host: ['server1.example.com', 'server2.example.com'],
      ref: 'origin/main',
      repo: 'git@github.com:user/repo.git',
      path: '/var/www/api',
      'post-deploy': 'npm install && npm run build && pm2 reload ecosystem.config.js --env production',
      env: {
        NODE_ENV: 'production'
      }
    }
  }
};
```

### PM2 Commands
```bash
# Start with ecosystem file
pm2 start ecosystem.config.js --env production

# Monitor application
pm2 monit

# Show logs
pm2 logs api-server --lines 100

# Zero-downtime reload
pm2 reload api-server

# Save process list
pm2 save
pm2 startup
```

---

## 3. API Monitoring

### In-Depth Explanation
Monitoring tracks system health, performance metrics, and business KPIs. Use tools like Prometheus for metrics, Grafana for visualization, and Application Performance Monitoring (APM) tools.

### Implementation Example

```javascript
// metrics.js
const client = require('prom-client');
const responseTime = require('response-time');

// Create metrics registry
const register = new client.Registry();
client.collectDefaultMetrics({ register });

// Custom metrics
const httpRequestDurationMicroseconds = new client.Histogram({
  name: 'http_request_duration_ms',
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'code'],
  buckets: [0.1, 5, 15, 50, 100, 200, 300, 400, 500]
});

const activeRequests = new client.Gauge({
  name: 'active_requests',
  help: 'Number of active requests'
});

register.registerMetric(httpRequestDurationMicroseconds);
register.registerMetric(activeRequests);

// Middleware to track metrics
const metricsMiddleware = responseTime((req, res, time) => {
  httpRequestDurationMicroseconds
    .labels(req.method, req.route?.path || req.url, res.statusCode)
    .observe(time);
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

module.exports = { metricsMiddleware, activeRequests };
```

### Key Metrics to Track
1. **System Metrics**: CPU, Memory, Disk I/O
2. **Application Metrics**: Request rate, Error rate, Response time
3. **Business Metrics**: User signups, Transactions, Revenue
4. **Dependency Metrics**: Database query time, External API latency

---

## 4. Rate Limiting

### In-Depth Explanation
Rate limiting protects against DDoS attacks, brute force attempts, and ensures fair resource usage. Implement multi-level rate limiting (IP, User, API Key).

### Implementation Example

```javascript
// rateLimiter.js
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');

// Redis client for distributed rate limiting
const redisClient = new Redis(process.env.REDIS_URL);

// Global rate limiter (loose)
const globalLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:global:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

// Strict limiter for auth endpoints
const authLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:auth:'
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per hour
  message: 'Too many login attempts, please try again later.',
  skipSuccessfulRequests: true
});

// API key based rate limiting
const createApiKeyLimiter = (requestsPerMinute) => rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:apikey:'
  }),
  keyGenerator: (req) => req.headers['x-api-key'] || req.ip,
  windowMs: 60 * 1000,
  max: requestsPerMinute
});

// Sliding window counter implementation
class SlidingWindowCounter {
  constructor(maxRequests, windowSize) {
    this.maxRequests = maxRequests;
    this.windowSize = windowSize;
    this.requests = new Map();
  }

  isAllowed(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowSize;
    
    if (!this.requests.has(identifier)) {
      this.requests.set(identifier, []);
    }
    
    const timestamps = this.requests.get(identifier);
    
    // Remove old timestamps
    while (timestamps.length > 0 && timestamps[0] < windowStart) {
      timestamps.shift();
    }
    
    if (timestamps.length >= this.maxRequests) {
      return false;
    }
    
    timestamps.push(now);
    return true;
  }
}

module.exports = { globalLimiter, authLimiter, createApiKeyLimiter };
```

---

## 5. Alerts

### In-Depth Explanation
Proactive alerting system that notifies teams about critical issues before they affect users. Use PagerDuty, Opsgenie, or custom webhooks.

### Implementation Example

```javascript
// alerting.js
const axios = require('axios');
const winston = require('winston');

class AlertManager {
  constructor() {
    this.alertCooldowns = new Map();
    this.cooldownPeriod = 300000; // 5 minutes
  }

  async sendAlert(type, severity, message, metadata = {}) {
    const alertKey = `${type}:${severity}`;
    const lastAlert = this.alertCooldowns.get(alertKey);
    
    // Cooldown check
    if (lastAlert && Date.now() - lastAlert < this.cooldownPeriod) {
      return;
    }

    this.alertCooldowns.set(alertKey, Date.now());

    const alertPayload = {
      type,
      severity: severity.toUpperCase(),
      message,
      timestamp: new Date().toISOString(),
      service: process.env.SERVICE_NAME || 'node-api',
      environment: process.env.NODE_ENV || 'development',
      metadata
    };

    // Send to multiple destinations
    const promises = [];

    // 1. Log
    winston.error('ALERT', alertPayload);

    // 2. PagerDuty
    if (process.env.PAGERDUTY_API_KEY) {
      promises.push(this.sendToPagerDuty(alertPayload));
    }

    // 3. Slack
    if (process.env.SLACK_WEBHOOK_URL) {
      promises.push(this.sendToSlack(alertPayload));
    }

    // 4. Email (SES/SendGrid)
    if (process.env.ALERT_EMAIL_RECIPIENTS) {
      promises.push(this.sendEmail(alertPayload));
    }

    await Promise.allSettled(promises);
  }

  async sendToPagerDuty(payload) {
    const pagerDutyEvent = {
      routing_key: process.env.PAGERDUTY_API_KEY,
      event_action: payload.severity === 'CRITICAL' ? 'trigger' : 'acknowledge',
      dedup_key: `${payload.type}-${payload.timestamp}`,
      payload: {
        summary: payload.message,
        source: payload.service,
        severity: payload.severity.toLowerCase(),
        custom_details: payload.metadata
      }
    };

    return axios.post('https://events.pagerduty.com/v2/enqueue', pagerDutyEvent);
  }

  async sendToSlack(payload) {
    const color = {
      CRITICAL: '#FF0000',
      HIGH: '#FFA500',
      MEDIUM: '#FFFF00',
      LOW: '#00FF00'
    }[payload.severity] || '#808080';

    const slackMessage = {
      attachments: [{
        color,
        title: `${payload.severity} Alert: ${payload.type}`,
        text: payload.message,
        fields: Object.entries(payload.metadata).map(([key, value]) => ({
          title: key,
          value: String(value),
          short: true
        })),
        footer: `${payload.service} • ${payload.environment}`,
        ts: Math.floor(new Date(payload.timestamp).getTime() / 1000)
      }]
    };

    return axios.post(process.env.SLACK_WEBHOOK_URL, slackMessage);
  }

  // Alert conditions
  checkResponseTime(req, res, time) {
    if (time > 1000) { // 1 second threshold
      this.sendAlert('HIGH_LATENCY', 'HIGH', 
        `Response time exceeded threshold: ${time}ms`,
        { path: req.path, method: req.method, time }
      );
    }
  }

  checkErrorRate(errorCount, totalRequests, windowMinutes = 5) {
    const errorRate = (errorCount / totalRequests) * 100;
    if (errorRate > 5) { // 5% error rate threshold
      this.sendAlert('HIGH_ERROR_RATE', 'CRITICAL',
        `Error rate exceeded threshold: ${errorRate.toFixed(2)}%`,
        { errorCount, totalRequests, errorRate, windowMinutes }
      );
    }
  }
}

module.exports = new AlertManager();
```

---

## 6. Caching Architecture

### In-Depth Explanation
Multi-layer caching strategy to reduce database load and improve response times. Implement in-memory, Redis, and CDN caching with appropriate invalidation strategies.

### Implementation Example

```javascript
// cacheManager.js
const Redis = require('ioredis');
const NodeCache = require('node-cache');

class CacheManager {
  constructor() {
    // L1: In-memory cache (fast, limited size)
    this.l1Cache = new NodeCache({
      stdTTL: 60, // 60 seconds default
      checkperiod: 120,
      useClones: false
    });

    // L2: Redis cache (distributed, persistent)
    this.redis = new Redis.Cluster([
      { host: process.env.REDIS_HOST, port: process.env.REDIS_PORT }
    ], {
      scaleReads: 'slave',
      redisOptions: {
        password: process.env.REDIS_PASSWORD
      }
    });

    this.redis.on('error', (err) => {
      console.error('Redis connection error:', err);
    });
  }

  async get(key, fetchFn, ttl = 300) {
    // Try L1 cache first
    const l1Value = this.l1Cache.get(key);
    if (l1Value !== undefined) {
      return l1Value;
    }

    // Try L2 (Redis) cache
    try {
      const l2Value = await this.redis.get(key);
      if (l2Value !== null) {
        const parsedValue = JSON.parse(l2Value);
        // Populate L1 cache
        this.l1Cache.set(key, parsedValue, ttl);
        return parsedValue;
      }
    } catch (error) {
      console.error('Redis get error:', error);
    }

    // Fetch from source
    const freshData = await fetchFn();
    
    // Update caches
    this.l1Cache.set(key, freshData, ttl);
    try {
      await this.redis.setex(key, ttl, JSON.stringify(freshData));
    } catch (error) {
      console.error('Redis set error:', error);
    }

    return freshData;
  }

  async invalidate(pattern) {
    // Invalidate L1 cache
    const keys = this.l1Cache.keys();
    keys.forEach(key => {
      if (key.includes(pattern)) {
        this.l1Cache.del(key);
      }
    });

    // Invalidate L2 cache
    try {
      const stream = this.redis.scanStream({
        match: `*${pattern}*`
      });
      
      const pipeline = this.redis.pipeline();
      stream.on('data', (keys) => {
        keys.forEach(key => pipeline.del(key));
      });
      
      return new Promise((resolve) => {
        stream.on('end', () => {
          pipeline.exec().then(resolve);
        });
      });
    } catch (error) {
      console.error('Redis invalidation error:', error);
    }
  }

  // Cache stampede prevention
  async getWithLock(key, fetchFn, ttl = 300) {
    const lockKey = `${key}:lock`;
    const now = Date.now();
    
    try {
      // Try to acquire lock
      const acquired = await this.redis.setnx(lockKey, now);
      
      if (acquired) {
        // Set lock expiration
        await this.redis.expire(lockKey, 10);
        
        try {
          const data = await fetchFn();
          await this.redis.setex(key, ttl, JSON.stringify(data));
          return data;
        } finally {
          await this.redis.del(lockKey);
        }
      } else {
        // Wait for other process to populate cache
        await new Promise(resolve => setTimeout(resolve, 100));
        return this.get(key, fetchFn, ttl);
      }
    } catch (error) {
      console.error('Cache lock error:', error);
      return fetchFn();
    }
  }
}

module.exports = new CacheManager();
```

---

## 7. Graceful Shutdown

### In-Depth Explanation
Properly handle process termination to complete ongoing requests, close database connections, and clean up resources before exiting.

### Implementation Example

```javascript
// gracefulShutdown.js
const logger = require('./logger');

class GracefulShutdown {
  constructor(server) {
    this.server = server;
    this.isShuttingDown = false;
    this.healthCheck = { status: 'healthy' };
    
    this.setupSignalHandlers();
    this.setupProcessHandlers();
  }

  setupSignalHandlers() {
    const signals = ['SIGTERM', 'SIGINT', 'SIGHUP'];
    
    signals.forEach(signal => {
      process.on(signal, () => {
        logger.info(`Received ${signal}, starting graceful shutdown`);
        this.shutdown();
      });
    });
  }

  setupProcessHandlers() {
    // Uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      this.shutdown(1);
    });

    // Unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
      this.shutdown(1);
    });
  }

  async shutdown(exitCode = 0) {
    if (this.isShuttingDown) {
      return;
    }
    
    this.isShuttingDown = true;
    this.healthCheck.status = 'unhealthy';
    
    logger.info('Graceful shutdown initiated');
    
    const shutdownPromises = [];
    
    // 1. Stop accepting new connections
    if (this.server) {
      shutdownPromises.push(new Promise((resolve) => {
        this.server.close(() => {
          logger.info('HTTP server closed');
          resolve();
        });
        
        // Force close after timeout
        setTimeout(() => {
          logger.warn('Forcing HTTP server close');
          resolve();
        }, 10000);
      }));
    }
    
    // 2. Close database connections
    if (this.closeDatabaseConnections) {
      shutdownPromises.push(this.closeDatabaseConnections());
    }
    
    // 3. Close Redis connections
    if (this.closeRedisConnections) {
      shutdownPromises.push(this.closeRedisConnections());
    }
    
    // 4. Wait for ongoing requests (if tracking)
    if (this.waitForOngoingRequests) {
      shutdownPromises.push(this.waitForOngoingRequests());
    }
    
    try {
      await Promise.allSettled(shutdownPromises);
      logger.info('Graceful shutdown completed');
      process.exit(exitCode);
    } catch (error) {
      logger.error('Error during shutdown:', error);
      process.exit(1);
    }
  }

  // Middleware to track ongoing requests
  trackRequests() {
    let ongoingRequests = 0;
    
    return (req, res, next) => {
      if (this.isShuttingDown) {
        res.setHeader('Connection', 'close');
        res.status(503).json({ error: 'Service unavailable' });
        return;
      }
      
      ongoingRequests++;
      res.on('finish', () => {
        ongoingRequests--;
      });
      
      next();
    };
  }

  waitForOngoingRequests() {
    return new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        // Implement request tracking logic
        if (/* no ongoing requests */ true) {
          clearInterval(checkInterval);
          resolve();
        }
      }, 100);
    });
  }
}

module.exports = GracefulShutdown;
```

---

## 8. Docker Containerization

### In-Depth Explanation
Containerization ensures consistency across environments and simplifies deployment. Use multi-stage builds for smaller images and follow security best practices.

### Implementation Example

```dockerfile
# Dockerfile
# Stage 1: Builder
FROM node:18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY yarn.lock ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source
COPY . .

# Build TypeScript/JavaScript
RUN npm run build

# Remove dev dependencies
RUN rm -rf node_modules && npm ci --only=production --ignore-scripts

# Stage 2: Runtime
FROM node:18-alpine

# Install runtime dependencies
RUN apk add --no-cache tini curl

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Copy from builder
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./

# Switch to non-root user
USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Use tini as init process
ENTRYPOINT ["/sbin/tini", "--"]

# Command to run
CMD ["node", "dist/server.js"]
```

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  api:
    build:
      context: .
      target: runtime
    container_name: node-api
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=postgresql://user:pass@postgres:5432/db
    depends_on:
      - postgres
      - redis
    networks:
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

  postgres:
    image: postgres:14-alpine
    container_name: postgres-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: db
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - backend
    command: postgres -c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track=all

  redis:
    image: redis:7-alpine
    container_name: redis-cache
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - backend

  nginx:
    image: nginx:alpine
    container_name: nginx-proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - api
    networks:
      - backend

networks:
  backend:
    driver: bridge

volumes:
  postgres_data:
  redis_data:
```

---

## 9. CI/CD Pipelines

### In-Depth Explanation
Automated pipeline for building, testing, and deploying with quality gates, security scans, and rollback capabilities.

### Implementation Examples

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Lint code
      run: npm run lint
    
    - name: Run tests with coverage
      run: |
        npm test
        npm run test:integration
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/postgres
        REDIS_URL: redis://localhost:6379
    
    - name: Security audit
      run: npm audit --audit-level=high
    
    - name: Run SAST
      uses: github/codeql-action/analyze@v2
    
    - name: Upload coverage reports
      uses: codecov/codecov-action@v3

  build-and-push:
    needs: test
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Log in to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v4
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=sha,prefix={{branch}}-
          type=ref,event=branch
          type=semver,pattern={{version}}
          type=raw,value=latest
    
    - name: Build and push
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
    
    - name: Scan image for vulnerabilities
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    environment: production
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Deploy to Kubernetes
      uses: appleboy/ssh-action@v0.1.5
      with:
        host: ${{ secrets.PRODUCTION_HOST }}
        username: ${{ secrets.PRODUCTION_USER }}
        key: ${{ secrets.PRODUCTION_SSH_KEY }}
        script: |
          kubectl set image deployment/node-api \
            node-api=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          kubectl rollout status deployment/node-api --timeout=300s
    
    - name: Run smoke tests
      run: |
        curl -f https://api.example.com/health
        npm run test:smoke
    
    - name: Notify Slack
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        text: Deployment completed successfully!
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

---

## 10. Nginx Reverse Proxy

### In-Depth Explanation
Nginx acts as a reverse proxy for load balancing, SSL termination, caching, and security. Configure for high performance and security.

### Implementation Example

```nginx
# nginx.conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';
    
    access_log /var/log/nginx/access.log main buffer=32k flush=5s;
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
    
    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        application/javascript
        application/json
        application/xml
        text/css
        text/javascript
        text/plain
        text/xml;
    
    # Upstream for Node.js servers
    upstream node_backend {
        least_conn;
        server api1:3000 max_fails=3 fail_timeout=30s;
        server api2:3000 max_fails=3 fail_timeout=30s;
        server api3:3000 max_fails=3 fail_timeout=30s;
        keepalive 32;
    }
    
    # Main server block
    server {
        listen 80;
        server_name api.example.com;
        
        # Redirect to HTTPS
        return 301 https://$server_name$request_uri;
    }
    
    server {
        listen 443 ssl http2;
        server_name api.example.com;
        
        # SSL Configuration
        ssl_certificate /etc/nginx/ssl/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        
        # Security Headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "default-src 'self'" always;
        
        # Proxy Configuration
        location / {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://node_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            proxy_cache_bypass $http_upgrade;
            proxy_read_timeout 60s;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            
            # Buffer settings
            proxy_buffering on;
            proxy_buffer_size 4k;
            proxy_buffers 8 4k;
            proxy_busy_buffers_size 8k;
        }
        
        # Authentication endpoints - stricter rate limiting
        location /auth/ {
            limit_req zone=auth burst=5 nodelay;
            
            proxy_pass http://node_backend;
            # ... same proxy settings as above
        }
        
        # Static files caching
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            
            proxy_pass http://node_backend;
            # ... proxy settings
        }
        
        # Health check endpoint
        location /health {
            access_log off;
            proxy_pass http://node_backend;
            
            health_check interval=10s fails=3 passes=2;
        }
        
        # Deny access to hidden files
        location ~ /\. {
            deny all;
        }
    }
}
```

---

## 11. Health Checks

### In-Depth Explanation
Comprehensive health checks monitor service dependencies and internal state. Implement readiness, liveness, and startup probes.

### Implementation Example

```javascript
// health.js
const Redis = require('ioredis');
const { Pool } = require('pg');
const os = require('os');
const logger = require('./logger');

class HealthChecker {
  constructor() {
    this.dependencies = {};
    this.checks = [];
    this.startupTime = Date.now();
    
    this.registerDefaultChecks();
  }

  registerDependency(name, checkFn) {
    this.dependencies[name] = checkFn;
  }

  registerCheck(name, checkFn, critical = true) {
    this.checks.push({ name, checkFn, critical });
  }

  registerDefaultChecks() {
    // Memory usage check
    this.registerCheck('memory', async () => {
      const freeMemory = os.freemem();
      const totalMemory = os.totalmem();
      const memoryUsage = ((totalMemory - freeMemory) / totalMemory) * 100;
      
      if (memoryUsage > 90) {
        throw new Error(`High memory usage: ${memoryUsage.toFixed(2)}%`);
      }
      
      return {
        free: Math.round(freeMemory / 1024 / 1024),
        total: Math.round(totalMemory / 1024 / 1024),
        usage: memoryUsage.toFixed(2)
      };
    });

    // CPU load check
    this.registerCheck('cpu', async () => {
      const load = os.loadavg();
      const cpus = os.cpus().length;
      
      if (load[0] > cpus * 0.9) {
        throw new Error(`High CPU load: ${load[0]}`);
      }
      
      return {
        load1: load[0],
        load5: load[1],
        load15: load[2],
        cores: cpus
      };
    });

    // Disk space check
    this.registerCheck('disk', async () => {
      // Implement disk space check
      return { status: 'ok' };
    });
  }

  async performHealthCheck(type = 'readiness') {
    const results = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      checks: {},
      dependencies: {}
    };

    // Check dependencies
    for (const [name, checkFn] of Object.entries(this.dependencies)) {
      try {
        const startTime = Date.now();
        const dependencyStatus = await checkFn();
        const latency = Date.now() - startTime;
        
        results.dependencies[name] = {
          status: 'healthy',
          latency,
          details: dependencyStatus
        };
      } catch (error) {
        results.dependencies[name] = {
          status: 'unhealthy',
          error: error.message,
          timestamp: new Date().toISOString()
        };
        
        if (type === 'readiness') {
          results.status = 'unhealthy';
        }
      }
    }

    // Perform health checks
    for (const check of this.checks) {
      try {
        const startTime = Date.now();
        const checkResult = await check.checkFn();
        const latency = Date.now() - startTime;
        
        results.checks[check.name] = {
          status: 'healthy',
          latency,
          details: checkResult
        };
      } catch (error) {
        results.checks[check.name] = {
          status: 'unhealthy',
          error: error.message,
          critical: check.critical
        };
        
        if (check.critical) {
          results.status = 'unhealthy';
        }
      }
    }

    // Add metrics
    results.metrics = {
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      activeHandles: process._getActiveHandles().length,
      activeRequests: process._getActiveRequests().length
    };

    return results;
  }

  // Middleware for health endpoints
  getHealthMiddleware() {
    return async (req, res) => {
      const endpoint = req.path;
      let healthType = 'readiness';
      
      if (endpoint.includes('liveness')) {
        healthType = 'liveness';
      } else if (endpoint.includes('startup')) {
        healthType = 'startup';
      }
      
      try {
        const health = await this.performHealthCheck(healthType);
        
        if (health.status === 'healthy') {
          res.status(200).json(health);
        } else {
          res.status(503).json(health);
        }
      } catch (error) {
        logger.error('Health check failed:', error);
        res.status(500).json({
          status: 'error',
          error: 'Health check failed',
          timestamp: new Date().toISOString()
        });
      }
    };
  }

  // Database health check
  static createDatabaseHealthCheck(pool) {
    return async () => {
      const client = await pool.connect();
      try {
        const result = await client.query('SELECT 1 as health');
        const connections = await client.query(
          'SELECT count(*) as active_connections FROM pg_stat_activity'
        );
        
        return {
          database: 'connected',
          active_connections: parseInt(connections.rows[0].active_connections)
        };
      } finally {
        client.release();
      }
    };
  }

  // Redis health check
  static createRedisHealthCheck(redisClient) {
    return async () => {
      const startTime = Date.now();
      const pong = await redisClient.ping();
      const latency = Date.now() - startTime;
      
      const info = await redisClient.info();
      const connectedClients = info.match(/connected_clients:(\d+)/)?.[1];
      
      return {
        status: pong === 'PONG' ? 'connected' : 'disconnected',
        latency,
        connected_clients: parseInt(connectedClients || '0')
      };
    };
  }
}

// Usage example
const healthChecker = new HealthChecker();
const dbPool = new Pool({ connectionString: process.env.DATABASE_URL });
const redisClient = new Redis(process.env.REDIS_URL);

// Register dependencies
healthChecker.registerDependency(
  'database',
  HealthChecker.createDatabaseHealthCheck(dbPool)
);

healthChecker.registerDependency(
  'redis',
  HealthChecker.createRedisHealthCheck(redisClient)
);

// Register custom business logic check
healthChecker.registerCheck('business-logic', async () => {
  // Check if critical business functionality is working
  const someCriticalService = await checkCriticalService();
  return { service: someCriticalService ? 'operational' : 'degraded' };
});

// Set up routes
app.get('/health/readiness', healthChecker.getHealthMiddleware());
app.get('/health/liveness', healthChecker.getHealthMiddleware());
app.get('/health/startup', healthChecker.getHealthMiddleware());
app.get('/health/full', healthChecker.getHealthMiddleware());

module.exports = healthChecker;
```

---

## 12. Scaling Node.js

### In-Depth Explanation
Horizontal and vertical scaling strategies for Node.js applications. Implement clustering, load balancing, and microservices architecture.

### Implementation Example

```javascript
// cluster.js
const cluster = require('cluster');
const os = require('os');
const logger = require('./logger');

class ApplicationCluster {
  constructor(app) {
    this.app = app;
    this.workers = new Map();
    this.isMaster = cluster.isMaster;
    this.cpuCount = process.env.NODE_CLUSTER_COUNT || os.cpus().length;
  }

  start() {
    if (this.isMaster) {
      this.startMaster();
    } else {
      this.startWorker();
    }
  }

  startMaster() {
    logger.info(`Master ${process.pid} is running`);
    logger.info(`Forking ${this.cpuCount} workers`);

    // Fork workers
    for (let i = 0; i < this.cpuCount; i++) {
      this.forkWorker();
    }

    // Handle worker events
    cluster.on('exit', (worker, code, signal) => {
      logger.warn(`Worker ${worker.process.pid} died with code ${code} and signal ${signal}`);
      logger.info('Starting a new worker');
      
      this.workers.delete(worker.id);
      setTimeout(() => this.forkWorker(), 1000);
    });

    cluster.on('online', (worker) => {
      logger.info(`Worker ${worker.process.pid} is online`);
      this.workers.set(worker.id, {
        pid: worker.process.pid,
        startTime: Date.now(),
        requests: 0
      });
    });

    cluster.on('message', (worker, message) => {
      if (message.type === 'incrementRequest') {
        const workerInfo = this.workers.get(worker.id);
        if (workerInfo) {
          workerInfo.requests++;
        }
      }
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('Master received SIGTERM, shutting down workers');
      
      for (const workerId in cluster.workers) {
        cluster.workers[workerId].kill('SIGTERM');
      }
      
      setTimeout(() => {
        logger.info('Master shutting down');
        process.exit(0);
      }, 5000);
    });
  }

  forkWorker() {
    const worker = cluster.fork();
    
    worker.on('message', (message) => {
      if (message.type === 'ready') {
        logger.info(`Worker ${worker.process.pid} is ready`);
      }
    });
  }

  startWorker() {
    const server = this.app.listen(process.env.PORT || 3000, () => {
      logger.info(`Worker ${process.pid} started on port ${server.address().port}`);
      
      // Notify master that worker is ready
      if (process.send) {
        process.send({ type: 'ready' });
      }
    });

    // Track requests
    server.on('request', (req, res) => {
      if (process.send) {
        process.send({ type: 'incrementRequest' });
      }
    });

    // Graceful shutdown for worker
    process.on('SIGTERM', () => {
      logger.info(`Worker ${process.pid} received SIGTERM`);
      
      server.close(() => {
        logger.info(`Worker ${process.pid} closed all connections`);
        process.exit(0);
      });
      
      setTimeout(() => {
        logger.warn(`Worker ${process.pid} forcing shutdown`);
        process.exit(1);
      }, 10000);
    });
  }

  getWorkerStats() {
    const stats = {
      totalWorkers: this.workers.size,
      workers: Array.from(this.workers.values()).map(worker => ({
        ...worker,
        uptime: Date.now() - worker.startTime
      })),
      totalRequests: Array.from(this.workers.values())
        .reduce((sum, worker) => sum + worker.requests, 0)
    };
    
    return stats;
  }
}

module.exports = ApplicationCluster;
```

### Load Balancer Configuration

```javascript
// loadBalancer.js
const http = require('http');
const httpProxy = require('http-proxy');

class LoadBalancer {
  constructor(servers) {
    this.servers = servers.map(server => ({
      ...server,
      weight: server.weight || 1,
      currentWeight: 0,
      connections: 0
    }));
    
    this.proxy = httpProxy.createProxyServer({
      xfwd: true,
      timeout: 30000
    });
    
    this.setupErrorHandling();
  }

  // Weighted Round Robin algorithm
  getNextServer() {
    let totalWeight = 0;
    let bestServer = null;
    let bestWeight = -1;

    for (const server of this.servers) {
      if (!server.healthy) continue;
      
      server.currentWeight += server.weight;
      totalWeight += server.weight;
      
      if (server.currentWeight > bestWeight) {
        bestWeight = server.currentWeight;
        bestServer = server;
      }
    }

    if (bestServer) {
      bestServer.currentWeight -= totalWeight;
      bestServer.connections++;
    }

    return bestServer;
  }

  setupErrorHandling() {
    this.proxy.on('error', (err, req, res) => {
      console.error('Proxy error:', err);
      
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end('Bad Gateway');
      }
    });

    this.proxy.on('proxyRes', (proxyRes, req, res) => {
      const server = req.targetServer;
      if (server) {
        server.connections--;
      }
    });
  }

  healthCheck() {
    setInterval(() => {
      this.servers.forEach(async (server) => {
        try {
          const response = await fetch(`http://${server.host}:${server.port}/health`);
          server.healthy = response.ok;
          server.lastCheck = new Date().toISOString();
        } catch (error) {
          server.healthy = false;
          server.lastCheck = new Date().toISOString();
          console.error(`Health check failed for ${server.host}:${server.port}`, error);
        }
      });
    }, 10000);
  }

  start(port = 80) {
    this.healthCheck();

    const server = http.createServer((req, res) => {
      const targetServer = this.getNextServer();
      
      if (!targetServer) {
        res.writeHead(503, { 'Content-Type': 'text/plain' });
        res.end('Service Unavailable');
        return;
      }

      req.targetServer = targetServer;
      
      this.proxy.web(req, res, {
        target: `http://${targetServer.host}:${targetServer.port}`,
        timeout: 30000
      });
    });

    server.listen(port, () => {
      console.log(`Load balancer running on port ${port}`);
    });

    return server;
  }
}

// Usage
const lb = new LoadBalancer([
  { host: '10.0.0.1', port: 3000, weight: 3 },
  { host: '10.0.0.2', port: 3000, weight: 2 },
  { host: '10.0.0.3', port: 3000, weight: 1 },
  { host: '10.0.0.4', port: 3000, weight: 4 }
]);

lb.start(8080);
```

---

## 13. Interview Questions

### Logging & Log Rotation
**Technical Questions:**
1. How would you implement structured logging in a Node.js application?
2. What are the differences between Winston and Pino, and when would you choose one over the other?
3. How do you handle log rotation to prevent disk space issues?
4. What information should never be logged in production?

**Scenario-Based Questions:**
1. You notice your application logs are consuming 100GB of disk space daily. How would you diagnose and resolve this?
2. A compliance audit requires you to retain logs for 7 years. How would you design this system?
3. How would you implement log aggregation across multiple microservices?

### PM2 Ecosystem File
**Technical Questions:**
1. What are the benefits of using PM2's cluster mode versus native Node.js clustering?
2. How do you configure zero-downtime deployments with PM2?
3. What environment-specific configurations would you include in an ecosystem file?

**Scenario-Based Questions:**
1. Your application needs to handle 10x more traffic. How would you configure PM2 to scale?
2. During deployment, users report session data loss. How would you prevent this with PM2?
3. How would you monitor and restart failed processes automatically?

### API Monitoring
**Technical Questions:**
1. What metrics are essential for monitoring a Node.js API?
2. How would you implement custom business metrics in your application?
3. What tools would you use for distributed tracing?

**Scenario-Based Questions:**
1. You receive an alert about high latency. How would you investigate and identify the root cause?
2. How would you design a monitoring system that can scale with your microservices architecture?
3. What would you do if you notice a memory leak pattern in your monitoring dashboard?

### Rate Limiting
**Technical Questions:**
1. Explain different rate limiting algorithms and their trade-offs.
2. How would you implement distributed rate limiting across multiple servers?
3. What are the security considerations when implementing rate limiting?

**Scenario-Based Questions:**
1. Your API is experiencing a DDoS attack. How would you adjust rate limiting rules?
2. A legitimate user complains about being rate limited. How would you handle this?
3. How would you implement different rate limits for different API endpoints?

### Alerts
**Technical Questions:**
1. How would you prevent alert fatigue while ensuring critical issues are caught?
2. What are the key components of an effective alert message?
3. How would you implement alert escalation policies?

**Scenario-Based Questions:**
1. Your alerting system is generating hundreds of false positives. How would you improve it?
2. How would you handle a situation where alerts are not being sent due to network issues?
3. What would you include in a post-mortem report for a critical alert?

### Caching Architecture
**Technical Questions:**
1. Explain cache invalidation strategies and their trade-offs.
2. How would you prevent cache stampede/thundering herd?
3. What are the differences between write-through and write-behind caching?

**Scenario-Based Questions:**
1. Users report seeing stale data. How would you debug cache invalidation issues?
2. Your cache hit rate has dropped from 95% to 60%. How would you investigate?
3. How would you design a caching strategy for a read-heavy vs write-heavy application?

### Graceful Shutdown
**Technical Questions:**
1. What are the steps involved in a graceful shutdown?
2. How would you handle long-running requests during shutdown?
3. What signals should a Node.js application handle for graceful shutdown?

**Scenario-Based Questions:**
1. During deployment, some requests fail with 502 errors. How would you ensure graceful shutdown prevents this?
2. How would you handle shutdown when database transactions are in progress?
3. What would you do if a process doesn't shut down gracefully after receiving SIGTERM?

### Docker Containerization
**Technical Questions:**
1. What are the security best practices for Docker containers?
2. How would you optimize Docker image size for a Node.js application?
3. Explain multi-stage builds and their benefits.

**Scenario-Based Questions:**
1. Your container is running out of memory. How would you debug and fix this?
2. How would you handle sensitive configuration in Docker containers?
3. What would you do if a containerized application can't connect to a database?

### CI/CD Pipelines
**Technical Questions:**
1. What stages would you include in a production CI/CD pipeline?
2. How would you implement rollback capabilities?
3. What security checks would you include in your pipeline?

**Scenario-Based Questions:**
1. A deployment fails in production. What's your rollback strategy?
2. How would you handle database migrations in a CI/CD pipeline?
3. What would you do if tests pass locally but fail in the CI environment?

### Nginx Reverse Proxy
**Technical Questions:**
1. What are the benefits of using Nginx as a reverse proxy?
2. How would you configure SSL termination in Nginx?
3. What caching strategies can you implement at the Nginx level?

**Scenario-Based Questions:**
1. You need to implement canary deployments. How would you configure Nginx for this?
2. How would you handle WebSocket connections through Nginx?
3. What would you do if Nginx returns 502 errors for some requests?

### Health Checks
**Technical Questions:**
1. What's the difference between readiness, liveness, and startup probes?
2. How would you implement health checks for external dependencies?
3. What metrics would you expose in a health check endpoint?

**Scenario-Based Questions:**
1. A health check fails intermittently. How would you troubleshoot this?
2. How would you design health checks for a microservice that depends on multiple databases?
3. What would you do if a service passes health checks but is still not functioning correctly?

### Scaling Node.js
**Technical Questions:**
1. What are the differences between vertical and horizontal scaling?
2. How does Node.js clustering work under the hood?
3. What are the challenges of scaling WebSocket connections?

**Scenario-Based Questions:**
1. Your application needs to handle 1 million concurrent connections. How would you architect this?
2. How would you handle stateful sessions in a scaled environment?
3. What scaling strategy would you choose for a real-time chat application vs a REST API?

### Senior Developer Real-World Scenarios

1. **System Design**: "Design a URL shortening service that handles 10,000 requests per second with 99.99% uptime. Consider rate limiting, caching, scaling, and monitoring."

2. **Performance Optimization**: "Users report slow response times during peak hours. What steps would you take to identify and resolve the bottleneck?"

3. **Disaster Recovery**: "Your primary database fails during a peak traffic period. What's your recovery plan and how do you minimize downtime?"

4. **Security Incident**: "You discover a vulnerability that exposed user data. What's your immediate response and long-term prevention plan?"

5. **Migration Strategy**: "You need to migrate from a monolithic architecture to microservices without downtime. How would you approach this?"

6. **Cost Optimization**: "Your cloud infrastructure costs have tripled in 3 months. How would you identify waste and optimize costs?"

7. **Team Leadership**: "You're leading a team to rebuild a legacy system. How would you balance new feature development with technical debt reduction?"

8. **Cross-Functional Coordination**: "The marketing team wants to launch a campaign expected to bring 10x traffic. How do you prepare your system?"

9. **Vendor Selection**: "You need to choose between building in-house vs using third-party services for logging, monitoring, and caching. What factors would you consider?"

10. **Incident Management**: "During a major outage, how would you coordinate between development, operations, and customer support teams?"

---

## 🎯 Conclusion

Building a production-ready Node.js backend requires careful consideration of multiple aspects beyond just writing code. Each component plays a critical role in ensuring reliability, scalability, and maintainability. Remember to:

1. **Start with monitoring** - You can't improve what you can't measure
2. **Implement security at every layer** - Defense in depth
3. **Plan for failure** - Everything fails eventually
4. **Automate everything** - Manual processes are error-prone
5. **Document decisions** - Future you will thank present you

This guide provides a comprehensive foundation, but remember that every application has unique requirements. Continuously evaluate and adapt these patterns to your specific needs.

---
