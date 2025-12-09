# 🔐 Node.js Security Best Practices Guide

## 📑 Table of Contents
1. [Input Validation](#input-validation)
2. [Sanitization](#sanitization)
3. [XSS Prevention](#xss-prevention)
4. [CSRF Basics](#csrf-basics)
5. [Rate Limiting](#rate-limiting)
6. [Brute-force Protection](#brute-force-protection)
7. [Helmet](#helmet)
8. [HTTP Parameter Pollution](#http-parameter-pollution)
9. [SQL Injection Prevention](#sql-injection-prevention)
10. [Encryption](#encryption)
11. [HTTPS Configuration](#https-configuration)
12. [Environment Variable Protection](#environment-variable-protection)

---

## 1. Input Validation <a name="input-validation"></a>

### Overview
Input validation ensures that only properly formatted data enters your application. It's the first line of defense against malicious data.

### Implementation with Zod

```javascript
import { z } from 'zod';

// User registration schema
const userSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  age: z.number().min(18).max(120),
  username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_]+$/),
  birthDate: z.string().refine((val) => !isNaN(Date.parse(val))),
});

// Express middleware
const validateRequest = (schema) => (req, res, next) => {
  try {
    schema.parse(req.body);
    next();
  } catch (error) {
    res.status(400).json({
      error: 'Validation failed',
      details: error.errors
    });
  }
};

// Usage
app.post('/register', validateRequest(userSchema), (req, res) => {
  // Safe to use req.body
});
```

### Implementation with Joi

```javascript
const Joi = require('joi');

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string()
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d@$!%*?&]{8,}$'))
    .required(),
  role: Joi.string().valid('user', 'admin', 'moderator').default('user'),
  metadata: Joi.object({
    ip: Joi.string().ip(),
    userAgent: Joi.string()
  })
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How would you implement conditional validation where field B is required only if field A has a specific value?"
2. "What's the difference between `zod`'s `refine()` and `transform()` methods and when would you use each?"
3. "How would you validate nested objects with dynamic keys in Zod/Joi?"

**Scenario-Based Questions:**
1. "You're building a financial application that accepts transaction amounts. A user submits `"1000"` (string) instead of `1000` (number). How would you handle this in validation while considering precision for decimal numbers?"
2. "During a penetration test, an attacker sends a payload with `__proto__` property to poison the prototype chain. How would your validation prevent this?"
3. "A legacy system sends dates in multiple formats (ISO, Unix timestamp, MM/DD/YYYY). How would you create a robust validation schema that accepts all formats but normalizes to ISO?"

**Real-World Challenge:**
> "Our e-commerce platform accepts product data from multiple vendors via API. Each vendor has different field names and formats (price as `"$99.99"`, `99.99`, `"99,99€"`). Design a validation layer that normalizes this data while maintaining audit trails of the original input."

---

## 2. Sanitization <a name="sanitization"></a>

### Overview
Sanitization removes or encodes malicious content from user input, preventing injection attacks.

### Implementation Examples

```javascript
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import validator from 'validator';

const window = new JSDOM('').window;
const purify = DOMPurify(window);

// HTML Sanitization
const sanitizeHTML = (dirtyHTML) => {
  return purify.sanitize(dirtyHTML, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'title', 'target'],
    ALLOW_DATA_ATTR: false
  });
};

// Input Sanitization Middleware
const sanitizeInput = (req, res, next) => {
  const sanitizeObject = (obj) => {
    Object.keys(obj).forEach(key => {
      if (typeof obj[key] === 'string') {
        // Remove null bytes, escape HTML, trim
        obj[key] = validator.escape(
          validator.stripLow(
            validator.trim(obj[key])
          )
        );
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitizeObject(obj[key]);
      }
    });
  };

  if (req.body) sanitizeObject(req.body);
  if (req.query) sanitizeObject(req.query);
  if (req.params) sanitizeObject(req.params);
  
  next();
};

// Usage
app.use(sanitizeInput);
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "What's the difference between `validator.escape()` and `DOMPurify.sanitize()`? When would you use one over the other?"
2. "How does DOMPurify handle SVG sanitization and what are the security implications?"
3. "Explain how you would sanitize MongoDB queries to prevent NoSQL injection while maintaining query functionality."

**Scenario-Based Questions:**
1. "A user uploads a profile description containing `<script>alert('xss')</script>` and `{{7*7}}` (template injection). How would your sanitization process handle both threats?"
2. "Your application accepts Markdown from users and converts it to HTML. How would you sanitize the output while preserving legitimate formatting like **bold** and *italic*?"
3. "An attacker uses Unicode homoglyph attacks (using Cyrillic 'а' instead of Latin 'a'). How would your sanitization detect and prevent this?"

**Real-World Challenge:**
> "We're building a collaborative document editor where multiple users can edit rich text simultaneously. Users need to apply formatting but we must prevent XSS. Design a sanitization strategy that allows safe collaborative editing with real-time preview."

---

## 3. XSS Prevention <a name="xss-prevention"></a>

### Overview
Cross-Site Scripting (XSS) attacks inject malicious scripts into web pages viewed by other users.

### Prevention Strategies

```javascript
import helmet from 'helmet';
import xss from 'xss';

// Content Security Policy
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "trusted-cdn.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "cdn.example.com"],
      connectSrc: ["'self'", "api.example.com"],
      fontSrc: ["'self'", "fonts.googleapis.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  })
);

// XSS Filter
app.use(helmet.xssFilter());

// Template Engine Protection (EJS example)
app.set('view engine', 'ejs');
app.locals.escape = (str) => {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
};

// Safe Output in Templates
// Instead of: <%= userInput %>
// Use: <%= escape(userInput) %>

// Custom XSS protection for JSON APIs
const xssOptions = {
  whiteList: {}, // empty, means filter out all tags
  stripIgnoreTag: true, // filter out all HTML not in the whitelist
  stripIgnoreTagBody: ['script', 'style'] // the script and style tag and its content
};

const sanitizeForXSS = (data) => {
  if (typeof data === 'string') {
    return xss(data, xssOptions);
  }
  if (Array.isArray(data)) {
    return data.map(sanitizeForXSS);
  }
  if (typeof data === 'object' && data !== null) {
    return Object.keys(data).reduce((acc, key) => {
      acc[key] = sanitizeForXSS(data[key]);
      return acc;
    }, {});
  }
  return data;
};
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Explain the differences between Reflected XSS, Stored XSS, and DOM-based XSS. How would you prevent each type?"
2. "How does Content Security Policy (CSP) prevent XSS and what are the limitations of different CSP directives?"
3. "What are the security implications of using `innerHTML` vs `textContent` in frontend JavaScript?"

**Scenario-Based Questions:**
1. "A user finds they can inject JavaScript via the URL parameter that gets reflected in a 404 error page. How would you fix this vulnerability?"
2. "Your application uses a third-party analytics script that occasionally gets compromised and serves malicious code. How would you mitigate this risk using CSP?"
3. "An attacker uses `<img src=x onerror=stealCookies()>` in a comment section. How would different XSS prevention layers catch this?"

**Real-World Challenge:**
> "Our customer support portal allows agents to view user-submitted HTML emails. We've discovered malicious emails that execute scripts when viewed. Design a secure email rendering system that displays HTML emails safely while preserving legitimate formatting and links."

---

## 4. CSRF Basics <a name="csrf-basics"></a>

### Overview
Cross-Site Request Forgery (CSRF) tricks users into performing actions they didn't intend to.

### Implementation with csurf and Double-Submit Cookie Pattern

```javascript
import csurf from 'csurf';
import crypto from 'crypto';

// CSRF Token Middleware
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
});

// Apply CSRF to routes
app.use(csrfProtection);

// Send CSRF token to frontend
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Alternative: Double-Submit Cookie Pattern
const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

const doubleSubmitCookieCSRF = (req, res, next) => {
  if (req.method === 'GET') {
    const token = generateCSRFToken();
    res.cookie('XSRF-TOKEN', token, {
      httpOnly: false, // Accessible by JavaScript
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    res.locals.csrfToken = token;
  } else if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
    const cookieToken = req.cookies['XSRF-TOKEN'];
    const headerToken = req.headers['x-xsrf-token'];
    
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }
  next();
};

// SameSite Cookie Protection
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict', // or 'lax' for GET requests from external sites
    domain: '.example.com'
  }
}));
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Explain how the SameSite cookie attribute prevents CSRF attacks. What are the differences between 'strict', 'lax', and 'none'?"
2. "How does the double-submit cookie pattern work and what are its advantages over server-side token storage?"
3. "Why are GET requests typically not protected by CSRF tokens, and when should they be?"

**Scenario-Based Questions:**
1. "Your application uses JWT tokens stored in localStorage. An attacker's site makes a POST request to your API, and the browser automatically includes the JWT. How would you prevent this CSRF attack?"
2. "A user complains they can't submit a form when your site is embedded in an iframe on a partner site. How would you fix this while maintaining security?"
3. "Your mobile app needs to call your API. Traditional CSRF tokens don't work well with mobile apps. What alternative strategies would you implement?"

**Real-World Challenge:**
> "We're migrating a monolithic application to microservices. Each service has its own domain. Users need to navigate seamlessly between services while maintaining CSRF protection. Design a cross-domain CSRF strategy that works across `auth.example.com`, `api.example.com`, and `app.example.com`."

---

## 5. Rate Limiting <a name="rate-limiting"></a>

### Overview
Rate limiting controls how many requests a client can make to your API within a given time period.

### Implementation with express-rate-limit and Redis

```javascript
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';

// Redis client for distributed rate limiting
const redisClient = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD
});

// Global rate limiter
const globalLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return req.ip; // Use IP address as key
  }
});

// Strict limiter for auth endpoints
const authLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args),
    prefix: 'rl:auth:'
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per hour
  message: 'Too many login attempts, please try again after an hour',
  skipSuccessfulRequests: true // Don't count successful logins
});

// Dynamic rate limiting based on user tier
const tieredRateLimit = (req, res, next) => {
  let maxRequests;
  const userTier = req.user?.subscriptionTier || 'free';
  
  switch(userTier) {
    case 'premium':
      maxRequests = 1000;
      break;
    case 'business':
      maxRequests = 10000;
      break;
    default:
      maxRequests = 100;
  }
  
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: maxRequests,
    keyGenerator: (req) => req.user?.id || req.ip
  })(req, res, next);
};

// Apply rate limiters
app.use('/api/', globalLimiter);
app.use('/auth/login', authLimiter);
app.use('/api/v1/', tieredRateLimit);

// Rate limiting headers middleware
app.use((req, res, next) => {
  res.setHeader('X-RateLimit-Limit', req.rateLimit.limit);
  res.setHeader('X-RateLimit-Remaining', req.rateLimit.remaining);
  res.setHeader('X-RateLimit-Reset', req.rateLimit.resetTime);
  next();
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Compare token bucket vs leaky bucket algorithms for rate limiting. When would you choose one over the other?"
2. "How would you implement distributed rate limiting across multiple server instances?"
3. "What strategies would you use to prevent rate limit evasion via IP rotation?"

**Scenario-Based Questions:**
1. "A legitimate user with a shared IP (corporate NAT) is being rate-limited because thousands of employees share the same IP. How would you handle this?"
2. "Your API is being targeted by a DDoS attack from thousands of IPs, each making requests just below the rate limit threshold. How would you adjust your rate limiting strategy?"
3. "A mobile app update accidentally creates an infinite loop that hits your API 100 times per second per user. How would your rate limiting handle this while minimizing impact on legitimate users?"

**Real-World Challenge:**
> "We're launching a public API that will be used by both human users and automated systems. We need to implement fair rate limiting that prevents abuse while allowing legitimate high-volume users (like search engine crawlers) to function. Design a rate limiting system with: 1) Different limits for authenticated vs anonymous users, 2) Whitelisting for trusted crawlers, 3) Burst allowance for sudden legitimate traffic spikes."

---

## 6. Brute-force Protection <a name="brute-force-protection"></a>

### Overview
Brute-force protection prevents attackers from guessing credentials through repeated attempts.

### Implementation Strategies

```javascript
import bcrypt from 'bcrypt';
import Redis from 'ioredis';

const redis = new Redis();
const FAILED_ATTEMPTS_KEY = 'failed_attempts:';
const BLOCKED_IPS_KEY = 'blocked_ips:';

class BruteForceProtector {
  constructor() {
    this.maxAttempts = 5;
    this.windowMs = 15 * 60 * 1000; // 15 minutes
    this.blockDuration = 24 * 60 * 60 * 1000; // 24 hours
  }

  async trackFailedAttempt(identifier, ip) {
    const key = `${FAILED_ATTEMPTS_KEY}${identifier}`;
    const ipKey = `${FAILED_ATTEMPTS_KEY}ip:${ip}`;
    
    // Increment counters
    const [userAttempts, ipAttempts] = await Promise.all([
      redis.incr(key),
      redis.incr(ipKey)
    ]);

    // Set expiration on first attempt
    if (userAttempts === 1) {
      await redis.expire(key, this.windowMs / 1000);
    }
    if (ipAttempts === 1) {
      await redis.expire(ipKey, this.windowMs / 1000);
    }

    // Block if too many attempts
    if (userAttempts >= this.maxAttempts || ipAttempts >= this.maxAttempts * 3) {
      await this.blockIdentifier(identifier, ip);
      return true;
    }
    
    return false;
  }

  async blockIdentifier(identifier, ip) {
    const blockKey = `${BLOCKED_IPS_KEY}${ip}`;
    await redis.setex(blockKey, this.blockDuration / 1000, 'blocked');
    
    // Send alert
    await this.sendSecurityAlert(identifier, ip);
  }

  async isBlocked(ip) {
    const blocked = await redis.get(`${BLOCKED_IPS_KEY}${ip}`);
    return !!blocked;
  }

  async resetAttempts(identifier, ip) {
    await Promise.all([
      redis.del(`${FAILED_ATTEMPTS_KEY}${identifier}`),
      redis.del(`${FAILED_ATTEMPTS_KEY}ip:${ip}`)
    ]);
  }

  async sendSecurityAlert(identifier, ip) {
    // Implement notification (email, Slack, etc.)
    console.log(`Security alert: Brute force attempt on ${identifier} from ${ip}`);
  }
}

// Login with brute force protection
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = req.ip;
  const protector = new BruteForceProtector();

  // Check if IP is blocked
  if (await protector.isBlocked(ip)) {
    return res.status(429).json({
      error: 'Too many failed attempts. Try again tomorrow.'
    });
  }

  // Find user
  const user = await User.findOne({ email });
  
  if (!user) {
    await protector.trackFailedAttempt(email, ip);
    // Same response whether user exists or not
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Check password with timing-safe comparison
  const isValid = await bcrypt.compare(password, user.password);
  
  if (!isValid) {
    const wasBlocked = await protector.trackFailedAttempt(email, ip);
    if (wasBlocked) {
      // Lock the account
      user.accountLocked = true;
      user.lockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await user.save();
    }
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Reset attempts on successful login
  await protector.resetAttempts(email, ip);
  
  // Generate session/token
  const token = generateToken(user);
  res.json({ token });
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How would you implement progressive delay (exponential backoff) for failed login attempts?"
2. "What's the difference between account locking and IP-based blocking? When would you use each?"
3. "How can you prevent timing attacks when comparing passwords or tokens?"

**Scenario-Based Questions:**
1. "An attacker is using a botnet with 10,000 different IPs to brute force a single account. How would you detect and prevent this?"
2. "Your monitoring shows attackers are trying common passwords (password123, admin, etc.) against multiple accounts. How would you implement a breached password check?"
3. "A user legitimately forgets their password and triggers the account lock. They need immediate access. How would you design a secure unlock process?"

**Real-World Challenge:**
> "Design a brute-force protection system for a banking application that must: 1) Prevent credential stuffing using known password breaches, 2) Allow legitimate users who mistype passwords occasionally, 3) Provide secure account recovery without creating new attack vectors, 4) Comply with regulatory requirements for security incident logging."

---

## 7. Helmet <a name="helmet"></a>

### Overview
Helmet helps secure Express apps by setting various HTTP headers.

### Comprehensive Implementation

```javascript
import helmet from 'helmet';
import express from 'express';

const app = express();

// Basic Helmet configuration
app.use(helmet());

// Advanced configuration with custom options
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdn.example.com",
          "https://apis.google.com"
        ],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:", "https://*.example.com"],
        connectSrc: ["'self'", "https://api.example.com", "wss://ws.example.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'self'", "https://www.youtube.com"],
        childSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'self'"],
        upgradeInsecureRequests: [],
      },
      reportOnly: false, // Set to true for monitoring phase
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    expectCt: {
      maxAge: 86400,
      enforce: true,
      reportUri: 'https://example.com/report-ct',
    },
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    ieNoOpen: true,
    noSniff: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    xssFilter: true,
  })
);

// CSP nonce for inline scripts
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      scriptSrc: [
        "'self'",
        (req, res) => `'nonce-${res.locals.cspNonce}'`,
      ],
    },
  })
);

// Route-specific CSP
app.use('/admin', helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"], // No unsafe-inline for admin
  }
}));

// Security headers middleware (complementary to Helmet)
app.use((req, res, next) => {
  // Additional security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 
    'camera=(), microphone=(), geolocation=(), interest-cohort=()'
  );
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  
  next();
});

// Error handling for CSP violations
app.post('/csp-violation', express.json({ type: 'application/csp-report' }), (req, res) => {
  console.error('CSP Violation:', req.body);
  // Log to security monitoring system
  logSecurityEvent('CSP_VIOLATION', req.body);
  res.status(204).end();
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Explain what each of these headers does: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`."
2. "How does `helmet.hidePoweredBy()` improve security, and what are its limitations?"
3. "What's the difference between `helmet.noSniff()` and `X-Content-Type-Options: nosniff`?"

**Scenario-Based Questions:**
1. "Your application uses WebSockets and several third-party widgets. How would you configure CSP to allow these while maintaining security?"
2. "A security scan reports missing `X-Frame-Options` header, but you have `frame-ancestors` in CSP. Is this a vulnerability?"
3. "How would you implement a Content Security Policy that allows inline styles for a legacy CMS but blocks scripts?"

**Real-World Challenge:**
> "We're implementing CSP for a complex enterprise application with: 1) Legacy inline scripts that can't be easily removed, 2) Multiple third-party analytics and tracking scripts, 3) A custom-built WYSIWYG editor that generates inline styles, 4) PDF viewer that uses object tags. Design a CSP implementation that balances security with functionality."

---

## 8. HTTP Parameter Pollution <a name="http-parameter-pollution"></a>

### Overview
HPP attacks send multiple parameters with the same name to exploit how servers parse them.

### Prevention and Detection

```javascript
import hpp from 'hpp';

// Basic HPP protection
app.use(hpp());

// Custom HPP configuration
app.use(hpp({
  checkBody: true,
  checkBodyOnlyForContentType: 'urlencoded',
  checkQuery: true,
  whitelist: ['arrayParam'], // Allow duplicates for specific parameters
}));

// Manual HPP protection middleware
const preventHPP = (req, res, next) => {
  const cleanParams = (params) => {
    const cleaned = {};
    
    Object.keys(params).forEach(key => {
      const value = params[key];
      
      if (Array.isArray(value)) {
        // For GET parameters, take the first value
        // For POST, you might want to validate or reject
        cleaned[key] = req.method === 'GET' ? value[0] : value;
      } else {
        cleaned[key] = value;
      }
    });
    
    return cleaned;
  };

  // Clean all parameter sources
  if (req.query) {
    req.query = cleanParams(req.query);
  }
  
  if (req.body) {
    req.body = cleanParams(req.body);
  }
  
  if (req.params) {
    req.params = cleanParams(req.params);
  }
  
  next();
};

// Validation with HPP consideration
const validateWithHPP = (schema) => (req, res, next) => {
  // Check for duplicate parameters
  const checkDuplicates = (source) => {
    const rawQuery = req.originalUrl.split('?')[1];
    if (rawQuery) {
      const params = new URLSearchParams(rawQuery);
      const keys = params.getAll('').map(p => p.split('=')[0]);
      const uniqueKeys = new Set(keys);
      
      if (keys.length !== uniqueKeys.size) {
        throw new Error('Duplicate parameters detected');
      }
    }
  };

  try {
    checkDuplicates();
    schema.parse(req.body);
    next();
  } catch (error) {
    res.status(400).json({ 
      error: 'Invalid request',
      details: error.message 
    });
  }
};

// Route with HPP protection
app.get('/search', 
  preventHPP,
  validateWithHPP(searchSchema),
  (req, res) => {
    // req.query is now safe
    const { query, page } = req.query;
    // ...
  }
);

// Database query with HPP protection
app.post('/users/filter', async (req, res) => {
  const { filters } = req.body;
  
  // Ensure filters is an object, not an array
  if (Array.isArray(filters)) {
    return res.status(400).json({ error: 'Invalid filters format' });
  }
  
  // Convert to array if single value
  const filterArray = Array.isArray(filters) ? filters : [filters];
  
  // Safe database query
  const users = await User.find({
    $and: filterArray.map(filter => ({ [filter.field]: filter.value }))
  });
  
  res.json(users);
});
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "How does HTTP Parameter Pollution differ from SQL Injection, and how are they related?"
2. "Explain how different web servers (Apache, Nginx, Node.js) handle duplicate query parameters."
3. "What's the security impact of HPP on NoSQL databases like MongoDB?"

**Scenario-Based Questions:**
1. "An attacker sends `?id=1&id=SELECT * FROM users` to your endpoint. Your ORM uses the last value. How would you prevent SQL injection in this case?"
2. "Your application accepts JSON and form-encoded data. How would HPP protection differ between these content types?"
3. "A legacy endpoint expects comma-separated values like `?ids=1,2,3`. An attacker sends `?ids=1&ids=2,3`. How would you handle this?"

**Real-World Challenge:**
> "Design a robust parameter handling system for a REST API that: 1) Supports both JSON and form-encoded requests, 2) Handles arrays in query strings (`?ids[]=1&ids[]=2`), 3) Prevents HPP while allowing legitimate duplicate parameters for batch operations, 4) Logs potential HPP attempts for security monitoring."

---

## 9. SQL Injection Prevention <a name="sql-injection-prevention"></a>

### Overview
SQL injection occurs when attackers manipulate SQL queries by injecting malicious SQL code.

### Prevention with Parameterized Queries and ORMs

```javascript
import mysql from 'mysql2/promise';
import { Sequelize, Op } from 'sequelize';
import mongoose from 'mongoose';

// Raw SQL with parameterized queries
class UserRepository {
  constructor() {
    this.pool = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
    });
  }

  // UNSAFE - Vulnerable to SQL injection
  async getUserUnsafe(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    const [rows] = await this.pool.query(query);
    return rows[0];
  }

  // SAFE - Parameterized query
  async getUserSafe(username) {
    const query = 'SELECT * FROM users WHERE username = ?';
    const [rows] = await this.pool.execute(query, [username]);
    return rows[0];
  }

  // SAFE - Named parameters
  async searchUsersSafe(filters) {
    const query = `
      SELECT * FROM users 
      WHERE 
        (username LIKE ? OR ? IS NULL)
        AND (email LIKE ? OR ? IS NULL)
        AND (age >= ? OR ? IS NULL)
    `;
    const params = [
      filters.username ? `%${filters.username}%` : null,
      filters.username ? `%${filters.username}%` : null,
      filters.email ? `%${filters.email}%` : null,
      filters.email ? `%${filters.email}%` : null,
      filters.minAge || null,
      filters.minAge || null,
    ];
    
    const [rows] = await this.pool.execute(query, params);
    return rows;
  }
}

// Sequelize ORM (MySQL, PostgreSQL, etc.)
const sequelize = new Sequelize({
  dialect: 'mysql',
  // ... other config
});

class User extends Model {}
User.init({
  username: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false },
}, { sequelize });

// SAFE queries with Sequelize
async function findUser(username) {
  // Vulnerable if using string concatenation
  // return User.findOne({ where: `username = '${username}'` });
  
  // Safe with parameterized queries
  return User.findOne({ 
    where: { username } 
  });
}

// Dynamic queries with validation
async function dynamicSearch(filters) {
  const whereClause = {};
  
  if (filters.username) {
    whereClause.username = { 
      [Op.like]: `%${filters.username}%` 
    };
  }
  
  if (filters.minAge && filters.maxAge) {
    whereClause.age = { 
      [Op.between]: [filters.minAge, filters.maxAge] 
    };
  }
  
  // Input validation
  if (filters.orderBy) {
    const allowedColumns = ['username', 'email', 'createdAt'];
    if (!allowedColumns.includes(filters.orderBy)) {
      throw new Error('Invalid order column');
    }
  }
  
  return User.findAll({
    where: whereClause,
    order: filters.orderBy ? [[filters.orderBy, 'ASC']] : undefined,
    limit: Math.min(filters.limit || 10, 100) // Prevent excessive limits
  });
}

// MongoDB with Mongoose (NoSQL injection prevention)
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  roles: [String],
});

const UserModel = mongoose.model('User', userSchema);

// UNSAFE - Vulnerable to NoSQL injection
async function findUserUnsafe(query) {
  // DON'T DO THIS: query could be { $where: "sleep(10000)" }
  return UserModel.find(JSON.parse(query));
}

// SAFE - With validation
async function findUserSafe(filters) {
  const safeFilters = {};
  
  if (filters.username) {
    safeFilters.username = filters.username;
  }
  
  if (filters.role) {
    // Validate against allowed roles
    const allowedRoles = ['user', 'admin', 'moderator'];
    if (allowedRoles.includes(filters.role)) {
      safeFilters.roles = filters.role;
    }
  }
  
  // Prevent operator injection
  Object.keys(filters).forEach(key => {
    if (key.startsWith('$')) {
      delete filters[key]; // Remove MongoDB operators
    }
  });
  
  return UserModel.find(safeFilters);
}

// Stored Procedure Example
async function getUserWithProfile(userId) {
  const query = 'CALL GetUserWithProfile(?)';
  const [rows] = await this.pool.execute(query, [userId]);
  return rows[0];
}

// Input validation for raw queries
const validateSQLInput = (input) => {
  const blacklist = [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'OR', 'AND',
    ';', '--', '/*', '*/', '@@', '@', 'CHAR', 'NVARCHAR', 'EXEC', 'XP_'
  ];
  
  const upperInput = input.toUpperCase();
  for (const keyword of blacklist) {
    if (upperInput.includes(keyword)) {
      throw new Error('Invalid input detected');
    }
  }
  
  return input;
};
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Explain the difference between first-order and second-order SQL injection. How would you prevent each?"
2. "How do prepared statements prevent SQL injection at the database driver level?"
3. "What are the limitations of using an ORM for SQL injection prevention?"

**Scenario-Based Questions:**
1. "A developer uses `User.find({ where: \`age > ${minAge}\` })` with Sequelize. Is this vulnerable to SQL injection? Why?"
2. "Your application needs to support dynamic ORDER BY clauses based on user selection. How would you implement this safely?"
3. "An attacker exploits a second-order SQL injection by storing malicious SQL in their profile bio, which gets used in a report generation query. How would you prevent this?"

**Real-World Challenge:**
> "Design a search API for an e-commerce platform that allows complex filtering (price ranges, categories, brands, ratings) and sorting. The filters come from user input via query parameters. Implement this with: 1) Complete SQL injection prevention, 2) Protection against excessive query complexity that could cause database load, 3) Input validation that allows special characters in product names (like O'Reilly books), 4) Support for full-text search without vulnerability."

---

## 10. Encryption <a name="encryption"></a>

### Overview
Encryption protects sensitive data at rest and in transit using algorithms like AES (symmetric) and RSA (asymmetric).

### Implementation Examples

```javascript
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Environment variables for keys (use KMS in production)
const ENCRYPTION_KEY = crypto.scryptSync(
  process.env.ENCRYPTION_SECRET, 
  'salt', 
  32
);
const IV_LENGTH = 16;
const ALGORITHM = 'aes-256-gcm';

class EncryptionService {
  // AES-GCM Encryption (symmetric)
  encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(
      ALGORITHM, 
      ENCRYPTION_KEY, 
      iv
    );
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      encryptedData: encrypted,
      authTag: authTag.toString('hex')
    };
  }

  decrypt(encryptedObject) {
    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      ENCRYPTION_KEY,
      Buffer.from(encryptedObject.iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedObject.authTag, 'hex'));
    
    let decrypted = decipher.update(
      encryptedObject.encryptedData, 
      'hex', 
      'utf8'
    );
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // RSA Encryption (asymmetric)
  generateRSAKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: process.env.RSA_PASSPHRASE
      }
    });
  }

  rsaEncrypt(text, publicKey) {
    const buffer = Buffer.from(text, 'utf8');
    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      buffer
    );
    return encrypted.toString('base64');
  }

  rsaDecrypt(encryptedText, privateKey) {
    const buffer = Buffer.from(encryptedText, 'base64');
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        passphrase: process.env.RSA_PASSPHRASE,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      buffer
    );
    return decrypted.toString('utf8');
  }

  // Password hashing with bcrypt
  async hashPassword(password) {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }

  async verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  }

  // JWT with encryption
  generateToken(payload) {
    return jwt.sign(
      payload,
      process.env.JWT_SECRET,
      {
        algorithm: 'HS256',
        expiresIn: '24h',
        issuer: 'example.com'
      }
    );
  }

  verifyToken(token) {
    return jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'example.com'
    });
  }

  // Data at rest encryption for database fields
  encryptField(value) {
    if (!value) return value;
    
    const encrypted = this.encrypt(String(value));
    return JSON.stringify(encrypted);
  }

  decryptField(encryptedValue) {
    if (!encryptedValue) return encryptedValue;
    
    try {
      const encryptedObject = JSON.parse(encryptedValue);
      return this.decrypt(encryptedObject);
    } catch (error) {
      throw new Error('Failed to decrypt field');
    }
  }
}

// Database field encryption middleware (Mongoose example)
const encryptMiddleware = (schema, options) => {
  const fieldsToEncrypt = options.fields || [];
  const encryptionService = new EncryptionService();

  schema.pre('save', async function(next) {
    const doc = this;
    
    fieldsToEncrypt.forEach(field => {
      if (doc[field] && doc.isModified(field)) {
        doc[field] = encryptionService.encryptField(doc[field]);
      }
    });
    
    next();
  });

  schema.post('find', function(docs) {
    docs.forEach(doc => {
      fieldsToEncrypt.forEach(field => {
        if (doc[field]) {
          try {
            doc[field] = encryptionService.decryptField(doc[field]);
          } catch (error) {
            // Log but don't fail
            console.error(`Failed to decrypt ${field}:`, error);
          }
        }
      });
    });
  });
};

// Usage with Mongoose
const userSchema = new mongoose.Schema({
  email: String,
  ssn: String, // Sensitive - will be encrypted
  creditCard: String // Sensitive - will be encrypted
});

// Apply encryption to sensitive fields
userSchema.plugin(encryptMiddleware, {
  fields: ['ssn', 'creditCard']
});

// Key rotation strategy
class KeyManager {
  constructor() {
    this.currentKeyVersion = 'v1';
    this.keyStore = new Map();
  }

  async rotateKeys() {
    const newVersion = `v${Date.now()}`;
    const newKey = crypto.randomBytes(32);
    
    // Store new key
    this.keyStore.set(newVersion, newKey);
    
    // Re-encrypt data with new key (background job)
    await this.reEncryptData(newVersion);
    
    // Update current version
    this.currentKeyVersion = newVersion;
    
    // Archive old keys (keep for decryption)
    return newVersion;
  }

  async reEncryptData(newKeyVersion) {
    // Implementation depends on your data storage
    // This would be a background job that re-encrypts all data
  }
}
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Explain the differences between AES-CBC and AES-GCM modes. When would you choose one over the other?"
2. "How does RSA encryption work with hybrid cryptosystems (like encrypting an AES key with RSA)?"
3. "What are the security implications of using JWT without encryption for sensitive data?"

**Scenario-Based Questions:**
1. "You need to store credit card numbers for recurring payments. How would you design the encryption strategy considering PCI DSS compliance?"
2. "An employee leaves the company who had access to encryption keys. What's your key rotation and revocation process?"
3. "Your application needs to search encrypted email addresses in the database. How would you implement this without decrypting the entire database?"

**Real-World Challenge:**
> "Design an end-to-end encryption system for a healthcare messaging platform that must: 1) Ensure messages are encrypted so even the platform can't read them, 2) Allow users to access their messages from multiple devices, 3) Support message search functionality, 4) Handle key recovery when users forget passwords, 5) Comply with HIPAA regulations for PHI (Protected Health Information) protection."

---

## 11. HTTPS Configuration <a name="https-configuration"></a>

### Overview
HTTPS encrypts data in transit between clients and servers using TLS/SSL.

### Implementation with Express and Best Practices

```javascript
import https from 'https';
import fs from 'fs';
import express from 'express';
import helmet from 'helmet';
import crypto from 'crypto';

const app = express();

// Load SSL certificates
const sslOptions = {
  // Primary certificate
  key: fs.readFileSync('/path/to/private-key.pem'),
  cert: fs.readFileSync('/path/to/certificate.pem'),
  
  // Intermediate certificates (for chain)
  ca: [
    fs.readFileSync('/path/to/intermediate1.pem'),
    fs.readFileSync('/path/to/intermediate2.pem'),
  ],
  
  // Security configurations
  ciphers: [
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
    '!aNULL',
    '!eNULL',
    '!EXPORT',
    '!DES',
    '!RC4',
    '!MD5',
    '!PSK',
    '!SRP',
    '!CAMELLIA'
  ].join(':'),
  
  honorCipherOrder: true,
  secureOptions: crypto.constants.SSL_OP_NO_SSLv2 | 
                  crypto.constants.SSL_OP_NO_SSLv3 |
                  crypto.constants.SSL_OP_NO_TLSv1 |
                  crypto.constants.SSL_OP_NO_TLSv1_1,
  
  // OCSP Stapling
  requestCert: false,
  rejectUnauthorized: true,
  
  // Session tickets
  sessionIdContext: 'your-app-name',
  
  // TLS 1.3 specific
  maxVersion: 'TLSv1.3',
  minVersion: 'TLSv1.2',
};

// Create HTTPS server
const server = https.createServer(sslOptions, app);

// HTTP to HTTPS redirect middleware
const enforceHTTPS = (req, res, next) => {
  // Check for Cloudflare or load balancer headers
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  
  if (proto === 'http') {
    const httpsUrl = `https://${req.headers.host}${req.originalUrl}`;
    return res.redirect(301, httpsUrl);
  }
  
  // HSTS header (also set by helmet)
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );
  
  next();
};

// Apply middleware
app.use(enforceHTTPS);
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));

// Certificate transparency
app.use((req, res, next) => {
  res.setHeader(
    'Expect-CT',
    'max-age=86400, enforce, report-uri="https://example.com/report-ct"'
  );
  next();
});

// Security headers for HTTPS
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Feature Policy / Permissions Policy
  res.setHeader('Permissions-Policy', 
    'camera=(), microphone=(), geolocation=(), payment=()'
  );
  
  next();
});

// SSL/TLS health check endpoint
app.get('/.well-known/ssl-health', (req, res) => {
  const health = {
    status: 'healthy',
    tlsVersion: req.connection.getProtocol(),
    cipher: req.connection.getCipher(),
    certificate: {
      subject: req.connection.getPeerCertificate().subject,
      issuer: req.connection.getPeerCertificate().issuer,
      validFrom: req.connection.getPeerCertificate().valid_from,
      validTo: req.connection.getPeerCertificate().valid_to,
    },
    timestamp: new Date().toISOString(),
  };
  
  res.json(health);
});

// Certificate auto-renewal check
const checkCertificateExpiry = () => {
  const cert = fs.readFileSync('/path/to/certificate.pem');
  const parsedCert = new crypto.X509Certificate(cert);
  const daysUntilExpiry = Math.floor(
    (parsedCert.validTo - Date.now()) / (1000 * 60 * 60 * 24)
  );
  
  if (daysUntilExpiry < 30) {
    console.warn(`Certificate expires in ${daysUntilExpiry} days`);
    // Trigger renewal process
    renewCertificate();
  }
};

// Start server
const PORT = 443;
server.listen(PORT, () => {
  console.log(`HTTPS server running on port ${PORT}`);
  
  // Schedule certificate checks
  setInterval(checkCertificateExpiry, 24 * 60 * 60 * 1000); // Daily
});

// HTTP server for redirects (port 80)
import http from 'http';
const httpApp = express();
httpApp.use('*', (req, res) => {
  res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
});
http.createServer(httpApp).listen(80);

// Nginx configuration example (for reference)
/*
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_trusted_certificate /path/to/chain.pem;
    
    # Strong TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
*/
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "Explain the TLS handshake process. What happens during the ClientHello and ServerHello phases?"
2. "What's the difference between SSL and TLS? Why is SSL deprecated?"
3. "How does OCSP stapling improve SSL/TLS performance and privacy?"

**Scenario-Based Questions:**
1. "A security scan reports your site supports weak ciphers (RC4, MD5). How would you update your TLS configuration to remove these?"
2. "Users report 'NET::ERR_CERT_DATE_INVALID' errors. How would you implement automatic certificate renewal?"
3. "Your application needs to support both modern browsers and legacy systems. How would you configure TLS to balance security and compatibility?"

**Real-World Challenge:**
> "Design a multi-domain HTTPS strategy for a SaaS platform with: 1) Main application at app.company.com, 2) Customer subdomains (customer1.company.com), 3) API at api.company.com, 4) WebSocket connections for real-time features. Considerations: Certificate management (wildcard vs individual), HSTS preloading, mixed content prevention, and supporting HTTP/2 and HTTP/3."

---

## 12. Environment Variable Protection <a name="environment-variable-protection"></a>

### Overview
Environment variables store sensitive configuration like API keys, database credentials, and encryption secrets.

### Best Practices and Implementation

```javascript
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';
import crypto from 'crypto';
import fs from 'fs';

// Load and expand environment variables
const envConfig = dotenv.config({ 
  path: process.env.NODE_ENV === 'test' ? '.env.test' : '.env' 
});
dotenvExpand.expand(envConfig);

// Environment validation schema
const envSchema = {
  NODE_ENV: {
    required: true,
    validate: (value) => ['development', 'production', 'test'].includes(value),
  },
  PORT: {
    required: true,
    default: 3000,
    validate: (value) => Number.isInteger(Number(value)),
  },
  DATABASE_URL: {
    required: true,
    validate: (value) => value.startsWith('postgres://') || value.startsWith('mongodb://'),
  },
  JWT_SECRET: {
    required: true,
    minLength: 32,
    validate: (value) => value.length >= 32,
  },
  AWS_ACCESS_KEY_ID: {
    required: process.env.NODE_ENV === 'production',
  },
  AWS_SECRET_ACCESS_KEY: {
    required: process.env.NODE_ENV === 'production',
  },
  ENCRYPTION_KEY: {
    required: true,
    validate: (value) => {
      try {
        Buffer.from(value, 'hex');
        return value.length === 64; // 32 bytes in hex
      } catch {
        return false;
      }
    },
  },
};

// Environment validator
class EnvironmentValidator {
  constructor(schema) {
    this.schema = schema;
    this.errors = [];
  }

  validate() {
    Object.entries(this.schema).forEach(([key, config]) => {
      const value = process.env[key];
      
      // Check required
      if (config.required && (value === undefined || value === '')) {
        this.errors.push(`Environment variable ${key} is required`);
        return;
      }
      
      // Apply default
      if (value === undefined && config.default !== undefined) {
        process.env[key] = config.default;
        return;
      }
      
      // Validate
      if (value !== undefined && config.validate) {
        if (!config.validate(value)) {
          this.errors.push(`Environment variable ${key} failed validation`);
        }
      }
      
      // Check min length
      if (value && config.minLength && value.length < config.minLength) {
        this.errors.push(`Environment variable ${key} must be at least ${config.minLength} characters`);
      }
    });
    
    if (this.errors.length > 0) {
      throw new Error(`Environment validation failed:\n${this.errors.join('\n')}`);
    }
  }
}

// Initialize and validate
const validator = new EnvironmentValidator(envSchema);
validator.validate();

// Secure environment variable access with encryption
class SecureEnv {
  constructor() {
    this.encryptedValues = new Map();
    this.masterKey = this.deriveKey(process.env.MASTER_KEY_SALT);
  }

  deriveKey(salt) {
    return crypto.pbkdf2Sync(
      process.env.ENCRYPTION_PASSPHRASE,
      salt,
      100000,
      32,
      'sha256'
    );
  }

  encryptValue(value, keyName) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
    
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    this.encryptedValues.set(keyName, {
      iv: iv.toString('hex'),
      encryptedData: encrypted,
      authTag: authTag.toString('hex'),
    });
    
    // Store in environment (for demonstration - in production use secure storage)
    process.env[keyName] = JSON.stringify(this.encryptedValues.get(keyName));
  }

  decryptValue(keyName) {
    const encrypted = this.encryptedValues.get(keyName);
    if (!encrypted) {
      const envValue = process.env[keyName];
      if (!envValue) return null;
      
      try {
        this.encryptedValues.set(keyName, JSON.parse(envValue));
      } catch {
        return envValue; // Not encrypted
      }
    }
    
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.masterKey,
      Buffer.from(this.encryptedValues.get(keyName).iv, 'hex')
    );
    
    decipher.setAuthTag(
      Buffer.from(this.encryptedValues.get(keyName).authTag, 'hex')
    );
    
    let decrypted = decipher.update(
      this.encryptedValues.get(keyName).encryptedData,
      'hex',
      'utf8'
    );
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // Runtime protection
  freezeEnvironment() {
    Object.freeze(process.env);
    
    // Prevent modification
    Object.defineProperty(process, 'env', {
      value: Object.freeze({ ...process.env }),
      writable: false,
      configurable: false,
    });
  }
}

// Usage
const secureEnv = new SecureEnv();

// Encrypt sensitive values on startup
if (process.env.ENCRYPT_SENSITIVE_VALUES === 'true') {
  const sensitiveKeys = ['DATABASE_PASSWORD', 'SMTP_PASSWORD', 'STRIPE_SECRET_KEY'];
  
  sensitiveKeys.forEach(key => {
    if (process.env[key]) {
      secureEnv.encryptValue(process.env[key], key);
      // Remove plain text from memory
      delete process.env[key];
    }
  });
}

// Secure environment variable access wrapper
const getEnv = (key, defaultValue = null) => {
  // Check for encrypted value first
  const decrypted = secureEnv.decryptValue(key);
  if (decrypted) return decrypted;
  
  // Fall back to regular environment variable
  const value = process.env[key];
  
  if (value === undefined) {
    if (defaultValue !== null) return defaultValue;
    throw new Error(`Environment variable ${key} is not defined`);
  }
  
  return value;
};

// Environment-specific configuration
class Config {
  static get isProduction() {
    return getEnv('NODE_ENV') === 'production';
  }

  static get isDevelopment() {
    return getEnv('NODE_ENV') === 'development';
  }

  static get isTest() {
    return getEnv('NODE_ENV') === 'test';
  }

  static get database() {
    return {
      url: getEnv('DATABASE_URL'),
      ssl: this.isProduction ? { rejectUnauthorized: true } : false,
      pool: {
        max: this.isProduction ? 20 : 5,
        min: 0,
        acquire: 30000,
        idle: 10000,
      },
    };
  }

  static get redis() {
    return {
      host: getEnv('REDIS_HOST', 'localhost'),
      port: parseInt(getEnv('REDIS_PORT', '6379')),
      password: getEnv('REDIS_PASSWORD', ''),
      tls: this.isProduction ? {} : undefined,
    };
  }

  static get jwt() {
    return {
      secret: getEnv('JWT_SECRET'),
      expiresIn: getEnv('JWT_EXPIRES_IN', '24h'),
      issuer: getEnv('JWT_ISSUER', 'example.com'),
    };
  }
}

// Environment variable security middleware
const envSecurityMiddleware = (req, res, next) => {
  // Prevent environment variable leakage in errors
  const originalSend = res.send;
  res.send = function(body) {
    if (typeof body === 'string') {
      // Scrub environment variables from error responses
      Object.keys(process.env).forEach(key => {
        if (process.env[key] && process.env[key].length > 5) {
          body = body.replace(
            new RegExp(process.env[key].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'),
            '***REDACTED***'
          );
        }
      });
    }
    originalSend.call(this, body);
  };
  next();
};

// Docker/container security
if (process.env.CONTAINERIZED === 'true') {
  // Set secure defaults for containers
  process.env.NODE_ENV = process.env.NODE_ENV || 'production';
  
  // Drop privileges in container
  if (process.getuid && process.getuid() === 0) {
    console.warn('Running as root in container - consider switching to non-root user');
  }
}

// Production checklist
if (Config.isProduction) {
  // Verify no development variables are set
  const devVariables = ['DEBUG', 'NODE_DEBUG', 'NODE_TLS_REJECT_UNAUTHORIZED'];
  devVariables.forEach(key => {
    if (process.env[key]) {
      console.error(`Development variable ${key} set in production!`);
      process.exit(1);
    }
  });

  // Verify all required production variables are set
  const requiredProductionVars = [
    'DATABASE_URL',
    'SESSION_SECRET',
    'ENCRYPTION_KEY',
  ];
  
  requiredProductionVars.forEach(key => {
    if (!process.env[key]) {
      console.error(`Required production variable ${key} is not set!`);
      process.exit(1);
    }
  });
}

// Export secure configuration
export { getEnv, Config, secureEnv, envSecurityMiddleware };
```

### 🎯 Senior Developer Interview Questions

**Technical Questions:**
1. "What's the difference between `process.env` and a configuration management service like AWS Parameter Store or HashiCorp Vault?"
2. "How would you prevent environment variables from being logged accidentally in error messages or debugging output?"
3. "Explain the security implications of storing environment variables in Docker images vs using Docker secrets or Kubernetes secrets."

**Scenario-Based Questions:**
1. "A developer accidentally commits a `.env` file with production database credentials to a public GitHub repository. What's your incident response plan?"
2. "Your application needs to rotate database credentials monthly. How would you automate this without downtime?"
3. "You discover an environment variable containing an API key has been exposed in client-side JavaScript. How would you identify all exposed secrets and prevent future leaks?"

**Real-World Challenge:**
> "Design a secrets management strategy for a microservices architecture with: 1) 50+ microservices, 2) Multiple environments (dev, staging, production), 3) Compliance requirements (SOC2, HIPAA), 4) Need for automated secret rotation, 5) Support for both containerized and serverless deployments. Include: How secrets are stored, accessed, rotated, and audited."

---

## 📊 Security Audit Checklist

Use this checklist to audit your Node.js application's security:

### Input Validation & Sanitization
- [ ] All user input validated with Zod/Yup/Joi
- [ ] HTML output properly escaped/sanitized
- [ ] No direct eval() or Function() with user input
- [ ] File uploads validated for type and size

### Authentication & Authorization
- [ ] Passwords hashed with bcrypt/scrypt/argon2
- [ ] JWT tokens signed and validated properly
- [ ] Session management secure (httpOnly, secure cookies)
- [ ] Role-based access control implemented
- [ ] Failed login attempts limited

### API Security
- [ ] Rate limiting implemented
- [ ] CORS properly configured
- [ ] CSRF protection enabled
- [ ] API keys rotated regularly
- [ ] Request/response logging (no sensitive data)

### Data Protection
- [ ] SQL/NoSQL injection prevented
- [ ] Sensitive data encrypted at rest
- [ ] TLS 1.2+ enforced
- [ ] PII data identified and protected
- [ ] Data minimization practiced

### Infrastructure Security
- [ ] Dependencies regularly updated
- [ ] Security headers set (CSP, HSTS, etc.)
- [ ] Error messages don't leak information
- [ ] Environment variables protected
- [ ] Regular security scans performed

---

## 🚨 Incident Response Template

```javascript
// security-incident-response.js
class SecurityIncidentResponse {
  static async handleIncident(type, details) {
    const incident = {
      type,
      details,
      timestamp: new Date().toISOString(),
      severity: this.assessSeverity(type, details),
    };

    // 1. Immediate containment
    await this.containIncident(incident);

    // 2. Investigation
    const investigation = await this.investigateIncident(incident);

    // 3. Eradication
    await this.eradicateThreat(investigation);

    // 4. Recovery
    await this.recoverSystems(incident);

    // 5. Post-incident analysis
    await this.conductPostMortem(incident);

    // 6. Update security controls
    await this.improveSecurityControls(incident);
  }

  static assessSeverity(type, details) {
    const severityMatrix = {
      'SQL_INJECTION': 'CRITICAL',
      'XSS': 'HIGH',
      'CSRF': 'MEDIUM',
      'DATA_LEAK': 'CRITICAL',
      'UNAUTHORIZED_ACCESS': 'HIGH',
    };
    return severityMatrix[type] || 'MEDIUM';
  }

  static async containIncident(incident) {
    // Implement based on incident type
    switch (incident.type) {
      case 'SQL_INJECTION':
        // Block suspicious IP, rollback queries
        break;
      case 'DATA_LEAK':
        // Revoke exposed credentials, reset keys
        break;
    }
  }
}
```

---

## 🔧 Security Tools Recommendation

### Development
- **ESLint with security plugins**: `eslint-plugin-security`
- **Dependency scanning**: `npm audit`, `snyk`, `dependabot`
- **Secret scanning**: `truffleHog`, `git-secrets`

### Testing
- **Static Analysis**: SonarQube, Semgrep
- **Dynamic Analysis**: OWASP ZAP, Burp Suite
- **Penetration Testing**: Metasploit, sqlmap

### Monitoring
- **Log aggregation**: ELK Stack, Splunk
- **SIEM**: Splunk ES, Azure Sentinel
- **RASP**: Imperva, Signal Sciences

### Deployment
- **Container scanning**: Trivy, Clair
- **Infrastructure as Code scanning**: Checkov, Terraform Compliance
- **WAF**: Cloudflare, AWS WAF, ModSecurity

---

## 📚 Additional Resources

### OWASP Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)

### Standards & Frameworks
- NIST Cybersecurity Framework
- ISO 27001
- PCI DSS (for payment processing)

### Learning Platforms
- PortSwigger Web Security Academy
- PentesterLab
- HackTheBox

---

## 🎓 Interview Preparation Tips

1. **Understand the fundamentals**: Know how attacks work at a protocol level
2. **Think in layers**: Security is about defense in depth
3. **Balance security and usability**: Overly restrictive security can hurt UX
4. **Stay updated**: Follow security blogs, CVEs, and attend conferences
5. **Practice**: Use platforms like PortSwigger Labs to practice real exploits

---

*Last updated: December 2025*  
*Remember: Security is a process, not a product. Regular audits, updates, and education are key to maintaining a secure application.*