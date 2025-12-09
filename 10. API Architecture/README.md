# API Architecture Guide

## 📚 Table of Contents
1. [Overview](#overview)
2. [MVC Pattern](#mvc-pattern)
3. [Services Folder](#services-folder)
4. [Repositories](#repositories)
5. [DTOs](#dtos)
6. [Middlewares Layer](#middlewares-layer)
7. [Utils Folder](#utils-folder)
8. [Error Handling Structure](#error-handling-structure)
9. [Separate Env Config](#separate-env-config)
10. [Versioning APIs](#versioning-apis)
11. [Pagination](#pagination)
12. [Filtering](#filtering)
13. [Sorting](#sorting)
14. [HATEOAS](#hateoas-optional)
15. [Interview Questions](#interview-questions)
16. [Real-World Scenarios](#real-world-scenarios)

## Overview

This document outlines a comprehensive API architecture pattern for building scalable, maintainable, and production-ready RESTful APIs. The architecture follows industry best practices and promotes separation of concerns, testability, and team collaboration.

---

## MVC Pattern

### **Description**
The Model-View-Controller (MVC) pattern separates application concerns into three components:
- **Models**: Data structures and business logic
- **Views**: Presentation layer (in APIs, this is typically JSON responses)
- **Controllers**: Handle requests, coordinate between models and views

### **Implementation**
```javascript
// Controller Example
class UserController {
  async getUsers(req, res) {
    const users = await userService.getAllUsers();
    res.json(UserDTO.fromArray(users));
  }
}

// Model Example
class User {
  constructor(id, name, email) {
    this.id = id;
    this.name = name;
    this.email = email;
  }
}
```

### **Interview Questions**
1. **Basic**: What are the advantages of using MVC pattern in API development?
2. **Intermediate**: How does MVC differ in API development compared to traditional web applications?
3. **Advanced**: When would you consider breaking away from strict MVC pattern in API design?

---

## Services Folder

### **Description**
Services contain business logic that doesn't naturally fit into models or controllers. They encapsulate complex operations, orchestrate multiple repository calls, and implement business rules.

### **Structure**
```
src/
  services/
    user.service.js
    payment.service.js
    notification.service.js
    auth.service.js
```

### **Best Practices**
- Services should be stateless
- One service per business domain
- Can call multiple repositories
- Should not handle HTTP-specific logic

### **Interview Questions**
1. **Basic**: What types of logic belong in services vs controllers?
2. **Intermediate**: How do you prevent service classes from becoming "god objects"?
3. **Advanced**: Describe strategies for managing dependencies between services.

---

## Repositories

### **Description**
Repositories abstract data access logic, providing a collection-like interface for accessing domain objects. They separate business logic from data storage concerns.

### **Implementation**
```javascript
class UserRepository {
  constructor(db) {
    this.db = db;
  }
  
  async findById(id) {
    return this.db.users.find({ id });
  }
  
  async create(userData) {
    return this.db.users.insert(userData);
  }
  
  async update(id, updates) {
    return this.db.users.update({ id }, updates);
  }
}
```

### **Patterns**
- Repository Pattern
- Data Mapper Pattern
- Unit of Work Pattern

### **Interview Questions**
1. **Basic**: What problem does the Repository pattern solve?
2. **Intermediate**: How would you implement a generic repository vs specific repositories?
3. **Advanced**: Discuss trade-offs between active record pattern and repository pattern.

---

## DTOs (Data Transfer Objects)

### **Description**
DTOs are simple objects that carry data between processes. They define the structure of data being transferred without business logic.

### **Use Cases**
- Request/Response payloads
- Data validation
- Preventing over-fetching/under-fetching
- Versioning data contracts

### **Implementation**
```javascript
class UserDTO {
  static fromEntity(user) {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      profileUrl: `/users/${user.id}`
    };
  }
  
  static toEntity(dto) {
    return {
      name: dto.name,
      email: dto.email,
      passwordHash: hash(dto.password)
    };
  }
}
```

### **Interview Questions**
1. **Basic**: Why use DTOs instead of sending entity objects directly?
2. **Intermediate**: How do DTOs help with API evolution and backward compatibility?
3. **Advanced**: Discuss performance implications of using DTOs in high-throughput systems.

---

## Middlewares Layer

### **Description**
Middlewares are functions that execute during the request/response cycle. They provide cross-cutting concerns like authentication, logging, and validation.

### **Common Middlewares**
```javascript
// Authentication middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization;
  req.user = await authService.verifyToken(token);
  next();
};

// Validation middleware
const validate = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body);
  if (error) throw new ValidationError(error.details);
  next();
};

// Logging middleware
const requestLogger = (req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
};
```

### **Interview Questions**
1. **Basic**: Explain the middleware execution order and how to control it.
2. **Intermediate**: How would you implement conditional middleware execution?
3. **Advanced**: Discuss strategies for managing middleware dependencies and testing.

---

## Utils Folder

### **Description**
Utility functions and helpers that are reused across the application. These should be pure, stateless functions.

### **Categories**
```
utils/
  constants.js       // Application constants
  helpers.js         // General helper functions
  validators.js      // Validation utilities
  formatters.js      // Data formatting utilities
  security.js        // Security-related utilities
  dateUtils.js       // Date manipulation functions
```

### **Best Practices**
- Keep functions pure and side-effect free
- Single responsibility per utility
- Comprehensive testing
- No business logic in utilities

### **Interview Questions**
1. **Basic**: What distinguishes utility functions from service methods?
2. **Intermediate**: How do you prevent utility file bloat?
3. **Advanced**: Discuss strategies for organizing utilities in a large codebase.

---

## Error Handling Structure

### **Description**
A consistent error handling strategy across the API with proper HTTP status codes, error messages, and logging.

### **Implementation**
```javascript
// Custom Error Classes
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
  }
}

class NotFoundError extends AppError {
  constructor(resource) {
    super(`${resource} not found`, 404);
  }
}

// Error Middleware
const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const response = {
    error: {
      message: err.message,
      code: err.code,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  };
  
  res.status(statusCode).json(response);
};
```

### **Interview Questions**
1. **Basic**: What are the key components of a good error response?
2. **Intermediate**: How would you implement error localization (i18n)?
3. **Advanced**: Discuss strategies for handling and monitoring asynchronous errors.

---

## Separate Env Config

### **Description**
Environment-specific configuration management that separates configuration from code.

### **Structure**
```
config/
  default.js
  development.js
  test.js
  production.js
  staging.js
.env.example
```

### **Implementation**
```javascript
// config/default.js
module.exports = {
  port: process.env.PORT || 3000,
  database: {
    url: process.env.DB_URL,
    poolSize: 10
  },
  auth: {
    jwtSecret: process.env.JWT_SECRET,
    expiresIn: '24h'
  }
};

// Environment-specific overrides
// config/production.js
module.exports = {
  logging: {
    level: 'error'
  },
  database: {
    poolSize: 50
  }
};
```

### **Interview Questions**
1. **Basic**: Why is it important to separate configuration from code?
2. **Intermediate**: How would you handle sensitive configuration in a cloud environment?
3. **Advanced**: Discuss strategies for configuration validation and schema enforcement.

---

## Versioning APIs

### **Description**
API versioning strategies to manage breaking changes while maintaining backward compatibility.

### **Strategies**
1. **URL Versioning**: `/api/v1/users`
2. **Header Versioning**: `Accept: application/vnd.company.v1+json`
3. **Query Parameter**: `/api/users?version=1`
4. **Media Type Versioning**: Custom content types

### **Implementation**
```javascript
// Route definition with versioning
app.use('/api/v1/users', v1UserRoutes);
app.use('/api/v2/users', v2UserRoutes);

// Header-based versioning middleware
const apiVersion = (req, res, next) => {
  const version = req.headers['api-version'] || 'v1';
  req.apiVersion = version;
  next();
};
```

### **Interview Questions**
1. **Basic**: Compare different API versioning strategies and their trade-offs.
2. **Intermediate**: How would you handle deprecated API versions?
3. **Advanced**: Discuss strategies for zero-downtime API version migrations.

---

## Pagination

### **Description**
Techniques for breaking large result sets into manageable chunks.

### **Implementation Patterns**
```javascript
// Offset-based Pagination
const getUsers = async (page = 1, limit = 20) => {
  const offset = (page - 1) * limit;
  return await userRepository.find({ offset, limit });
};

// Cursor-based Pagination
const getUsers = async (cursor, limit = 20) => {
  return await userRepository.find({
    where: { id: { $gt: cursor } },
    limit
  });
};

// Response Format
{
  "data": [...],
  "pagination": {
    "total": 1000,
    "page": 2,
    "limit": 20,
    "totalPages": 50,
    "hasNext": true,
    "hasPrev": true
  }
}
```

### **Interview Questions**
1. **Basic**: Compare offset vs cursor-based pagination.
2. **Intermediate**: How would you implement efficient pagination with filtered results?
3. **Advanced**: Discuss pagination challenges in distributed systems with eventual consistency.

---

## Filtering

### **Description**
Allowing clients to filter results based on various criteria.

### **Implementation**
```javascript
// Query Builder Pattern
class QueryBuilder {
  constructor(baseQuery = {}) {
    this.query = baseQuery;
  }
  
  filter(filters) {
    Object.entries(filters).forEach(([key, value]) => {
      if (this.isValidFilter(key)) {
        this.query[key] = value;
      }
    });
    return this;
  }
  
  build() {
    return this.query;
  }
}

// Usage
const filters = {
  status: 'active',
  role: 'admin',
  createdAfter: '2024-01-01'
};

const query = new QueryBuilder()
  .filter(filters)
  .build();
```

### **Interview Questions**
1. **Basic**: How would you design a flexible filtering API?
2. **Intermediate**: What security considerations are important for filter APIs?
3. **Advanced**: Discuss implementing complex filtering with operators (AND, OR, NOT).

---

## Sorting

### **Description**
Allowing clients to specify result ordering.

### **Implementation**
```javascript
const parseSort = (sortQuery) => {
  if (!sortQuery) return { createdAt: -1 }; // Default sort
  
  return sortQuery.split(',').reduce((sort, field) => {
    const direction = field.startsWith('-') ? -1 : 1;
    const fieldName = field.replace(/^-/, '');
    
    if (this.isSortableField(fieldName)) {
      sort[fieldName] = direction;
    }
    
    return sort;
  }, {});
};

// API: GET /users?sort=-createdAt,name
```

### **Interview Questions**
1. **Basic**: How would you handle multi-field sorting?
2. **Intermediate**: What performance considerations exist for sorting?
3. **Advanced**: Discuss implementing sorting on computed/aggregated fields.

---

## HATEOAS (Optional)

### **Description**
Hypermedia as the Engine of Application State - including links in API responses to guide clients through available actions.

### **Implementation**
```javascript
const addLinks = (resource, req) => {
  return {
    ...resource,
    _links: {
      self: { href: `${req.baseUrl}/${resource.id}` },
      update: { 
        href: `${req.baseUrl}/${resource.id}`,
        method: 'PUT'
      },
      delete: {
        href: `${req.baseUrl}/${resource.id}`,
        method: 'DELETE'
      }
    }
  };
};

// Response Format
{
  "id": 123,
  "name": "John Doe",
  "_links": {
    "self": { "href": "/api/v1/users/123" },
    "update": { "href": "/api/v1/users/123", "method": "PUT" },
    "delete": { "href": "/api/v1/users/123", "method": "DELETE" }
  }
}
```

### **Interview Questions**
1. **Basic**: What are the benefits of HATEOAS?
2. **Intermediate**: How does HATEOAS affect API discoverability?
3. **Advanced**: Discuss implementing HATEOAS in a microservices architecture.

---

## Interview Questions

### **Architectural Design Questions**
1. **System Design**: "Design an API for a ride-sharing service like Uber. How would you structure the endpoints, handle real-time updates, and ensure scalability?"
   
2. **Performance Optimization**: "Our user listing API is slowing down as we approach 10 million users. What architectural changes would you propose to maintain performance?"
   
3. **Security**: "How would you design an API that needs to handle sensitive financial data while complying with GDPR and PCI DSS?"
   
4. **Migration Strategy**: "We need to migrate from REST to GraphQL without breaking existing clients. What would your migration strategy look like?"
   
5. **Caching Strategy**: "Design a caching strategy for an e-commerce API with frequently changing inventory and pricing data."

### **Problem-Solving Questions**
1. **Rate Limiting**: "How would you implement a sophisticated rate-limiting system that considers different tiers of API consumers?"
   
2. **Webhook Reliability**: "Design a reliable webhook system that guarantees delivery even when third-party endpoints are temporarily unavailable."
   
3. **Data Consistency**: "How would you ensure data consistency in an API that updates multiple microservices in a single transaction?"
   
4. **API Monitoring**: "What metrics and monitoring would you implement for a business-critical API?"
   
5. **Documentation**: "How would you ensure API documentation stays synchronized with the actual implementation?"

### **Behavioral Questions**
1. **Trade-off Decisions**: "Describe a time you had to make a trade-off between API design purity and practical implementation constraints."
   
2. **Breaking Changes**: "How have you handled introducing breaking changes to a public API used by thousands of developers?"
   
3. **Team Collaboration**: "How do you ensure consistency in API design across multiple teams working on different services?"
   
4. **Technical Debt**: "Describe your approach to managing technical debt in a large API codebase."
   
5. **Mentoring**: "How would you mentor junior developers on API design principles and best practices?"

---

## Real-World Scenarios

### **Scenario 1: Social Media Platform API**
**Context**: Building Twitter-like API with tweets, followers, and real-time notifications.

**Challenges**:
- High read/write ratio
- Timeline generation complexity
- Real-time updates
- Media uploads and processing

**Architecture Decisions**:
- CQRS pattern for timeline generation
- WebSocket for real-time notifications
- CDN for media storage
- Event-driven architecture for fan-out updates

### **Scenario 2: E-commerce Marketplace API**
**Context**: Multi-vendor marketplace like Amazon with inventory, orders, and payments.

**Challenges**:
- Inventory consistency
- Payment gateway integration
- Order fulfillment workflow
- Multi-tenancy

**Architecture Decisions**:
- Saga pattern for distributed transactions
- Circuit breakers for external service calls
- Event sourcing for order history
- API gateway for vendor-specific routing

### **Scenario 3: IoT Device Management API**
**Context**: Managing millions of IoT devices with telemetry data and remote commands.

**Challenges**:
- High volume of concurrent connections
- Device authentication and authorization
- Command queuing and delivery guarantees
- Data aggregation and analytics

**Architecture Decisions**:
- MQTT/WebSocket for device communication
- Device shadow pattern for state management
- Time-series database for telemetry
- Message queue for command processing

### **Scenario 4: Banking API**
**Context**: Digital banking API for account management, transfers, and transactions.

**Challenges**:
- Regulatory compliance (PSD2, Open Banking)
- Financial transaction integrity
- Fraud detection
- Audit trails

**Architecture Decisions**:
- Idempotent operations for transactions
- Immutable audit logs
- Real-time fraud detection microservice
- API security gateway with strong authentication

### **Scenario 5: Healthcare Telemedicine API**
**Context**: HIPAA-compliant API for patient records, appointments, and video consultations.

**Challenges**:
- PHI data protection
- Real-time video streaming
- Appointment scheduling optimization
- Provider-patient matching

**Architecture Decisions**:
- End-to-end encryption for sensitive data
- WebRTC for video consultations
- Rule engine for scheduling optimization
- Strict access controls with role-based permissions

---

## Quick Reference Checklist

### **For New API Development**
- [ ] Implement MVC separation
- [ ] Set up service layer for business logic
- [ ] Create repository layer for data access
- [ ] Define DTOs for request/response
- [ ] Configure environment-specific settings
- [ ] Implement error handling middleware
- [ ] Add API versioning strategy
- [ ] Design pagination, filtering, sorting
- [ ] Set up logging and monitoring
- [ ] Create comprehensive documentation

### **For API Maintenance**
- [ ] Monitor API performance metrics
- [ ] Review and update documentation
- [ ] Analyze error rates and patterns
- [ ] Check dependency updates
- [ ] Review security vulnerabilities
- [ ] Test backward compatibility
- [ ] Optimize database queries
- [ ] Update rate limiting rules
- [ ] Archive deprecated versions

---

## Additional Resources

### **Books**
- "Designing Web APIs" by Brenda Jin
- "REST API Design Rulebook" by Mark Masse
- "Building Microservices" by Sam Newman

### **Tools**
- **API Documentation**: Swagger/OpenAPI, Postman
- **Testing**: Jest, Supertest, Newman
- **Monitoring**: Prometheus, Grafana, New Relic
- **Security**: OWASP ZAP, Burp Suite

### **Standards**
- OpenAPI Specification
- JSON API
- OAuth 2.0 / OpenID Connect
- RFC 7807 (Problem Details for HTTP APIs)

---
