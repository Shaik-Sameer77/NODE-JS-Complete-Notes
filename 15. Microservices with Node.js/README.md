# Microservices with Node.js & TypeScript: Comprehensive Guide

## 📚 Table of Contents
1. [Monolith vs Microservices](#1-monolith-vs-microservices)
2. [API Gateway Pattern](#2-api-gateway-pattern)
3. [Message Brokers](#3-message-brokers)
4. [Event-Driven Architecture](#4-event-driven-architecture)
5. [Microservice Communication](#5-microservice-communication)
6. [Distributed Tracing](#6-distributed-tracing)
7. [Service Discovery](#7-service-discovery)
8. [Load Balancing](#8-load-balancing)
9. [Circuit Breakers](#9-circuit-breakers)
10. [Saga Pattern](#10-saga-pattern)
11. [CQRS (Optional)](#11-cqrs-optional)
12. [Applying TypeScript](#12-applying-typescript)
13. [Using Nx or Turborepo](#13-using-nx-or-turborepo)

---

## 1. Monolith vs Microservices

### 📖 In-Depth Explanation

**Monolithic Architecture** is a traditional unified model where all components of an application are interconnected and interdependent. Think of it as a single, large container housing all application components.

```typescript
// Monolithic Structure Example
src/
├── controllers/
├── models/
├── routes/
├── services/
└── app.ts  // Everything in one codebase
```

**Microservices Architecture** decomposes applications into small, loosely coupled services that can be developed, deployed, and scaled independently.

```typescript
// Microservices Structure Example
services/
├── user-service/
├── order-service/
├── payment-service/
├── notification-service/
└── api-gateway/
```

### ⚖️ Comparison Table

| Aspect | Monolithic | Microservices |
|--------|------------|---------------|
| **Development** | Single codebase, easier to start | Multiple repos, complex setup |
| **Deployment** | Single deployment unit | Independent deployments |
| **Scalability** | Scale entire app | Scale individual services |
| **Technology** | Single tech stack | Polyglot (mixed technologies) |
| **Failure** | Single point of failure | Isolated failures |
| **Data Management** | Single database | Database per service |

### 🎯 Real-World Scenario: E-commerce Migration
*You're leading the migration of a monolithic e-commerce platform (users, products, orders, payments) to microservices. The current system struggles with scaling during flash sales and has deployment bottlenecks.*

**Interview Questions:**
1. What metrics would you use to justify a microservices migration?
2. How would you approach breaking down the monolith? (Strangler Pattern vs Big Bang)
3. What are the hidden costs of microservices that stakeholders might overlook?
4. How would you handle shared data models during transition?
5. What organizational changes are needed for successful microservices adoption?

**Technical Questions:**
1. When is a monolith actually preferable to microservices?
2. How do you handle transactions that span multiple services?
3. What strategies exist for database decomposition?
4. How do you maintain consistency during the migration phase?

---

## 2. API Gateway Pattern

### 📖 In-Depth Explanation

An API Gateway is a single entry point that routes requests to appropriate microservices, handles cross-cutting concerns, and provides a unified interface to clients.

```typescript
// API Gateway with Express + TypeScript
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import rateLimit from 'express-rate-limit';

const app = express();

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(limiter);

// Routing to microservices
app.use('/api/users', createProxyMiddleware({
  target: 'http://user-service:3001',
  changeOrigin: true,
  pathRewrite: { '^/api/users': '' }
}));

app.use('/api/orders', createProxyMiddleware({
  target: 'http://order-service:3002',
  changeOrigin: true,
  pathRewrite: { '^/api/orders': '' }
}));

// Request/Response transformation
app.use('/api/aggregate/user-orders', async (req, res) => {
  const userData = await fetchUser(req.userId);
  const orders = await fetchOrders(req.userId);
  res.json({ user: userData, orders });
});

// Authentication middleware
app.use(async (req, res, next) => {
  const token = req.headers.authorization;
  const isValid = await validateToken(token);
  if (!isValid) return res.status(401).json({ error: 'Unauthorized' });
  next();
});
```

### 🎯 Real-World Scenario: Multi-Client Support
*Your company needs to support web, mobile, and third-party partners through the same microservices backend. Each client has different data requirements and rate limits.*

**Interview Questions:**
1. How would you design an API Gateway to handle different client requirements?
2. What strategies would you use for API versioning in a microservices ecosystem?
3. How do you handle partial failures when aggregating data from multiple services?
4. What security considerations are crucial at the API Gateway level?
5. How would you implement caching strategies at the gateway?

**Technical Questions:**
1. How do you implement circuit breaking at the gateway level?
2. What's the difference between API Gateway and Service Mesh?
3. How do you handle WebSocket connections through an API Gateway?
4. What metrics should you collect at the gateway for observability?

---

## 3. Message Brokers

### 📖 In-Depth Explanation

Message brokers enable asynchronous communication between microservices using publish-subscribe or message queue patterns.

#### **RabbitMQ (AMQP) Example**
```typescript
// Producer Service
import amqp from 'amqplib';

class OrderProducer {
  private channel: amqp.Channel;

  async connect() {
    const connection = await amqp.connect('amqp://localhost');
    this.channel = await connection.createChannel();
    await this.channel.assertExchange('order-events', 'topic', { durable: true });
  }

  async publishOrderCreated(order: Order) {
    this.channel.publish('order-events', 'order.created', 
      Buffer.from(JSON.stringify(order)),
      { persistent: true }
    );
  }
}

// Consumer Service
class NotificationConsumer {
  async consume() {
    const connection = await amqp.connect('amqp://localhost');
    const channel = await connection.createChannel();
    
    await channel.assertExchange('order-events', 'topic', { durable: true });
    const queue = await channel.assertQueue('', { exclusive: true });
    
    await channel.bindQueue(queue.queue, 'order-events', 'order.*');
    
    channel.consume(queue.queue, (msg) => {
      if (msg) {
        const order = JSON.parse(msg.content.toString());
        this.sendNotification(order);
        channel.ack(msg);
      }
    });
  }
}
```

#### **Apache Kafka Example**
```typescript
// Kafka Producer with TypeScript
import { Kafka, Producer } from 'kafkajs';

const kafka = new Kafka({
  clientId: 'order-service',
  brokers: ['kafka1:9092', 'kafka2:9092']
});

const producer = kafka.producer();

await producer.connect();
await producer.send({
  topic: 'orders',
  messages: [
    {
      key: order.id,
      value: JSON.stringify(order),
      headers: {
        'event-type': 'ORDER_CREATED',
        'version': '1.0'
      }
    }
  ]
});

// Kafka Consumer with Schema Registry
import { SchemaRegistry } from '@kafkajs/confluent-schema-registry';

const registry = new SchemaRegistry({ host: 'http://schema-registry:8081' });
const consumer = kafka.consumer({ groupId: 'notification-group' });

await consumer.subscribe({ topic: 'orders', fromBeginning: false });

await consumer.run({
  eachMessage: async ({ message }) => {
    const decodedValue = await registry.decode(message.value);
    // Process Avro-serialized message
  }
});
```

### ⚖️ RabbitMQ vs Kafka Comparison

| Feature | RabbitMQ | Apache Kafka |
|---------|----------|--------------|
| **Pattern** | Message Queue, Pub/Sub | Log-based, Pub/Sub |
| **Delivery** | Push-based | Pull-based |
| **Ordering** | Queue-level ordering | Partition-level ordering |
| **Throughput** | ~50K msg/sec | Millions msg/sec |
| **Durability** | Optional persistence | Persistent log |
| **Use Case** | Task distribution, RPC | Event streaming, analytics |

### 🎯 Real-World Scenario: Order Processing System
*You're designing an order processing system where orders go through validation, inventory check, payment processing, and shipping. Each step can take varying time and may fail.*

**Interview Questions:**
1. When would you choose Kafka over RabbitMQ for an order processing system?
2. How would you ensure exactly-once processing in a distributed messaging system?
3. What strategies would you use for message schema evolution?
4. How do you handle poison pills (unprocessable messages)?
5. What monitoring and alerting would you implement for your message brokers?

**Technical Questions:**
1. How do you implement dead letter queues in RabbitMQ?
2. What are Kafka consumer groups and how do they work?
3. How do you handle message ordering requirements across partitions?
4. What are idempotent producers and why are they important?

---

## 4. Event-Driven Architecture

### 📖 In-Depth Explanation

Event-Driven Architecture (EDA) uses events to trigger and communicate between decoupled services. Events represent state changes and are immutable.

```typescript
// Event Sourcing with TypeScript
interface DomainEvent {
  id: string;
  type: string;
  aggregateId: string;
  version: number;
  timestamp: Date;
  payload: any;
}

class OrderAggregate {
  private events: DomainEvent[] = [];
  private state: OrderState;

  createOrder(orderData: OrderData) {
    const event: DomainEvent = {
      id: uuid(),
      type: 'ORDER_CREATED',
      aggregateId: this.id,
      version: this.currentVersion + 1,
      timestamp: new Date(),
      payload: orderData
    };
    
    this.applyEvent(event);
    this.events.push(event);
  }

  private applyEvent(event: DomainEvent) {
    switch (event.type) {
      case 'ORDER_CREATED':
        this.state = { ...event.payload, status: 'CREATED' };
        break;
      case 'ORDER_PAID':
        this.state.status = 'PAID';
        break;
    }
  }

  // Rebuild state from event stream
  static fromEvents(events: DomainEvent[]): OrderAggregate {
    const aggregate = new OrderAggregate();
    events.forEach(event => aggregate.applyEvent(event));
    return aggregate;
  }
}

// Event-Driven Service Integration
class OrderService {
  constructor(private eventBus: EventBus) {}

  async processOrder(orderId: string) {
    // 1. Validate order
    // 2. Publish ORDER_VALIDATED event
    await this.eventBus.publish({
      type: 'ORDER_VALIDATED',
      payload: { orderId, timestamp: new Date() }
    });

    // Other services subscribe to these events
  }
}

class PaymentService {
  constructor(private eventBus: EventBus) {
    this.eventBus.subscribe('ORDER_VALIDATED', this.processPayment.bind(this));
  }

  async processPayment(event: DomainEvent) {
    // Process payment and publish PAYMENT_PROCESSED event
  }
}
```

### 🎯 Real-World Scenario: Real-time Inventory Management
*You're building a retail system where inventory updates must be reflected in real-time across multiple channels (web, mobile, physical stores). Stock levels change frequently due to purchases, returns, and shipments.*

**Interview Questions:**
1. How would you design an event-driven system for real-time inventory?
2. What strategies would you use to handle event ordering across distributed systems?
3. How do you ensure no events are lost during processing?
4. What would you do if a service goes down and misses events?
5. How do you handle schema changes in event payloads over time?

**Technical Questions:**
1. What's the difference between Event Sourcing and Event-Driven Architecture?
2. How do you implement idempotent event handlers?
3. What are outbox patterns and why are they important?
4. How do you handle compensating events for rollbacks?

---

## 5. Microservice Communication

### 📖 In-Depth Explanation

Microservices communicate through various patterns: synchronous (HTTP/REST, gRPC) and asynchronous (messaging).

#### **gRPC with TypeScript and Protocol Buffers**
```protobuf
// protos/order.proto
syntax = "proto3";

package order;

service OrderService {
  rpc CreateOrder (CreateOrderRequest) returns (OrderResponse);
  rpc GetOrder (GetOrderRequest) returns (OrderResponse);
  rpc StreamOrders (OrderStreamRequest) returns (stream OrderResponse);
}

message CreateOrderRequest {
  string user_id = 1;
  repeated OrderItem items = 2;
}

message OrderResponse {
  string order_id = 1;
  OrderStatus status = 2;
  double total = 3;
}

enum OrderStatus {
  PENDING = 0;
  CONFIRMED = 1;
  SHIPPED = 2;
  DELIVERED = 3;
}
```

```typescript
// gRPC Server
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';

const packageDefinition = protoLoader.loadSync('order.proto');
const orderProto = grpc.loadPackageDefinition(packageDefinition);

const server = new grpc.Server();

server.addService(orderProto.order.OrderService.service, {
  createOrder: (call: grpc.ServerUnaryCall<any, any>, callback: grpc.sendUnaryData<any>) => {
    const order = processOrder(call.request);
    callback(null, order);
  },
  
  streamOrders: (call: grpc.ServerWritableStream<any, any>) => {
    const orders = getOrderStream();
    orders.forEach(order => call.write(order));
    call.end();
  }
});

// gRPC Client
const client = new orderProto.order.OrderService(
  'localhost:50051',
  grpc.credentials.createInsecure()
);

// Bidirectional Streaming Example
const duplexStream = client.chat();
duplexStream.on('data', (response) => {
  console.log('Received:', response);
});
duplexStream.write({ message: 'Hello' });
```

#### **REST with Service Discovery**
```typescript
// Service Client with Circuit Breaker and Retry
import axios, { AxiosInstance } from 'axios';
import axiosRetry from 'axios-retry';
import CircuitBreaker from 'opossum';

class ServiceClient {
  private client: AxiosInstance;
  private breaker: CircuitBreaker;

  constructor(private serviceName: string, private discovery: ServiceDiscovery) {
    this.client = axios.create();
    
    axiosRetry(this.client, {
      retries: 3,
      retryDelay: axiosRetry.exponentialDelay,
      retryCondition: (error) => {
        return axiosRetry.isNetworkError(error) || 
               axiosRetry.isRetryableError(error) ||
               error.response?.status === 429;
      }
    });

    this.breaker = new CircuitBreaker(
      async (url: string, data: any) => {
        const serviceUrl = await this.discovery.resolve(this.serviceName);
        return this.client.post(`${serviceUrl}${url}`, data);
      },
      {
        timeout: 3000,
        errorThresholdPercentage: 50,
        resetTimeout: 30000
      }
    );
  }

  async callService(endpoint: string, data: any) {
    return this.breaker.fire(endpoint, data);
  }
}
```

### 🎯 Real-World Scenario: Multi-Datacenter Communication
*Your microservices are deployed across multiple AWS regions for disaster recovery. Services need to communicate with low latency while maintaining data consistency.*

**Interview Questions:**
1. How would you design service communication for multi-region deployment?
2. What strategies would you use to minimize latency in cross-region calls?
3. How do you handle network partitions (CAP theorem considerations)?
4. What monitoring would you implement for inter-service communication?
5. How would you implement service-to-service authentication across regions?

**Technical Questions:**
1. What are the trade-offs between gRPC and REST for internal communication?
2. How do you implement mutual TLS for service authentication?
3. What are sticky sessions and when are they problematic?
4. How do you handle service versioning in API contracts?

---

## 6. Distributed Tracing

### 📖 In-Depth Explanation

Distributed tracing tracks requests as they flow through multiple microservices, providing visibility into performance and dependencies.

```typescript
// OpenTelemetry Implementation
import { NodeTracerProvider } from '@opentelemetry/node';
import { SimpleSpanProcessor, ConsoleSpanExporter } from '@opentelemetry/tracing';
import { ZipkinExporter } from '@opentelemetry/exporter-zipkin';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { KafkaInstrumentation } from '@opentelemetry/instrumentation-kafkajs';

// Setup Tracing
const provider = new NodeTracerProvider();

// Export to multiple backends
provider.addSpanProcessor(new SimpleSpanProcessor(new ConsoleSpanExporter()));
provider.addSpanProcessor(new SimpleSpanProcessor(new ZipkinExporter({
  serviceName: 'order-service',
  url: 'http://zipkin:9411/api/v2/spans'
})));

provider.register();

// Instrumentations
const httpInstrumentation = new HttpInstrumentation();
const expressInstrumentation = new ExpressInstrumentation();
const kafkaInstrumentation = new KafkaInstrumentation();

// Custom Instrumentation
import { trace } from '@opentelemetry/api';

class TracedService {
  async processOrder(orderId: string) {
    const tracer = trace.getTracer('order-service');
    
    return tracer.startActiveSpan('processOrder', async (span) => {
      try {
        span.setAttribute('order.id', orderId);
        span.setAttribute('service.version', '1.0.0');
        
        // Add events to span
        span.addEvent('order_processing_started', {
          timestamp: Date.now()
        });

        // Business logic
        const result = await this.validateOrder(orderId);
        
        span.setStatus({ code: SpanStatusCode.OK });
        span.addEvent('order_processing_completed');
        
        return result;
      } catch (error) {
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error.message
        });
        span.recordException(error);
        throw error;
      } finally {
        span.end();
      }
    });
  }
}

// Context Propagation
import { context, propagation } from '@opentelemetry/api';

async function makeServiceCall(url: string, data: any) {
  const tracer = trace.getTracer('http-client');
  const span = tracer.startSpan('service-call');

  return context.with(trace.setSpan(context.active(), span), async () => {
    const headers = {};
    // Inject trace context into headers
    propagation.inject(context.active(), headers);

    const response = await axios.post(url, data, { headers });
    span.end();
    return response;
  });
}
```

### 🎯 Real-World Scenario: Performance Investigation
*Users are experiencing slow checkout times. The checkout process involves 8 different microservices, and you need to identify the bottleneck.*

**Interview Questions:**
1. How would you instrument your services for distributed tracing?
2. What trace data would you collect to identify performance issues?
3. How would you correlate logs with traces for debugging?
4. What sampling strategies would you implement for production tracing?
5. How do you handle trace context propagation across different transport protocols?

**Technical Questions:**
1. What's the difference between OpenTracing and OpenTelemetry?
2. How do you implement custom instrumentation for database queries?
3. What are span attributes vs span events?
4. How do you handle trace context in asynchronous operations?

---

## 7. Service Discovery

### 📖 In-Depth Explanation

Service discovery enables microservices to find and communicate with each other dynamically in a distributed environment.

```typescript
// Client-side Discovery Pattern
interface ServiceInstance {
  id: string;
  serviceName: string;
  host: string;
  port: number;
  metadata: Map<string, string>;
  status: 'UP' | 'DOWN';
  lastHeartbeat: Date;
}

class ServiceDiscoveryClient {
  private registry: Map<string, ServiceInstance[]> = new Map();
  private heartbeatInterval: NodeJS.Timeout;

  constructor(private discoveryServerUrl: string) {
    this.startHeartbeat();
    this.startServicePolling();
  }

  async register(service: ServiceInstance) {
    await axios.post(`${this.discoveryServerUrl}/register`, service);
  }

  async discover(serviceName: string): Promise<ServiceInstance> {
    const instances = this.registry.get(serviceName) || [];
    
    if (instances.length === 0) {
      await this.refreshServiceList(serviceName);
      return this.discover(serviceName);
    }

    // Load balancing: Round Robin
    const instance = instances[this.currentIndex % instances.length];
    this.currentIndex++;
    
    // Health check
    if (!await this.isHealthy(instance)) {
      return this.discover(serviceName);
    }
    
    return instance;
  }

  private async refreshServiceList(serviceName: string) {
    const response = await axios.get(
      `${this.discoveryServerUrl}/services/${serviceName}`
    );
    this.registry.set(serviceName, response.data);
  }

  private startHeartbeat() {
    this.heartbeatInterval = setInterval(async () => {
      await axios.post(`${this.discoveryServerUrl}/heartbeat`, {
        serviceId: this.serviceId
      });
    }, 30000);
  }
}

// Server-side Discovery with Consul
import Consul from 'consul';

class ConsulServiceDiscovery {
  private consul: Consul.Consul;

  constructor() {
    this.consul = new Consul({
      host: 'consul-server',
      port: '8500'
    });
  }

  async registerService(service: any) {
    await this.consul.agent.service.register({
      name: service.name,
      id: service.id,
      address: service.address,
      port: service.port,
      tags: service.tags,
      check: {
        http: `http://${service.address}:${service.port}/health`,
        interval: '10s',
        timeout: '5s',
        deregistercriticalserviceafter: '1m'
      }
    });
  }

  async discoverService(serviceName: string): Promise<any[]> {
    return this.consul.health.service({
      service: serviceName,
      passing: true
    });
  }
}
```

### 🎯 Real-World Scenario: Auto-scaling Environment
*Your services auto-scale based on load. New instances spin up and down constantly. Services need to discover each other without manual configuration.*

**Interview Questions:**
1. How would you design service discovery for an auto-scaling Kubernetes environment?
2. What are the trade-offs between client-side and server-side discovery?
3. How do you handle service discovery during network partitions?
4. What strategies would you use for service registration and deregistration?
5. How do you prevent stale service registry entries?

**Technical Questions:**
1. How does DNS-based service discovery work in Kubernetes?
2. What are health checks and how often should they run?
3. How do you implement zone-aware service discovery?
4. What are the security considerations for service discovery?

---

## 8. Load Balancing

### 📖 In-Depth Explanation

Load balancing distributes traffic across multiple service instances to optimize resource utilization and ensure high availability.

```typescript
// Custom Load Balancer with Multiple Strategies
interface LoadBalancingStrategy {
  selectInstance(instances: ServiceInstance[]): ServiceInstance;
}

class RoundRobinStrategy implements LoadBalancingStrategy {
  private currentIndex: number = 0;

  selectInstance(instances: ServiceInstance[]): ServiceInstance {
    const instance = instances[this.currentIndex % instances.length];
    this.currentIndex++;
    return instance;
  }
}

class LeastConnectionsStrategy implements LoadBalancingStrategy {
  private connectionCounts: Map<string, number> = new Map();

  selectInstance(instances: ServiceInstance[]): ServiceInstance {
    return instances.reduce((prev, current) => {
      const prevCount = this.connectionCounts.get(prev.id) || 0;
      const currentCount = this.connectionCounts.get(current.id) || 0;
      return currentCount < prevCount ? current : prev;
    });
  }

  incrementConnection(instanceId: string) {
    const count = this.connectionCounts.get(instanceId) || 0;
    this.connectionCounts.set(instanceId, count + 1);
  }
}

class AdaptiveLoadBalancer {
  private strategies: Map<string, LoadBalancingStrategy> = new Map();
  private metrics: Map<string, InstanceMetrics> = new Map();

  constructor(private discovery: ServiceDiscovery) {
    this.strategies.set('round-robin', new RoundRobinStrategy());
    this.strategies.set('least-connections', new LeastConnectionsStrategy());
    this.startMetricsCollection();
  }

  async getInstance(serviceName: string, strategy: string = 'adaptive'): Promise<ServiceInstance> {
    const instances = await this.discovery.discover(serviceName);
    
    if (instances.length === 0) {
      throw new Error(`No instances available for ${serviceName}`);
    }

    // Filter out unhealthy instances
    const healthyInstances = instances.filter(instance => 
      this.isInstanceHealthy(instance)
    );

    if (healthyInstances.length === 0) {
      throw new Error(`No healthy instances available for ${serviceName}`);
    }

    // Adaptive strategy based on metrics
    if (strategy === 'adaptive') {
      return this.adaptiveSelection(healthyInstances);
    }

    return this.strategies.get(strategy)?.selectInstance(healthyInstances) || healthyInstances[0];
  }

  private adaptiveSelection(instances: ServiceInstance[]): ServiceInstance {
    // Consider multiple factors: latency, error rate, CPU usage
    return instances.reduce((best, current) => {
      const bestScore = this.calculateScore(best);
      const currentScore = this.calculateScore(current);
      return currentScore > bestScore ? current : best;
    });
  }

  private calculateScore(instance: ServiceInstance): number {
    const metrics = this.metrics.get(instance.id);
    if (!metrics) return 100; // Default score for new instances

    let score = 100;
    
    // Penalize high latency
    if (metrics.avgLatency > 100) score -= 20;
    if (metrics.avgLatency > 500) score -= 30;
    
    // Penalize high error rate
    if (metrics.errorRate > 0.1) score -= 25;
    if (metrics.errorRate > 0.5) score -= 50;
    
    // Penalize high CPU usage
    if (metrics.cpuUsage > 80) score -= 15;
    
    return Math.max(0, score);
  }
}

// Integration with API Gateway
class LoadBalancedProxy {
  constructor(private loadBalancer: AdaptiveLoadBalancer) {}

  async proxyRequest(req: Request, serviceName: string) {
    try {
      const instance = await this.loadBalancer.getInstance(serviceName);
      
      const response = await axios({
        method: req.method,
        url: `http://${instance.host}:${instance.port}${req.path}`,
        data: req.body,
        headers: req.headers,
        timeout: 5000
      });

      // Update metrics on success
      this.updateMetrics(instance.id, {
        latency: Date.now() - req.startTime,
        success: true
      });

      return response.data;
    } catch (error) {
      // Update metrics on failure
      if (error.config?.instanceId) {
        this.updateMetrics(error.config.instanceId, {
          latency: Date.now() - req.startTime,
          success: false,
          error: error.code
        });
      }
      throw error;
    }
  }
}
```

### 🎯 Real-World Scenario: Black Friday Traffic Spike
*Your e-commerce platform needs to handle 10x normal traffic during Black Friday sales. You have auto-scaling configured but need intelligent load balancing.*

**Interview Questions:**
1. How would you design load balancing for sudden traffic spikes?
2. What metrics would you use for adaptive load balancing?
3. How do you handle "thundering herd" problem during service restarts?
4. What strategies would you use for canary deployments with load balancing?
5. How do you implement sticky sessions when needed (shopping cart)?

**Technical Questions:**
1. What's the difference between Layer 4 and Layer 7 load balancing?
2. How does consistent hashing work in load balancing?
3. What are health checks and how do they affect load balancing decisions?
4. How do you implement client-side load balancing vs server-side?

---

## 9. Circuit Breakers

### 📖 In-Depth Explanation

Circuit breakers prevent cascading failures by detecting failing services and temporarily blocking requests to them.

```typescript
// Circuit Breaker Implementation
interface CircuitBreakerOptions {
  failureThreshold: number;     // Failures before opening
  resetTimeout: number;         // Time before attempting reset
  timeout: number;              // Request timeout
  monitorInterval: number;      // Health check interval
}

enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}

class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount: number = 0;
  private lastFailureTime: number = 0;
  private nextAttemptTime: number = 0;
  private successCount: number = 0;
  private metrics: CircuitMetrics;

  constructor(
    private options: CircuitBreakerOptions,
    private command: (...args: any[]) => Promise<any>
  ) {
    this.startMonitoring();
  }

  async execute(...args: any[]): Promise<any> {
    // Check if circuit is open
    if (this.state === CircuitState.OPEN) {
      if (Date.now() < this.nextAttemptTime) {
        throw new CircuitBreakerError('Circuit is OPEN');
      }
      this.state = CircuitState.HALF_OPEN;
    }

    try {
      // Execute with timeout
      const result = await this.executeWithTimeout(...args);
      
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure(error);
      throw error;
    }
  }

  private async executeWithTimeout(...args: any[]): Promise<any> {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error('Request timeout'));
      }, this.options.timeout);

      this.command(...args)
        .then(resolve)
        .catch(reject)
        .finally(() => clearTimeout(timeoutId));
    });
  }

  private onSuccess(): void {
    this.failureCount = 0;
    
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
      
      // If enough successes in HALF_OPEN state, close circuit
      if (this.successCount >= 3) {
        this.state = CircuitState.CLOSED;
        this.successCount = 0;
        this.emit('closed');
      }
    }
  }

  private onFailure(error: Error): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.state === CircuitState.HALF_OPEN) {
      // Immediate trip back to OPEN
      this.state = CircuitState.OPEN;
      this.nextAttemptTime = Date.now() + this.options.resetTimeout;
      this.emit('open');
      return;
    }
    
    if (this.failureCount >= this.options.failureThreshold) {
      this.state = CircuitState.OPEN;
      this.nextAttemptTime = Date.now() + this.options.resetTimeout;
      this.emit('open');
    }
  }

  private startMonitoring(): void {
    setInterval(() => {
      this.collectMetrics();
      
      // Adaptive timeout based on response times
      if (this.metrics.avgResponseTime > this.options.timeout * 0.8) {
        this.options.timeout = Math.min(
          this.options.timeout * 1.5,
          10000 // Max 10 seconds
        );
      }
    }, this.options.monitorInterval);
  }
}

// Usage with Service Client
class ResilientServiceClient {
  private circuitBreaker: CircuitBreaker;

  constructor(private serviceUrl: string) {
    this.circuitBreaker = new CircuitBreaker(
      {
        failureThreshold: 5,
        resetTimeout: 30000,
        timeout: 3000,
        monitorInterval: 10000
      },
      this.callService.bind(this)
    );
  }

  private async callService(endpoint: string, data: any) {
    const response = await axios.post(
      `${this.serviceUrl}${endpoint}`,
      data,
      { timeout: 3000 }
    );
    return response.data;
  }

  async request(endpoint: string, data: any, retries: number = 3) {
    for (let i = 0; i < retries; i++) {
      try {
        return await this.circuitBreaker.execute(endpoint, data);
      } catch (error) {
        if (error instanceof CircuitBreakerError) {
          // Fallback strategy
          return this.fallback(endpoint, data);
        }
        
        if (i === retries - 1) throw error;
        
        // Exponential backoff
        await this.sleep(Math.pow(2, i) * 100);
      }
    }
  }

  private fallback(endpoint: string, data: any) {
    // Return cached data or default response
    switch (endpoint) {
      case '/products':
        return this.getCachedProducts();
      default:
        throw new Error('No fallback available');
    }
  }
}
```

### 🎯 Real-World Scenario: Payment Service Outage
*The payment service is experiencing intermittent failures. You need to prevent these failures from cascading to the checkout service while maintaining user experience.*

**Interview Questions:**
1. How would you configure circuit breakers for a payment service?
2. What fallback strategies would you implement for payment failures?
3. How do you determine appropriate thresholds for circuit breaker tripping?
4. What monitoring would you implement for circuit breaker states?
5. How do you handle the transition from OPEN to HALF_OPEN state?

**Technical Questions:**
1. What's the difference between circuit breaker and bulkhead pattern?
2. How do you implement adaptive timeouts based on service health?
3. What metrics should you expose from circuit breakers?
4. How do you test circuit breaker behavior?

---

## 10. Saga Pattern

### 📖 In-Depth Explanation

The Saga pattern manages distributed transactions by breaking them into a sequence of local transactions with compensating actions for rollback.

```typescript
// Saga Orchestrator Pattern
interface SagaStep {
  id: string;
  action: () => Promise<any>;
  compensation?: () => Promise<any>;
  retryPolicy: RetryPolicy;
}

interface RetryPolicy {
  maxAttempts: number;
  backoffFactor: number;
  initialDelay: number;
}

class SagaOrchestrator {
  private steps: SagaStep[] = [];
  private completedSteps: SagaStep[] = [];
  private executionLog: SagaLogEntry[] = [];

  constructor(private sagaId: string) {}

  addStep(step: SagaStep): this {
    this.steps.push(step);
    return this;
  }

  async execute(): Promise<void> {
    this.log('SAGA_STARTED', { sagaId: this.sagaId });

    for (const step of this.steps) {
      try {
        await this.executeStep(step);
        this.completedSteps.push(step);
      } catch (error) {
        this.log('STEP_FAILED', { stepId: step.id, error: error.message });
        await this.compensate();
        throw new SagaExecutionError('Saga failed and compensated', error);
      }
    }

    this.log('SAGA_COMPLETED', { sagaId: this.sagaId });
  }

  private async executeStep(step: SagaStep): Promise<void> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= step.retryPolicy.maxAttempts; attempt++) {
      try {
        this.log('STEP_STARTED', { stepId: step.id, attempt });
        
        await step.action();
        
        this.log('STEP_COMPLETED', { stepId: step.id, attempt });
        return;
      } catch (error) {
        lastError = error;
        this.log('STEP_RETRY', { stepId: step.id, attempt, error: error.message });
        
        if (attempt < step.retryPolicy.maxAttempts) {
          const delay = step.retryPolicy.initialDelay * 
                       Math.pow(step.retryPolicy.backoffFactor, attempt - 1);
          await this.sleep(delay);
        }
      }
    }
    
    throw lastError!;
  }

  private async compensate(): Promise<void> {
    this.log('COMPENSATION_STARTED', { 
      sagaId: this.sagaId, 
      stepsToCompensate: this.completedSteps.length 
    });

    // Compensate in reverse order
    for (const step of [...this.completedSteps].reverse()) {
      if (step.compensation) {
        try {
          await step.compensation();
          this.log('COMPENSATION_COMPLETED', { stepId: step.id });
        } catch (error) {
          this.log('COMPENSATION_FAILED', { 
            stepId: step.id, 
            error: error.message 
          });
          // Continue compensating other steps even if one fails
        }
      }
    }

    this.log('COMPENSATION_FINISHED', { sagaId: this.sagaId });
  }

  // Saga for Order Processing
  static createOrderSaga(orderId: string): SagaOrchestrator {
    const saga = new SagaOrchestrator(`order-${orderId}`);

    return saga
      .addStep({
        id: 'validate-order',
        action: async () => {
          await orderService.validateOrder(orderId);
        },
        compensation: async () => {
          await orderService.markAsInvalid(orderId);
        },
        retryPolicy: { maxAttempts: 3, backoffFactor: 2, initialDelay: 100 }
      })
      .addStep({
        id: 'reserve-inventory',
        action: async () => {
          await inventoryService.reserveItems(orderId);
        },
        compensation: async () => {
          await inventoryService.releaseItems(orderId);
        },
        retryPolicy: { maxAttempts: 3, backoffFactor: 2, initialDelay: 100 }
      })
      .addStep({
        id: 'process-payment',
        action: async () => {
          await paymentService.processPayment(orderId);
        },
        compensation: async () => {
          await paymentService.refundPayment(orderId);
        },
        retryPolicy: { maxAttempts: 5, backoffFactor: 2, initialDelay: 200 }
      })
      .addStep({
        id: 'create-shipment',
        action: async () => {
          await shippingService.createShipment(orderId);
        },
        compensation: async () => {
          await shippingService.cancelShipment(orderId);
        },
        retryPolicy: { maxAttempts: 3, backoffFactor: 2, initialDelay: 100 }
      });
  }
}

// Choreography-based Saga
class OrderSagaChoreography {
  async handleOrderCreated(event: OrderCreatedEvent) {
    // Publish events and let services react
    await eventBus.publish({
      type: 'ORDER_VALIDATION_REQUESTED',
      payload: { orderId: event.orderId }
    });
  }
}

// Service reacting to saga events
class InventoryService {
  constructor(private eventBus: EventBus) {
    this.eventBus.subscribe('ORDER_VALIDATED', this.reserveInventory.bind(this));
    this.eventBus.subscribe('PAYMENT_FAILED', this.releaseInventory.bind(this));
  }

  async reserveInventory(event: OrderValidatedEvent) {
    try {
      await this.reserveItems(event.orderId);
      
      await eventBus.publish({
        type: 'INVENTORY_RESERVED',
        payload: { orderId: event.orderId }
      });
    } catch (error) {
      await eventBus.publish({
        type: 'INVENTORY_RESERVATION_FAILED',
        payload: { orderId: event.orderId, error: error.message }
      });
    }
  }
}
```

### 🎯 Real-World Scenario: Travel Booking System
*You're building a travel booking system that needs to coordinate flights, hotels, and car rentals. If any component fails, all bookings need to be rolled back.*

**Interview Questions:**
1. Would you use orchestration or choreography for travel booking sagas? Why?
2. How would you handle long-running sagas (bookings that take minutes/hours)?
3. What strategies would you use for saga persistence and recovery?
4. How do you handle compensating actions that fail?
5. What idempotency guarantees do you need for saga steps?

**Technical Questions:**
1. How do you implement idempotent saga steps?
2. What's the difference between backward recovery and forward recovery?
3. How do you handle concurrent saga executions for the same resource?
4. What database patterns support saga implementation?

---

## 11. CQRS (Optional)

### 📖 In-Depth Explanation

CQRS (Command Query Responsibility Segregation) separates read and write operations into different models, optimizing for specific use cases.

```typescript
// CQRS Implementation with Event Sourcing
interface Command {
  type: string;
  payload: any;
  metadata: {
    userId: string;
    timestamp: Date;
    correlationId: string;
  };
}

interface Query {
  type: string;
  filters: Record<string, any>;
  options: {
    limit: number;
    offset: number;
    sort: Record<string, 1 | -1>;
  };
}

// Command Side (Write Model)
class CommandHandler {
  constructor(
    private eventStore: EventStore,
    private commandBus: CommandBus
  ) {}

  async handleCreateOrder(command: CreateOrderCommand): Promise<void> {
    // Validate command
    await this.validateCommand(command);
    
    // Load aggregate
    const order = OrderAggregate.create(command.payload);
    
    // Apply business rules
    if (!order.isValid()) {
      throw new ValidationError('Order validation failed');
    }
    
    // Store events
    await this.eventStore.saveEvents(
      order.id,
      order.getUncommittedEvents(),
      order.version
    );
    
    // Publish events for read model updates
    await this.commandBus.publishEvents(order.getUncommittedEvents());
    
    order.markEventsAsCommitted();
  }

  async handleCancelOrder(command: CancelOrderCommand): Promise<void> {
    const events = await this.eventStore.getEvents(command.payload.orderId);
    const order = OrderAggregate.fromEvents(events);
    
    order.cancel(command.payload.reason);
    
    await this.eventStore.saveEvents(
      order.id,
      order.getUncommittedEvents(),
      order.version
    );
    
    await this.commandBus.publishEvents(order.getUncommittedEvents());
  }
}

// Query Side (Read Model)
class QueryHandler {
  constructor(private readDatabase: ReadDatabase) {}

  async handleGetOrders(query: GetOrdersQuery): Promise<OrderView[]> {
    const { filters, options } = query;
    
    // Optimized query for read operations
    return this.readDatabase.orders
      .find(filters)
      .sort(options.sort)
      .skip(options.offset)
      .limit(options.limit)
      .toArray();
  }

  async handleGetOrderStats(query: GetOrderStatsQuery): Promise<OrderStats> {
    // Materialized view for statistics
    return this.readDatabase.orderStats.findOne({
      date: query.date,
      region: query.region
    });
  }
}

// Read Model Projection
class OrderProjection {
  constructor(private readDatabase: ReadDatabase) {}

  async onOrderCreated(event: OrderCreatedEvent): Promise<void> {
    const orderView: OrderView = {
      id: event.aggregateId,
      userId: event.payload.userId,
      items: event.payload.items,
      total: event.payload.items.reduce((sum, item) => sum + item.price * item.quantity, 0),
      status: 'created',
      createdAt: event.timestamp,
      updatedAt: event.timestamp
    };
    
    await this.readDatabase.orders.insertOne(orderView);
    
    // Update materialized view for statistics
    await this.updateOrderStats(event);
  }

  async onOrderPaid(event: OrderPaidEvent): Promise<void> {
    await this.readDatabase.orders.updateOne(
      { id: event.aggregateId },
      { 
        $set: { 
          status: 'paid',
          paidAt: event.timestamp,
          updatedAt: event.timestamp
        }
      }
    );
  }

  private async updateOrderStats(event: OrderCreatedEvent): Promise<void> {
    const date = new Date(event.timestamp).toISOString().split('T')[0];
    
    await this.readDatabase.orderStats.updateOne(
      { date },
      {
        $inc: {
          totalOrders: 1,
          totalRevenue: event.payload.total,
          [`items.${event.payload.items[0].category}`]: event.payload.items.length
        }
      },
      { upsert: true }
    );
  }
}

// Synchronization between Write and Read Models
class ReadModelSync {
  constructor(
    private eventStore: EventStore,
    private projections: Projection[]
  ) {}

  async startSync(): Promise<void> {
    let lastProcessedEvent = await this.getLastProcessedEvent();
    
    while (true) {
      const events = await this.eventStore.getEventsAfter(lastProcessedEvent);
      
      for (const event of events) {
        // Process event through all projections
        await Promise.all(
          this.projections.map(projection => projection.handle(event))
        );
        
        lastProcessedEvent = event.id;
        await this.saveLastProcessedEvent(lastProcessedEvent);
      }
      
      await this.sleep(1000); // Polling interval
    }
  }
}
```

### 🎯 Real-World Scenario: Analytics Dashboard
*You need to build a real-time analytics dashboard showing order metrics. The write-optimized order service can't handle the complex queries needed for analytics.*

**Interview Questions:**
1. When would you choose CQRS for a system?
2. How would you handle eventual consistency between write and read models?
3. What strategies would you use for read model rebuilding?
4. How do you handle schema changes in read models?
5. What are the trade-offs of CQRS?

**Technical Questions:**
1. How do you ensure idempotency in projections?
2. What patterns exist for read-write synchronization?
3. How do you handle projection failures?
4. What are materialized views and when are they useful?

---

## 12. Applying TypeScript

### 📖 In-Depth Explanation

TypeScript enhances microservices development with type safety, interfaces, and advanced type features.

```typescript
// Domain-Driven Design with TypeScript
namespace OrderDomain {
  // Value Objects
  export class Money {
    constructor(
      public readonly amount: number,
      public readonly currency: string
    ) {
      if (amount < 0) throw new Error('Amount cannot be negative');
      if (!this.isValidCurrency(currency)) {
        throw new Error(`Invalid currency: ${currency}`);
      }
    }
    
    add(other: Money): Money {
      if (this.currency !== other.currency) {
        throw new Error('Cannot add different currencies');
      }
      return new Money(this.amount + other.amount, this.currency);
    }
  }
  
  // Entity with TypeScript decorators
  export class Order {
    public readonly id: OrderId;
    private items: OrderItem[] = [];
    private status: OrderStatus = OrderStatus.CREATED;
    
    constructor(id: OrderId, public readonly customerId: CustomerId) {
      this.id = id;
    }
    
    @validate
    addItem(productId: ProductId, quantity: number, price: Money): void {
      if (this.status !== OrderStatus.CREATED) {
        throw new Error('Cannot add items to a processed order');
      }
      
      const item = new OrderItem(productId, quantity, price);
      this.items.push(item);
    }
    
    @transaction
    async process(): Promise<void> {
      this.status = OrderStatus.PROCESSING;
      
      // Business logic with type safety
      await this.validateItems();
      await this.calculateTotals();
      
      this.status = OrderStatus.PROCESSED;
    }
    
    get total(): Money {
      return this.items.reduce(
        (total, item) => total.add(item.price),
        new Money(0, 'USD')
      );
    }
  }
  
  // Repository Pattern with Generics
  export interface Repository<T extends Entity> {
    findById(id: string): Promise<T | null>;
    save(entity: T): Promise<void>;
    delete(id: string): Promise<void>;
  }
  
  export class OrderRepository implements Repository<Order> {
    constructor(private db: Database) {}
    
    async findById(id: OrderId): Promise<Order | null> {
      const data = await this.db.orders.findOne({ id });
      return data ? this.toDomain(data) : null;
    }
    
    async save(order: Order): Promise<void> {
      const data = this.toPersistence(order);
      await this.db.orders.updateOne(
        { id: order.id },
        { $set: data },
        { upsert: true }
      );
    }
    
    private toDomain(data: any): Order {
      const order = new Order(data.id, data.customerId);
      // Hydrate from persistence
      return order;
    }
  }
  
  // Service with Dependency Injection
  export interface IOrderService {
    createOrder(command: CreateOrderCommand): Promise<OrderId>;
    cancelOrder(command: CancelOrderCommand): Promise<void>;
  }
  
  @injectable()
  export class OrderService implements IOrderService {
    constructor(
      @inject('OrderRepository') private repository: OrderRepository,
      @inject('EventBus') private eventBus: EventBus,
      @inject('Logger') private logger: Logger
    ) {}
    
    @logExecution
    async createOrder(command: CreateOrderCommand): Promise<OrderId> {
      const order = new Order(OrderId.generate(), command.customerId);
      
      command.items.forEach(item => {
        order.addItem(item.productId, item.quantity, item.price);
      });
      
      await order.process();
      await this.repository.save(order);
      
      // Publish domain events
      await this.eventBus.publish(new OrderCreatedEvent(order));
      
      this.logger.info('Order created', { orderId: order.id });
      return order.id;
    }
  }
}

// Configuration with Type Safety
interface ServiceConfig {
  port: number;
  database: {
    url: string;
    poolSize: number;
    timeout: number;
  };
  redis: {
    host: string;
    port: number;
    ttl: number;
  };
  featureFlags: {
    enableCache: boolean;
    enableMetrics: boolean;
  };
}

class ConfigService {
  private config: ServiceConfig;
  
  constructor() {
    this.config = this.validateConfig(process.env);
  }
  
  private validateConfig(env: NodeJS.ProcessEnv): ServiceConfig {
    const config = {
      port: parseInt(env.PORT || '3000'),
      database: {
        url: env.DATABASE_URL || 'mongodb://localhost:27017',
        poolSize: parseInt(env.DB_POOL_SIZE || '10'),
        timeout: parseInt(env.DB_TIMEOUT || '5000')
      },
      redis: {
        host: env.REDIS_HOST || 'localhost',
        port: parseInt(env.REDIS_PORT || '6379'),
        ttl: parseInt(env.REDIS_TTL || '3600')
      },
      featureFlags: {
        enableCache: env.ENABLE_CACHE === 'true',
        enableMetrics: env.ENABLE_METRICS === 'true'
      }
    };
    
    // Runtime validation
    if (config.port < 1 || config.port > 65535) {
      throw new Error('Invalid port number');
    }
    
    return config;
  }
  
  get<T extends keyof ServiceConfig>(key: T): ServiceConfig[T] {
    return this.config[key];
  }
}
```

### 🎯 Real-World Scenario: Large Team Collaboration
*Your team of 20 developers is building a complex microservices ecosystem. You need to ensure type safety across service boundaries and maintain API contracts.*

**Interview Questions:**
1. How would you enforce type safety across microservice boundaries?
2. What strategies would you use for shared type definitions between services?
3. How do you handle API versioning with TypeScript?
4. What tools would you use for type checking in a CI/CD pipeline?
5. How do you balance TypeScript strictness with development velocity?

**Technical Questions:**
1. How do you generate TypeScript types from OpenAPI/Swagger specifications?
2. What are type guards and how are they useful in microservices?
3. How do you implement runtime type validation (zod, io-ts)?
4. What are branded types and when should you use them?

---

## 13. Using Nx or Turborepo

### 📖 In-Depth Explanation

Monorepo tools like Nx and Turborepo help manage multiple microservices in a single repository with shared tooling and dependencies.

```typescript
// Nx Workspace Configuration
// nx.json
{
  "npmScope": "myorg",
  "affected": {
    "defaultBase": "main"
  },
  "tasksRunnerOptions": {
    "default": {
      "runner": "@nrwl/nx-cloud",
      "options": {
        "cacheableOperations": ["build", "test", "lint"],
        "accessToken": "..."
      }
    }
  },
  "targetDefaults": {
    "build": {
      "dependsOn": ["^build"],
      "inputs": ["production", "^production"]
    },
    "test": {
      "inputs": ["default", "^production"]
    },
    "lint": {
      "inputs": ["default", "{workspaceRoot}/.eslintrc.json"]
    }
  }
}

// Workspace Structure with Nx
myorg/
├── apps/
│   ├── api-gateway/
│   │   ├── src/
│   │   ├── project.json
│   │   └── Dockerfile
│   ├── user-service/
│   ├── order-service/
│   └── payment-service/
├── libs/
│   ├── shared/
│   │   ├── types/          # Shared TypeScript types
│   │   ├── utils/          # Shared utilities
│   │   └── config/         # Shared configuration
│   ├── events/
│   │   ├── src/            # Event schemas and types
│   │   └── project.json
│   └── auth/
│       └── src/            # Authentication library
├── tools/
│   ├── scripts/
│   └── generators/         # Custom code generators
├── docker-compose.yml
├── package.json
└── nx.json

// Turborepo Configuration
// turbo.json
{
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**", ".next/**"]
    },
    "test": {
      "dependsOn": ["build"],
      "inputs": ["src/**/*.ts", "test/**/*.ts"]
    },
    "lint": {
      "outputs": []
    },
    "deploy": {
      "dependsOn": ["build", "test", "lint"],
      "outputs": []
    }
  },
  "remoteCache": {
    "signature": true
  }
}

// Shared Configuration with TypeScript Paths
// tsconfig.base.json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@myorg/shared": ["libs/shared/src/index.ts"],
      "@myorg/events": ["libs/events/src/index.ts"],
      "@myorg/auth": ["libs/auth/src/index.ts"]
    }
  }
}

// Shared Library Example
// libs/shared/src/types/order.ts
export interface Order {
  id: string;
  userId: string;
  items: OrderItem[];
  total: number;
  status: OrderStatus;
}

export type OrderStatus = 
  | 'created' 
  | 'paid' 
  | 'shipped' 
  | 'delivered' 
  | 'cancelled';

// Service using shared types
// apps/order-service/src/order.controller.ts
import { Order, OrderStatus } from '@myorg/shared';

export class OrderController {
  async getOrder(id: string): Promise<Order> {
    // Type safety across services
    return this.repository.findById(id);
  }
}

// Custom Generators for Consistency
// tools/generators/service/index.ts
export default function(tree: Tree, schema: ServiceSchema) {
  const projectRoot = `apps/${schema.name}`;
  
  // Generate standardized service structure
  generateFiles(tree, path.join(__dirname, 'files'), projectRoot, {
    ...schema,
    tmpl: ''
  });
  
  // Update workspace configuration
  addProjectConfiguration(
    tree,
    schema.name,
    {
      root: projectRoot,
      projectType: 'application',
      sourceRoot: `${projectRoot}/src`,
      targets: {
        build: {
          executor: '@nrwl/node:webpack',
          options: {
            outputPath: `dist/apps/${schema.name}`
          }
        },
        serve: {
          executor: '@nrwl/node:node',
          options: {
            buildTarget: `${schema.name}:build`
          }
        },
        test: {
          executor: '@nrwl/jest:jest',
          options: {
            jestConfig: `${projectRoot}/jest.config.js`
          }
        }
      }
    }
  );
}

// Docker Compose for Local Development
// docker-compose.yml
version: '3.8'
services:
  api-gateway:
    build:
      context: .
      dockerfile: apps/api-gateway/Dockerfile
    depends_on:
      - user-service
      - order-service
    environment:
      - NODE_ENV=development
    ports:
      - "3000:3000"
    networks:
      - microservices

  user-service:
    build:
      context: .
      dockerfile: apps/user-service/Dockerfile
      target: development
    volumes:
      - ./apps/user-service:/app
      - /app/node_modules
    environment:
      - DATABASE_URL=mongodb://mongodb:27017/users
    depends_on:
      - mongodb
    networks:
      - microservices

  order-service:
    build:
      context: .
      dockerfile: apps/order-service/Dockerfile
    networks:
      - microservices

  # Infrastructure
  mongodb:
    image: mongo:6
    networks:
      - microservices

  redis:
    image: redis:alpine
    networks:
      - microservices

  kafka:
    image: confluentinc/cp-kafka:latest
    networks:
      - microservices

networks:
  microservices:
    driver: bridge
```

### 🎯 Real-World Scenario: Enterprise Microservices Platform
*You're building a platform with 50+ microservices for a large enterprise. Teams need independence while sharing common libraries and tooling.*

**Interview Questions:**
1. When would you choose a monorepo over multiple repositories?
2. How would you manage dependencies across 50+ microservices?
3. What strategies would you use for independent deployments from a monorepo?
4. How do you handle service-specific configuration in a shared structure?
5. What CI/CD pipeline design works best with monorepos?

**Technical Questions:**
1. How does Nx/Turborepo caching work and how do you optimize it?
2. What are affected projects and how do they speed up builds?
3. How do you handle versioning of shared libraries?
4. What are the challenges of Docker builds in a monorepo?

---

## 📊 Summary & Best Practices

### Key Takeaways

1. **Start Simple**: Begin with a modular monolith before jumping to microservices
2. **Domain-Driven Design**: Align services with business domains
3. **Observability First**: Implement logging, metrics, and tracing from day one
4. **Automate Everything**: CI/CD, testing, and deployment automation
5. **Design for Failure**: Assume everything will fail and plan accordingly

### Technology Recommendations

| Use Case | Recommended Technology |
|----------|----------------------|
| **API Gateway** | Kong, Express Gateway, AWS API Gateway |
| **Service Mesh** | Istio, Linkerd, Consul Connect |
| **Message Broker** | Kafka (event streaming), RabbitMQ (task queues) |
| **Service Discovery** | Consul, Eureka, Kubernetes DNS |
| **Distributed Tracing** | Jaeger, Zipkin, AWS X-Ray |
| **Monitoring** | Prometheus, Grafana, Datadog |
| **Container Orchestration** | Kubernetes, AWS ECS, Docker Swarm |
| **Database per Service** | PostgreSQL, MongoDB, DynamoDB |

### Common Pitfalls to Avoid

1. **Distributed Monolith**: Services too tightly coupled
2. **Network Overhead**: Too many interservice calls
3. **Data Consistency**: Ignoring eventual consistency requirements
4. **Operational Complexity**: Underestimating monitoring needs
5. **Team Structure**: Conway's Law - wrong team boundaries

## 🚀 Getting Started

### Quick Start Template

```bash
# Clone template
git clone https://github.com/your-org/microservices-template
cd microservices-template

# Install dependencies
npm install

# Start development environment
docker-compose up -d
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

### Next Steps

1. Define your bounded contexts
2. Design service APIs and contracts
3. Set up CI/CD pipeline
4. Implement monitoring and alerting
5. Plan for scaling and disaster recovery

## 📚 Additional Resources

- [Microservices Patterns](https://microservices.io/patterns/)
- [Domain-Driven Design](https://dddcommunity.org/)
- [The Twelve-Factor App](https://12factor.net/)
- [Google SRE Book](https://sre.google/sre-book/table-of-contents/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)

---
