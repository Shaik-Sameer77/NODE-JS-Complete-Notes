# MongoDB with Mongoose: Complete Guide

## Table of Contents
- [Introduction to MongoDB & Mongoose](#introduction-to-mongodb--mongoose)
- [Schemas](#schemas)
  - [Schema Types](#schema-types)
  - [Schema Options](#schema-options)
  - [Virtual Properties](#virtual-properties)
- [Models](#models)
  - [Model Methods](#model-methods)
  - [Static vs Instance Methods](#static-vs-instance-methods)
- [Validators](#validators)
  - [Built-in Validators](#built-in-validators)
  - [Custom Validators](#custom-validators)
  - [Async Validators](#async-validators)
- [Indexing](#indexing)
  - [Index Types](#index-types)
  - [Index Properties](#index-properties)
  - [Index Performance](#index-performance)
- [Aggregation](#aggregation)
  - [Aggregation Pipeline](#aggregation-pipeline)
  - [Pipeline Stages](#pipeline-stages)
  - [Aggregation Optimization](#aggregation-optimization)
- [Transactions](#transactions)
  - [ACID Transactions](#acid-transactions)
  - [Session Management](#session-management)
- [Populating Relations](#populating-relations)
  - [Reference Population](#reference-population)
  - [Virtual Population](#virtual-population)
  - [Dynamic Population](#dynamic-population)
- [Optimizing Queries](#optimizing-queries)
  - [Query Optimization Techniques](#query-optimization-techniques)
  - [Performance Monitoring](#performance-monitoring)
- [Interview Questions](#interview-questions)
  - [Junior to Mid-Level](#junior-to-mid-level)
  - [Senior Level](#senior-level)
  - [Real-World Scenarios](#real-world-scenarios)

---

## Introduction to MongoDB & Mongoose

MongoDB is a NoSQL document database that provides high performance, high availability, and easy scalability. Mongoose is an ODM (Object Data Modeling) library for MongoDB and Node.js that provides a straight-forward, schema-based solution to model application data.

**Key Benefits:**
- Schema validation and casting
- Business logic hooks (middleware)
- Query building helpers
- Population for referencing other documents

```javascript
const mongoose = require('mongoose');

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/mydatabase', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10, // Connection pool size
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
});

// Connection events
mongoose.connection.on('connected', () => {
  console.log('Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Mongoose disconnected');
});
```

---

## Schemas

A schema defines the structure of documents within a MongoDB collection. It specifies field types, default values, validators, and other metadata.

### Schema Types

```javascript
const { Schema } = require('mongoose');

const userSchema = new Schema({
  // String type with validation
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
  },
  
  // Number type with range validation
  age: {
    type: Number,
    min: [13, 'You must be at least 13 years old'],
    max: [120, 'Age must be reasonable'],
    default: 18
  },
  
  // Date type with default
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true // Cannot be modified after creation
  },
  
  // Array of strings
  tags: [{
    type: String,
    lowercase: true,
    trim: true
  }],
  
  // Embedded document (subdocument)
  address: {
    street: String,
    city: String,
    country: {
      type: String,
      default: 'USA'
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      index: '2dsphere' // Geospatial index
    }
  },
  
  // Mixed type (any data)
  metadata: Schema.Types.Mixed,
  
  // ObjectId reference to another collection
  department: {
    type: Schema.Types.ObjectId,
    ref: 'Department'
  },
  
  // Map type (key-value pairs)
  preferences: {
    type: Map,
    of: String,
    default: new Map([['theme', 'light'], ['language', 'en']])
  },
  
  // Enum type
  status: {
    type: String,
    enum: {
      values: ['active', 'inactive', 'suspended', 'deleted'],
      message: '{VALUE} is not a valid status'
    },
    default: 'active'
  },
  
  // Boolean with custom getter/setter
  isVerified: {
    type: Boolean,
    default: false,
    set: v => v === true || v === 'true' || v === 1
  }
});
```

### Schema Options

```javascript
const productSchema = new Schema({
  name: String,
  price: Number,
  category: String
}, {
  // Schema options
  timestamps: true, // Adds createdAt and updatedAt automatically
  versionKey: '_v', // Custom version key name
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      ret.id = ret._id.toString();
      delete ret._id;
      delete ret.__v;
      return ret;
    }
  },
  toObject: { virtuals: true },
  
  // Collection options
  collection: 'store_products', // Custom collection name
  strict: true, // Only save fields defined in schema
  strictQuery: false, // Allow querying fields not in schema
  
  // Index options
  autoIndex: true, // Auto-create indexes
  minimize: true, // Remove empty objects
  
  // Shard key (for sharded collections)
  shardKey: { category: 1 }
});

// Compound index
productSchema.index({ category: 1, price: -1 });

// Text index for search
productSchema.index({ name: 'text', description: 'text' });
```

### Virtual Properties

Virtuals are document properties that you can get and set but that do not get persisted to MongoDB.

```javascript
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
}).set(function(v) {
  const [firstName, lastName] = v.split(' ');
  this.firstName = firstName;
  this.lastName = lastName;
});

// Virtual for age calculation
userSchema.virtual('age').get(function() {
  if (!this.birthDate) return null;
  const diff = Date.now() - this.birthDate.getTime();
  return Math.floor(diff / (1000 * 60 * 60 * 24 * 365.25));
});

// Virtual with options
userSchema.virtual('posts', {
  ref: 'Post', // The model to use
  localField: '_id', // Find posts where `localField`
  foreignField: 'author', // is equal to `foreignField`
  justOne: false // Set to true for one-to-one relationship
});

// Using virtual in queries
const user = await User.findById(userId).populate('posts');
```

---

## Models

Models are fancy constructors compiled from Schema definitions. An instance of a model is called a document. Models are responsible for creating and reading documents from the underlying MongoDB database.

### Creating Models

```javascript
const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);

// Alternative: Create model from existing connection
const conn = mongoose.createConnection('mongodb://localhost:27017/test');
const Admin = conn.model('Admin', adminSchema);
```

### CRUD Operations

```javascript
// Create
const user = new User({
  username: 'john_doe',
  email: 'john@example.com',
  age: 25
});
await user.save();

// Alternative: create directly
const user = await User.create({
  username: 'jane_doe',
  email: 'jane@example.com'
});

// Create multiple
const users = await User.insertMany([
  { username: 'alice', email: 'alice@example.com' },
  { username: 'bob', email: 'bob@example.com' }
]);

// Read
const user = await User.findById(userId);
const user = await User.findOne({ email: 'john@example.com' });
const users = await User.find({ status: 'active' });
const count = await User.countDocuments({ age: { $gt: 18 } });

// Update
const user = await User.findByIdAndUpdate(
  userId,
  { $set: { status: 'active' } },
  { new: true, runValidators: true }
);

// Update multiple
const result = await User.updateMany(
  { status: 'inactive' },
  { $set: { lastLogin: new Date() } }
);

// Delete
await User.findByIdAndDelete(userId);
await User.deleteMany({ status: 'deleted' });
```

### Model Methods

#### Instance Methods

```javascript
userSchema.methods = {
  // Instance method
  getProfile() {
    return {
      username: this.username,
      email: this.email,
      age: this.age,
      fullName: this.fullName
    };
  },
  
  // Method to check password (example with bcrypt)
  async comparePassword(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
  },
  
  // Method to generate auth token
  generateAuthToken() {
    return jwt.sign(
      { userId: this._id, email: this.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
  },
  
  // Method to deactivate account
  async deactivate(reason) {
    this.status = 'inactive';
    this.deactivationReason = reason;
    this.deactivatedAt = new Date();
    return await this.save();
  }
};

// Using instance method
const user = await User.findById(userId);
const profile = user.getProfile();
const isValid = await user.comparePassword(password);
const token = user.generateAuthToken();
```

#### Static Methods

```javascript
userSchema.statics = {
  // Find user by credentials
  async findByCredentials(email, password) {
    const user = await this.findOne({ email });
    if (!user) {
      throw new Error('Invalid login credentials');
    }
    
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      throw new Error('Invalid login credentials');
    }
    
    return user;
  },
  
  // Find inactive users older than X days
  async findInactiveUsers(days = 30) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    return this.find({
      status: 'inactive',
      lastLogin: { $lt: cutoffDate }
    });
  },
  
  // Bulk update with validation
  async bulkUpdateStatus(userIds, status) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const users = await this.find({ _id: { $in: userIds } }).session(session);
      
      for (const user of users) {
        user.status = status;
        user.updatedAt = new Date();
        await user.save({ session });
      }
      
      await session.commitTransaction();
      return users;
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }
};

// Using static method
const user = await User.findByCredentials(email, password);
const inactiveUsers = await User.findInactiveUsers(60);
```

---

## Validators

Validators are rules that determine whether a field's value is acceptable.

### Built-in Validators

```javascript
const productSchema = new Schema({
  name: {
    type: String,
    required: [true, 'Product name is required'],
    trim: true
  },
  
  sku: {
    type: String,
    unique: true,
    validate: {
      validator: function(v) {
        return /^[A-Z]{3}-[0-9]{6}$/.test(v);
      },
      message: props => `${props.value} is not a valid SKU format!`
    }
  },
  
  price: {
    type: Number,
    required: true,
    min: [0, 'Price cannot be negative'],
    max: [10000, 'Price cannot exceed $10,000'],
    // Custom setter to round to 2 decimal places
    set: v => Math.round(v * 100) / 100
  },
  
  quantity: {
    type: Number,
    required: true,
    integer: true, // Mongoose 5.x+ feature
    min: 0
  },
  
  categories: {
    type: [String],
    validate: {
      validator: function(v) {
        return v.length <= 5;
      },
      message: 'A product can have at most 5 categories'
    }
  },
  
  releaseDate: {
    type: Date,
    validate: {
      validator: function(v) {
        return v <= new Date();
      },
      message: 'Release date cannot be in the future'
    }
  },
  
  // Array of objects with validation
  reviews: [{
    user: { type: Schema.Types.ObjectId, ref: 'User' },
    rating: {
      type: Number,
      required: true,
      min: 1,
      max: 5
    },
    comment: {
      type: String,
      maxlength: [500, 'Comment cannot exceed 500 characters']
    },
    createdAt: {
      type: Date,
      default: Date.now,
      immutable: true
    }
  }],
  
  // Conditional validation
  discountPrice: {
    type: Number,
    required: function() {
      return this.isOnSale; // Only required if isOnSale is true
    },
    validate: {
      validator: function(v) {
        return v < this.price;
      },
      message: 'Discount price must be less than regular price'
    }
  }
});
```

### Custom Validators

```javascript
const orderSchema = new Schema({
  items: [{
    productId: { type: Schema.Types.ObjectId, ref: 'Product' },
    quantity: Number,
    price: Number
  }],
  
  totalAmount: {
    type: Number,
    validate: {
      // Async validator
      validator: async function(v) {
        // Calculate sum of items
        const sum = this.items.reduce((total, item) => {
          return total + (item.price * item.quantity);
        }, 0);
        
        // Allow small rounding differences
        return Math.abs(v - sum) < 0.01;
      },
      message: 'Total amount does not match sum of items'
    }
  },
  
  shippingAddress: {
    type: String,
    validate: {
      validator: function(v) {
        // Check if address is in serviceable area
        const serviceableCities = ['New York', 'Los Angeles', 'Chicago'];
        return serviceableCities.some(city => v.includes(city));
      },
      message: 'We do not deliver to this address'
    }
  },
  
  // Cross-field validation
  paymentMethod: {
    type: String,
    enum: ['credit_card', 'paypal', 'bank_transfer']
  },
  
  creditCardLast4: {
    type: String,
    validate: {
      validator: function(v) {
        // Only validate if payment method is credit card
        if (this.paymentMethod !== 'credit_card') return true;
        return /^\d{4}$/.test(v);
      },
      message: 'Credit card last 4 digits must be 4 numbers'
    }
  }
});

// Schema-level validation
orderSchema.path('items').validate(function(items) {
  return items.length > 0;
}, 'Order must have at least one item');

// Async schema-level validation
orderSchema.path('totalAmount').validate(async function(value) {
  if (value > 10000) {
    const user = await User.findById(this.userId);
    return user.isVIP; // Only VIP users can place large orders
  }
  return true;
}, 'Order amount exceeds limit for regular users');
```

### Validation Error Handling

```javascript
try {
  const product = new Product({
    name: 'Laptop',
    price: -100, // Invalid: negative price
    quantity: 'not-a-number' // Invalid: not a number
  });
  
  await product.save();
} catch (error) {
  if (error.name === 'ValidationError') {
    const errors = {};
    
    // Extract validation errors
    Object.keys(error.errors).forEach(key => {
      errors[key] = error.errors[key].message;
    });
    
    console.log('Validation errors:', errors);
    
    // Get specific error for a field
    if (error.errors['price']) {
      console.log('Price error:', error.errors['price'].message);
    }
  }
}

// Manual validation
const product = new Product({ name: 'Test', price: -10 });
const validationError = product.validateSync();

if (validationError) {
  const errors = {};
  Object.keys(validationError.errors).forEach(key => {
    errors[key] = validationError.errors[key].message;
  });
  console.log('Sync validation errors:', errors);
}
```

---

## Indexing

Indexes support the efficient execution of queries in MongoDB.

### Single Field Indexes

```javascript
const userSchema = new Schema({
  email: { type: String, unique: true, index: true },
  username: { type: String, unique: true },
  age: Number,
  createdAt: Date,
  location: {
    type: { type: String, default: 'Point' },
    coordinates: [Number]
  }
});

// Create index on single field
userSchema.index({ email: 1 }); // Ascending
userSchema.index({ createdAt: -1 }); // Descending

// Unique index
userSchema.index({ username: 1 }, { unique: true });

// Sparse index (only index documents that have the field)
userSchema.index({ phoneNumber: 1 }, { sparse: true });

// Partial index (only index documents that match filter)
userSchema.index(
  { email: 1 },
  { 
    partialFilterExpression: { 
      email: { $exists: true, $type: 'string' }
    }
  }
);
```

### Compound Indexes

```javascript
// Compound index on multiple fields
userSchema.index({ status: 1, createdAt: -1 });

// Compound index with different sort orders
orderSchema.index({ userId: 1, orderDate: -1, totalAmount: -1 });

// Compound unique index
const bookingSchema = new Schema({
  roomId: { type: Schema.Types.ObjectId, ref: 'Room' },
  date: Date,
  userId: { type: Schema.Types.ObjectId, ref: 'User' }
});

// Ensure a room can only be booked once per date
bookingSchema.index({ roomId: 1, date: 1 }, { unique: true });

// Covering index (includes all fields needed by a query)
userSchema.index(
  { status: 1, age: 1 },
  { include: ['email', 'username'] }
);
```

### Specialized Indexes

```javascript
// Text index for full-text search
const articleSchema = new Schema({
  title: String,
  content: String,
  author: String,
  tags: [String]
});

// Create text index on multiple fields
articleSchema.index(
  { title: 'text', content: 'text', tags: 'text' },
  {
    weights: {
      title: 10,
      tags: 5,
      content: 1
    },
    name: 'ArticleTextIndex'
  }
);

// Geospatial index for location-based queries
const placeSchema = new Schema({
  name: String,
  location: {
    type: {
      type: String,
      enum: ['Point'],
      required: true
    },
    coordinates: {
      type: [Number],
      required: true
    }
  },
  category: String
});

// 2dsphere index for geospatial queries
placeSchema.index({ location: '2dsphere' });

// TTL (Time-To-Live) index for automatic expiration
const sessionSchema = new Schema({
  userId: Schema.Types.ObjectId,
  token: String,
  createdAt: { type: Date, default: Date.now }
});

// Automatically delete documents after 24 hours
sessionSchema.index({ createdAt: 1 }, { expireAfterSeconds: 24 * 60 * 60 });

// Hashed index for hash-based sharding
userSchema.index({ email: 'hashed' });
```

### Index Management

```javascript
// Get all indexes
const indexes = await User.collection.getIndexes();
console.log('Indexes:', indexes);

// Create index programmatically
await User.collection.createIndex(
  { email: 1 },
  { 
    unique: true,
    partialFilterExpression: { email: { $exists: true } }
  }
);

// Drop an index
await User.collection.dropIndex('email_1');

// Check index usage with explain()
const explainResult = await User.find({ email: 'test@example.com' })
  .explain('executionStats');

console.log('Query plan:', explainResult.executionStats);
console.log('Index used:', explainResult.queryPlanner.winningPlan);

// Rebuild indexes
await User.collection.reIndex();

// Get index size
const stats = await User.collection.stats();
console.log('Index sizes:', stats.indexSizes);
```

### Index Performance Considerations

```javascript
// 1. Index selectivity
// More selective indexes (fields with many unique values) are more efficient
userSchema.index({ email: 1 }); // High selectivity
userSchema.index({ gender: 1 }); // Low selectivity (only M/F)

// 2. Index cardinality
// Consider creating separate indexes for queries with different selectivity

// 3. Index intersection
// MongoDB can use multiple indexes for a single query

// 4. Covered queries
// When all fields in query are part of an index
const users = await User.find(
  { status: 'active', age: { $gt: 18 } },
  { _id: 0, status: 1, age: 1 } // Only include indexed fields
).hint({ status: 1, age: 1 }); // Force index usage

// 5. Index maintenance
// Monitor index size and rebuild if necessary
const totalIndexSize = await User.collection.totalIndexSize();
console.log('Total index size:', totalIndexSize);

// 6. Index hints
// Force MongoDB to use a specific index
const users = await User.find({ status: 'active' })
  .hint({ status: 1, createdAt: -1 });

// 7. Index for sorting
// Ensure sort fields are indexed
userSchema.index({ createdAt: -1 }); // For sorting by newest first

// 8. Compound index field order
// Equality → Sort → Range
// Good: { status: 1, createdAt: -1 }
// Bad: { createdAt: -1, status: 1 }
```

---

## Aggregation

Aggregation operations process data records and return computed results.

### Aggregation Pipeline Basics

```javascript
const orderSchema = new Schema({
  orderId: String,
  userId: Schema.Types.ObjectId,
  items: [{
    productId: Schema.Types.ObjectId,
    name: String,
    quantity: Number,
    price: Number,
    category: String
  }],
  totalAmount: Number,
  status: String,
  orderDate: Date,
  shippingAddress: {
    city: String,
    state: String,
    country: String
  }
});

const Order = mongoose.model('Order', orderSchema);
```

### Common Pipeline Stages

```javascript
// Basic aggregation example
const salesReport = await Order.aggregate([
  // Stage 1: Filter documents
  {
    $match: {
      status: 'completed',
      orderDate: {
        $gte: new Date('2024-01-01'),
        $lte: new Date('2024-12-31')
      }
    }
  },
  
  // Stage 2: Unwind array to work with individual items
  {
    $unwind: '$items'
  },
  
  // Stage 3: Group by product category
  {
    $group: {
      _id: '$items.category',
      totalQuantity: { $sum: '$items.quantity' },
      totalRevenue: { 
        $sum: { $multiply: ['$items.quantity', '$items.price'] }
      },
      averagePrice: { $avg: '$items.price' },
      orderCount: { $sum: 1 },
      products: { $addToSet: '$items.productId' }
    }
  },
  
  // Stage 4: Lookup product details
  {
    $lookup: {
      from: 'products',
      localField: 'products',
      foreignField: '_id',
      as: 'productDetails'
    }
  },
  
  // Stage 5: Project final shape
  {
    $project: {
      category: '$_id',
      totalQuantity: 1,
      totalRevenue: 1,
      averagePrice: { $round: ['$averagePrice', 2] },
      orderCount: 1,
      productCount: { $size: '$products' },
      topProducts: {
        $slice: ['$productDetails', 5]
      },
      _id: 0
    }
  },
  
  // Stage 6: Sort by revenue
  {
    $sort: { totalRevenue: -1 }
  },
  
  // Stage 7: Add computed field
  {
    $addFields: {
      revenuePerOrder: {
        $divide: ['$totalRevenue', '$orderCount']
      }
    }
  }
]);

// Pagination in aggregation
const page = 1;
const limit = 10;
const skip = (page - 1) * limit;

const paginatedResults = await Order.aggregate([
  { $match: { status: 'completed' } },
  { $sort: { orderDate: -1 } },
  { $skip: skip },
  { $limit: limit },
  {
    $facet: {
      metadata: [
        { $count: 'total' },
        { $addFields: { page: page } }
      ],
      data: [
        // Keep pipeline for data
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'user'
          }
        },
        { $unwind: '$user' }
      ]
    }
  }
]);
```

### Advanced Aggregation Features

```javascript
// Conditional aggregation
const customerSegmentation = await Order.aggregate([
  {
    $group: {
      _id: '$userId',
      totalSpent: { $sum: '$totalAmount' },
      orderCount: { $sum: 1 },
      firstOrder: { $min: '$orderDate' },
      lastOrder: { $max: '$orderDate' }
    }
  },
  {
    $addFields: {
      customerType: {
        $switch: {
          branches: [
            {
              case: { $gte: ['$totalSpent', 1000] },
              then: 'VIP'
            },
            {
              case: { $gte: ['$totalSpent', 500] },
              then: 'Premium'
            },
            {
              case: { $gte: ['$totalSpent', 100] },
              then: 'Regular'
            }
          ],
          default: 'New'
        }
      },
      averageOrderValue: {
        $divide: ['$totalSpent', '$orderCount']
      }
    }
  }
]);

// Array operations in aggregation
const productAnalytics = await Order.aggregate([
  { $match: { status: 'completed' } },
  { $unwind: '$items' },
  {
    $group: {
      _id: '$items.productId',
      totalSold: { $sum: '$items.quantity' },
      revenue: { 
        $sum: { $multiply: ['$items.quantity', '$items.price'] }
      },
      orders: { $addToSet: '$_id' }
    }
  },
  {
    $project: {
      productId: '$_id',
      totalSold: 1,
      revenue: 1,
      orderCount: { $size: '$orders' },
      averageQuantityPerOrder: {
        $divide: ['$totalSold', { $size: '$orders' }]
      },
      _id: 0
    }
  }
]);

// Date aggregation (by month, quarter, etc.)
const monthlySales = await Order.aggregate([
  {
    $group: {
      _id: {
        year: { $year: '$orderDate' },
        month: { $month: '$orderDate' },
        quarter: { $ceil: { $divide: [{ $month: '$orderDate' }, 3] } }
      },
      totalRevenue: { $sum: '$totalAmount' },
      orderCount: { $sum: 1 },
      averageOrderValue: { $avg: '$totalAmount' }
    }
  },
  {
    $sort: { '_id.year': 1, '_id.month': 1 }
  }
]);

// Using $expr for complex conditions
const highValueOrders = await Order.aggregate([
  {
    $match: {
      $expr: {
        $and: [
          { $eq: ['$status', 'completed'] },
          { $gt: ['$totalAmount', 500] },
          {
            $gt: [
              { $size: '$items' },
              3
            ]
          }
        ]
      }
    }
  }
]);

// Text search in aggregation
const searchResults = await Order.aggregate([
  {
    $match: {
      $text: { $search: 'gift card premium' }
    }
  },
  {
    $sort: { score: { $meta: 'textScore' } }
  },
  {
    $project: {
      orderId: 1,
      totalAmount: 1,
      status: 1,
      score: { $meta: 'textScore' }
    }
  }
]);
```

### Aggregation with Facets

```javascript
const comprehensiveReport = await Order.aggregate([
  {
    $match: {
      orderDate: {
        $gte: new Date('2024-01-01'),
        $lte: new Date('2024-12-31')
      }
    }
  },
  {
    $facet: {
      // Summary statistics
      summary: [
        {
          $group: {
            _id: null,
            totalRevenue: { $sum: '$totalAmount' },
            totalOrders: { $sum: 1 },
            avgOrderValue: { $avg: '$totalAmount' },
            uniqueCustomers: { $addToSet: '$userId' }
          }
        },
        {
          $project: {
            _id: 0,
            totalRevenue: 1,
            totalOrders: 1,
            avgOrderValue: { $round: ['$avgOrderValue', 2] },
            uniqueCustomerCount: { $size: '$uniqueCustomers' }
          }
        }
      ],
      
      // Monthly breakdown
      monthlyTrends: [
        {
          $group: {
            _id: {
              year: { $year: '$orderDate' },
              month: { $month: '$orderDate' }
            },
            revenue: { $sum: '$totalAmount' },
            orders: { $sum: 1 }
          }
        },
        { $sort: { '_id.year': 1, '_id.month': 1 } }
      ],
      
      // Top customers
      topCustomers: [
        {
          $group: {
            _id: '$userId',
            totalSpent: { $sum: '$totalAmount' },
            orderCount: { $sum: 1 }
          }
        },
        { $sort: { totalSpent: -1 } },
        { $limit: 10 }
      ],
      
      // Status distribution
      statusDistribution: [
        {
          $group: {
            _id: '$status',
            count: { $sum: 1 },
            revenue: { $sum: '$totalAmount' }
          }
        }
      ],
      
      // Geographic distribution
      geographicDistribution: [
        {
          $group: {
            _id: '$shippingAddress.state',
            orderCount: { $sum: 1 },
            totalRevenue: { $sum: '$totalAmount' }
          }
        },
        { $sort: { totalRevenue: -1 } }
      ]
    }
  }
]);
```

### Aggregation Performance Optimization

```javascript
// 1. Use $match early to reduce documents
const optimizedAggregation = await Order.aggregate([
  // Filter first to reduce pipeline workload
  { $match: { status: 'completed', totalAmount: { $gt: 100 } } },
  
  // Use indexes with $match
  { $match: { orderDate: { $gte: startDate, $lte: endDate } } },
  
  // Project only needed fields
  { $project: { items: 1, totalAmount: 1, orderDate: 1 } },
  
  // Unwind after reducing documents
  { $unwind: '$items' },
  
  // Add indexes for sort
  { $sort: { orderDate: -1 } }
]);

// 2. Use $lookup with pipeline (MongoDB 3.6+)
const ordersWithProducts = await Order.aggregate([
  {
    $lookup: {
      from: 'products',
      let: { productIds: '$items.productId' },
      pipeline: [
        {
          $match: {
            $expr: {
              $in: ['$_id', '$$productIds']
            }
          }
        },
        {
          $project: {
            name: 1,
            category: 1,
            price: 1
          }
        }
      ],
      as: 'productDetails'
    }
  }
]);

// 3. Use $addFields instead of multiple $project stages
const optimized = await Order.aggregate([
  {
    $addFields: {
      itemCount: { $size: '$items' },
      hasDiscount: { $gt: ['$discountAmount', 0] },
      netAmount: {
        $subtract: ['$totalAmount', '$discountAmount']
      }
    }
  }
]);

// 4. Use $sample for random sampling
const randomOrders = await Order.aggregate([
  { $match: { status: 'completed' } },
  { $sample: { size: 100 } }
]);

// 5. Use $out to store aggregation results
await Order.aggregate([
  { $match: { orderDate: { $gte: startDate } } },
  {
    $group: {
      _id: '$userId',
      totalSpent: { $sum: '$totalAmount' }
    }
  },
  { $out: 'customer_lifetime_values' }
]);

// 6. Use $merge to update existing collection
await Order.aggregate([
  { $match: { orderDate: { $gte: new Date() } } },
  {
    $group: {
      _id: '$userId',
      dailySpend: { $sum: '$totalAmount' }
    }
  },
  {
    $merge: {
      into: 'daily_customer_spending',
      on: '_id',
      whenMatched: 'merge',
      whenNotMatched: 'insert'
    }
  }
]);

// 7. Monitor aggregation performance
const explainAggregation = await Order.aggregate([
  { $match: { status: 'completed' } },
  { $group: { _id: '$userId', count: { $sum: 1 } } }
]).explain('executionStats');

console.log('Aggregation stats:', explainAggregation);
```

---

## Transactions

MongoDB transactions allow multiple operations to be executed as a single atomic unit.

### Basic Transaction Usage

```javascript
// Start a session
const session = await mongoose.startSession();

try {
  // Start transaction
  session.startTransaction();
  
  // Perform operations within transaction
  const order = await Order.create([{
    userId: user._id,
    items: cartItems,
    totalAmount: total,
    status: 'pending'
  }], { session });
  
  // Update inventory
  for (const item of cartItems) {
    await Product.updateOne(
      { _id: item.productId, stock: { $gte: item.quantity } },
      { $inc: { stock: -item.quantity } },
      { session }
    );
  }
  
  // Create payment record
  await Payment.create([{
    orderId: order[0]._id,
    amount: total,
    method: paymentMethod,
    status: 'completed'
  }], { session });
  
  // Update user's order history
  await User.updateOne(
    { _id: user._id },
    { 
      $push: { 
        orders: order[0]._id,
        $each: [],
        $sort: -1,
        $slice: 50 // Keep only last 50 orders
      },
      $inc: { totalOrders: 1, totalSpent: total }
    },
    { session }
  );
  
  // Commit transaction if all operations succeed
  await session.commitTransaction();
  
  return order[0];
} catch (error) {
  // Abort transaction on error
  await session.abortTransaction();
  
  // Log transaction error
  console.error('Transaction failed:', error);
  
  // Rethrow error for handling upstream
  throw new Error(`Order processing failed: ${error.message}`);
} finally {
  // End session
  session.endSession();
}
```

### Advanced Transaction Patterns

```javascript
class BankingService {
  async transferFunds(fromAccountId, toAccountId, amount) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction();
      
      // Check if accounts exist and are active
      const fromAccount = await Account.findOne({
        _id: fromAccountId,
        status: 'active',
        balance: { $gte: amount }
      }).session(session);
      
      if (!fromAccount) {
        throw new Error('Insufficient funds or account inactive');
      }
      
      const toAccount = await Account.findOne({
        _id: toAccountId,
        status: 'active'
      }).session(session);
      
      if (!toAccount) {
        throw new Error('Recipient account not found or inactive');
      }
      
      // Perform debit and credit operations
      await Account.updateOne(
        { _id: fromAccountId },
        { $inc: { balance: -amount } },
        { session }
      );
      
      await Account.updateOne(
        { _id: toAccountId },
        { $inc: { balance: amount } },
        { session }
      );
      
      // Create transaction record
      const transaction = await Transaction.create([{
        fromAccount: fromAccountId,
        toAccount: toAccountId,
        amount: amount,
        type: 'transfer',
        status: 'completed',
        timestamp: new Date(),
        reference: `TRX-${Date.now()}`
      }], { session });
      
      // Update account transaction history
      await Account.updateOne(
        { _id: fromAccountId },
        { $push: { transactions: transaction[0]._id } },
        { session }
      );
      
      await Account.updateOne(
        { _id: toAccountId },
        { $push: { transactions: transaction[0]._id } },
        { session }
      );
      
      await session.commitTransaction();
      
      return {
        success: true,
        transactionId: transaction[0]._id,
        newBalance: fromAccount.balance - amount
      };
      
    } catch (error) {
      await session.abortTransaction();
      
      // Log the failed transaction for audit
      await FailedTransaction.create({
        fromAccount: fromAccountId,
        toAccount: toAccountId,
        amount: amount,
        error: error.message,
        timestamp: new Date()
      });
      
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  async batchTransfer(transfers) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction();
      
      const results = [];
      
      for (const transfer of transfers) {
        try {
          const result = await this.transferFunds(
            transfer.fromAccountId,
            transfer.toAccountId,
            transfer.amount,
            session // Reuse same session
          );
          results.push({ ...transfer, success: true, result });
        } catch (error) {
          results.push({ ...transfer, success: false, error: error.message });
          // Continue with other transfers
        }
      }
      
      // Check if any critical failures occurred
      const criticalFailures = results.filter(r => !r.success && r.critical);
      
      if (criticalFailures.length > 0) {
        throw new Error('Critical transfers failed');
      }
      
      await session.commitTransaction();
      return results;
      
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }
}
```

### Transaction with Retry Logic

```javascript
async function executeWithRetry(operation, maxRetries = 3) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction();
      
      const result = await operation(session);
      
      await session.commitTransaction();
      
      return result;
    } catch (error) {
      await session.abortTransaction();
      lastError = error;
      
      // Check if error is retryable
      if (isRetryableError(error) && attempt < maxRetries) {
        // Exponential backoff
        const delay = Math.pow(2, attempt) * 100;
        console.log(`Retry attempt ${attempt} after ${delay}ms`);
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      
      break;
    } finally {
      session.endSession();
    }
  }
  
  throw lastError;
}

function isRetryableError(error) {
  // Transient transaction errors
  const retryableCodes = [
    'WriteConflict',
    'LockTimeout',
    'PreparedTransactionInProgress',
    'SnapshotTooOld'
  ];
  
  return retryableCodes.some(code => 
    error.message.includes(code) || error.codeName === code
  );
}

// Usage
const result = await executeWithRetry(async (session) => {
  // Your transactional operations
  const order = await Order.create([orderData], { session });
  await Inventory.updateOne(
    { productId: orderData.productId },
    { $inc: { quantity: -orderData.quantity } },
    { session }
  );
  return order;
});
```

### Cross-Collection Transactions

```javascript
async function createECommerceOrder(userId, cart, paymentInfo, shippingAddress) {
  const session = await mongoose.startSession();
  
  try {
    session.startTransaction();
    
    // 1. Validate and reserve inventory
    const inventoryUpdates = [];
    const orderItems = [];
    
    for (const item of cart.items) {
      const product = await Product.findOne({
        _id: item.productId,
        status: 'active',
        inventory: { $gte: item.quantity }
      }).session(session);
      
      if (!product) {
        throw new Error(`Product ${item.productId} unavailable`);
      }
      
      // Reserve inventory
      await Product.updateOne(
        { _id: item.productId },
        { 
          $inc: { 
            inventory: -item.quantity,
            reservedInventory: item.quantity
          }
        },
        { session }
      );
      
      inventoryUpdates.push({
        productId: item.productId,
        quantity: -item.quantity
      });
      
      orderItems.push({
        productId: item.productId,
        name: product.name,
        quantity: item.quantity,
        price: product.price,
        subtotal: product.price * item.quantity
      });
    }
    
    // 2. Calculate totals
    const subtotal = orderItems.reduce((sum, item) => sum + item.subtotal, 0);
    const tax = subtotal * 0.08; // 8% tax
    const shipping = calculateShipping(shippingAddress, cart);
    const total = subtotal + tax + shipping;
    
    // 3. Create order
    const order = await Order.create([{
      userId,
      items: orderItems,
      subtotal,
      tax,
      shipping,
      total,
      status: 'pending',
      shippingAddress,
      paymentStatus: 'pending',
      createdAt: new Date()
    }], { session });
    
    // 4. Process payment
    const paymentResult = await processPayment(paymentInfo, total);
    
    if (!paymentResult.success) {
      throw new Error(`Payment failed: ${paymentResult.error}`);
    }
    
    await Payment.create([{
      orderId: order[0]._id,
      amount: total,
      method: paymentInfo.method,
      transactionId: paymentResult.transactionId,
      status: 'completed',
      processedAt: new Date()
    }], { session });
    
    // 5. Update order status
    await Order.updateOne(
      { _id: order[0]._id },
      { 
        $set: { 
          status: 'processing',
          paymentStatus: 'completed',
          paymentId: paymentResult.transactionId
        }
      },
      { session }
    );
    
    // 6. Update user's order history
    await User.updateOne(
      { _id: userId },
      { 
        $push: { 
          orders: {
            $each: [order[0]._id],
            $position: 0
          }
        },
        $inc: { totalOrders: 1, totalSpent: total }
      },
      { session }
    );
    
    // 7. Clear user's cart
    await Cart.deleteOne({ userId }, { session });
    
    // 8. Send order confirmation
    await Notification.create([{
      userId,
      type: 'order_confirmation',
      title: 'Order Confirmed',
      message: `Your order #${order[0].orderNumber} has been confirmed.`,
      metadata: { orderId: order[0]._id },
      sentAt: new Date()
    }], { session });
    
    await session.commitTransaction();
    
    // Post-transaction actions (outside transaction)
    await sendEmailConfirmation(userId, order[0]);
    await updateAnalytics(order[0]);
    
    return {
      success: true,
      orderId: order[0]._id,
      orderNumber: order[0].orderNumber,
      total: total
    };
    
  } catch (error) {
    await session.abortTransaction();
    
    // Revert inventory reservations
    if (inventoryUpdates && inventoryUpdates.length > 0) {
      await revertInventoryReservations(inventoryUpdates);
    }
    
    throw error;
  } finally {
    session.endSession();
  }
}
```

### Transaction Best Practices

```javascript
// 1. Keep transactions short
// Transactions block resources, so keep them under 60 seconds

// 2. Use appropriate read/write concerns
const session = await mongoose.startSession({
  defaultTransactionOptions: {
    readConcern: { level: 'snapshot' },
    writeConcern: { w: 'majority' },
    readPreference: 'primary'
  }
});

// 3. Handle transaction timeouts
session.startTransaction({
  maxTimeMS: 30000, // 30 second timeout
  readConcern: { level: 'local' },
  writeConcern: { w: 1 }
});

// 4. Monitor transaction performance
mongoose.connection.on('transactionStarted', (event) => {
  console.log('Transaction started:', event);
});

mongoose.connection.on('transactionCommitted', (event) => {
  console.log('Transaction committed:', event);
});

mongoose.connection.on('transactionAborted', (event) => {
  console.log('Transaction aborted:', event);
});

// 5. Use causal consistency for read-your-writes
const session = mongoose.startSession({ causalConsistency: true });

// 6. Implement deadlock detection and handling
async function safeTransaction(operation) {
  const maxAttempts = 5;
  
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      if (error.message.includes('WriteConflict') && attempt < maxAttempts - 1) {
        // Random backoff to avoid repeated conflicts
        const backoff = Math.random() * 100 * Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, backoff));
        continue;
      }
      throw error;
    }
  }
}

// 7. Use optimistic concurrency control
const productSchema = new Schema({
  name: String,
  price: Number,
  version: { type: Number, default: 0 }
});

productSchema.pre('save', function(next) {
  if (this.isModified()) {
    this.version += 1;
  }
  next();
});

async function updateProductWithOptimisticLock(productId, update) {
  const product = await Product.findById(productId);
  const currentVersion = product.version;
  
  const result = await Product.updateOne(
    { 
      _id: productId,
      version: currentVersion // Ensure no one else updated
    },
    { 
      ...update,
      $inc: { version: 1 }
    }
  );
  
  if (result.nModified === 0) {
    throw new Error('Concurrent modification detected');
  }
  
  return result;
}
```

---

## Populating Relations

Population is the process of automatically replacing specified paths in the document with document(s) from other collection(s).

### Basic Population

```javascript
const userSchema = new Schema({
  name: String,
  email: String
});

const postSchema = new Schema({
  title: String,
  content: String,
  author: { type: Schema.Types.ObjectId, ref: 'User' },
  comments: [{ type: Schema.Types.ObjectId, ref: 'Comment' }],
  tags: [{ type: Schema.Types.ObjectId, ref: 'Tag' }]
});

const commentSchema = new Schema({
  content: String,
  author: { type: Schema.Types.ObjectId, ref: 'User' },
  post: { type: Schema.Types.ObjectId, ref: 'Post' },
  createdAt: { type: Date, default: Date.now }
});
```

### Single-Level Population

```javascript
// Populate single reference
const post = await Post.findById(postId)
  .populate('author')
  .populate('tags');

// Populate with field selection
const post = await Post.findById(postId)
  .populate('author', 'name email avatar')
  .populate('tags', 'name color');

// Populate with conditions
const post = await Post.findById(postId)
  .populate({
    path: 'comments',
    match: { 
      status: 'approved',
      createdAt: { $gt: new Date('2024-01-01') }
    },
    options: { 
      sort: { createdAt: -1 },
      limit: 10
    },
    select: 'content author createdAt',
    // Populate nested references
    populate: {
      path: 'author',
      select: 'name avatar'
    }
  });

// Populate multiple paths
const post = await Post.findById(postId)
  .populate([
    { path: 'author', select: 'name' },
    { 
      path: 'comments',
      populate: { path: 'author', select: 'name' }
    },
    { path: 'tags' }
  ]);

// Population on query results
const posts = await Post.find({ status: 'published' })
  .populate('author')
  .populate('tags')
  .sort({ createdAt: -1 })
  .limit(20);
```

### Deep Population (Nested)

```javascript
// Deep nested population
const post = await Post.findById(postId)
  .populate({
    path: 'comments',
    populate: [
      {
        path: 'author',
        select: 'name avatar',
        populate: {
          path: 'profile',
          select: 'bio location'
        }
      },
      {
        path: 'replies',
        populate: {
          path: 'author',
          select: 'name'
        }
      }
    ]
  });

// Recursive population (for tree structures)
const categorySchema = new Schema({
  name: String,
  parent: { type: Schema.Types.ObjectId, ref: 'Category' },
  children: [{ type: Schema.Types.ObjectId, ref: 'Category' }]
});

async function getCategoryTree(categoryId, depth = 3) {
  const populateChildren = (currentDepth) => {
    if (currentDepth >= depth) return null;
    
    return {
      path: 'children',
      populate: populateChildren(currentDepth + 1)
    };
  };
  
  return Category.findById(categoryId)
    .populate(populateChildren(0))
    .exec();
}
```

### Virtual Population

```javascript
// Virtual populate (for reverse relationships)
postSchema.virtual('likes', {
  ref: 'Like', // The model to use
  localField: '_id', // Find likes where `localField`
  foreignField: 'post', // is equal to `foreignField`
  count: true // Return count instead of documents
});

postSchema.virtual('bookmarks', {
  ref: 'Bookmark',
  localField: '_id',
  foreignField: 'post',
  // Options for the populate
  options: { 
    sort: { createdAt: -1 },
    limit: 50 
  }
});

// Using virtual populate
const post = await Post.findById(postId)
  .populate('likes')
  .populate('bookmarks');

// Virtual with match
userSchema.virtual('publishedPosts', {
  ref: 'Post',
  localField: '_id',
  foreignField: 'author',
  match: { status: 'published' }
});

// Virtual with options and population
userSchema.virtual('recentComments', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'author',
  options: { 
    sort: { createdAt: -1 },
    limit: 5 
  },
  populate: {
    path: 'post',
    select: 'title slug'
  }
});
```

### Dynamic Population

```javascript
// Dynamic population based on conditions
async function getPostWithRelations(postId, populateOptions = {}) {
  const query = Post.findById(postId);
  
  // Add population based on options
  if (populateOptions.includeAuthor) {
    query.populate('author', 'name avatar');
  }
  
  if (populateOptions.includeComments) {
    const commentPopulate = {
      path: 'comments',
      options: { sort: { createdAt: -1 } }
    };
    
    if (populateOptions.commentLimit) {
      commentPopulate.options.limit = populateOptions.commentLimit;
    }
    
    if (populateOptions.includeCommentAuthors) {
      commentPopulate.populate = {
        path: 'author',
        select: 'name avatar'
      };
    }
    
    query.populate(commentPopulate);
  }
  
  if (populateOptions.includeTags) {
    query.populate('tags', 'name color');
  }
  
  if (populateOptions.includeStats) {
    query.populate('likes');
    query.populate('bookmarks');
  }
  
  return query.exec();
}

// Population with middleware
postSchema.pre('find', function() {
  // Auto-populate author for all find queries
  this.populate('author', 'name avatar');
});

postSchema.pre('findOne', function() {
  this.populate('author', 'name avatar');
});

// Conditional auto-population
postSchema.pre(/^find/, function(next) {
  // Only auto-populate if not already populated
  if (!this._mongooseOptions.populate) {
    this.populate('author', 'name avatar');
  }
  next();
});
```

### Population Performance Optimization

```javascript
// 1. Use lean() with population for read-only operations
const posts = await Post.find({ status: 'published' })
  .populate('author', 'name avatar')
  .lean(); // Returns plain JavaScript objects

// 2. Batch population to avoid N+1 queries
async function getPostsWithAuthors(posts) {
  const authorIds = [...new Set(posts.map(p => p.author))];
  const authors = await User.find({ _id: { $in: authorIds } })
    .select('name avatar email')
    .lean();
  
  const authorMap = authors.reduce((map, author) => {
    map[author._id] = author;
    return map;
  }, {});
  
  return posts.map(post => ({
    ...post.toObject(),
    author: authorMap[post.author]
  }));
}

// 3. Selective population based on needs
function getPostPopulation(needs) {
  const population = [];
  
  if (needs.includes('author')) {
    population.push({ path: 'author', select: 'name avatar' });
  }
  
  if (needs.includes('comments')) {
    population.push({ 
      path: 'comments',
      select: 'content createdAt',
      options: { sort: { createdAt: -1 }, limit: 10 }
    });
  }
  
  if (needs.includes('tags')) {
    population.push({ path: 'tags', select: 'name color' });
  }
  
  return population;
}

// 4. Use $lookup in aggregation instead of populate for complex queries
const postsWithStats = await Post.aggregate([
  { $match: { status: 'published' } },
  {
    $lookup: {
      from: 'users',
      localField: 'author',
      foreignField: '_id',
      as: 'author'
    }
  },
  { $unwind: '$author' },
  {
    $lookup: {
      from: 'likes',
      localField: '_id',
      foreignField: 'post',
      as: 'likes'
    }
  },
  {
    $addFields: {
      likeCount: { $size: '$likes' },
      authorName: '$author.name'
    }
  },
  {
    $project: {
      title: 1,
      content: 1,
      authorName: 1,
      likeCount: 1,
      'author.avatar': 1
    }
  }
]);

// 5. Cache populated results
class PostCache {
  constructor(redisClient) {
    this.redis = redisClient;
    this.ttl = 300; // 5 minutes
  }
  
  async getPostWithRelations(postId) {
    const cacheKey = `post:${postId}:with_relations`;
    
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }
    
    const post = await Post.findById(postId)
      .populate('author', 'name avatar')
      .populate('tags', 'name')
      .populate({
        path: 'comments',
        options: { limit: 10, sort: { createdAt: -1 } },
        populate: { path: 'author', select: 'name' }
      })
      .lean();
    
    if (post) {
      await this.redis.setex(cacheKey, this.ttl, JSON.stringify(post));
    }
    
    return post;
  }
}
```

### Population with Transform

```javascript
// Transform populated data
const post = await Post.findById(postId)
  .populate({
    path: 'author',
    select: 'name email',
    transform: (doc) => {
      if (!doc) return doc;
      return {
        id: doc._id,
        name: doc.name,
        email: doc.email,
        initials: doc.name.split(' ').map(n => n[0]).join('')
      };
    }
  })
  .populate({
    path: 'comments',
    options: { limit: 5 },
    transform: (comments) => {
      return comments.map(comment => ({
        id: comment._id,
        content: comment.content,
        author: comment.author,
        timeAgo: getTimeAgo(comment.createdAt)
      }));
    }
  });

// Global transform for all populated documents
mongoose.set('toObject', { transform: true });
mongoose.set('toJSON', { transform: true });

postSchema.set('toObject', {
  transform: function(doc, ret, options) {
    ret.id = ret._id.toString();
    delete ret._id;
    delete ret.__v;
    
    // Transform populated fields
    if (ret.author && ret.author._id) {
      ret.author.id = ret.author._id.toString();
      delete ret.author._id;
      delete ret.author.__v;
    }
    
    return ret;
  }
});
```

---

## Optimizing Queries

### Query Optimization Techniques

```javascript
// 1. Use Projection to Select Only Needed Fields
const users = await User.find({ status: 'active' }, 'name email avatar');
const user = await User.findById(userId, 'name email createdAt');

// 2. Use Lean for Read-Only Operations
const posts = await Post.find({ status: 'published' })
  .populate('author', 'name')
  .lean(); // Returns plain JS objects, faster

// 3. Implement Efficient Pagination
async function getPaginatedResults(model, query, page = 1, limit = 20, sort = { createdAt: -1 }) {
  const skip = (page - 1) * limit;
  
  const [results, total] = await Promise.all([
    model.find(query)
      .select('title author createdAt')
      .populate('author', 'name')
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .lean(),
    
    model.countDocuments(query)
  ]);
  
  return {
    results,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
      hasNext: page * limit < total,
      hasPrev: page > 1
    }
  };
}

// 4. Use Covered Queries
// Create index that covers the query
userSchema.index({ status: 1, createdAt: -1, name: 1, email: 1 });

// Query that uses only indexed fields
const activeUsers = await User.find(
  { status: 'active' },
  { _id: 0, name: 1, email: 1, status: 1, createdAt: 1 }
).hint({ status: 1, createdAt: -1 });

// 5. Batch Operations for Better Performance
// Use insertMany for bulk inserts
const users = await User.insertMany(userArray, { ordered: false });

// Use bulkWrite for mixed operations
const result = await Product.bulkWrite([
  {
    updateOne: {
      filter: { _id: productId1 },
      update: { $set: { price: 99.99 } }
    }
  },
  {
    updateOne: {
      filter: { _id: productId2 },
      update: { $inc: { stock: -5 } }
    }
  },
  {
    deleteOne: {
      filter: { _id: productId3 }
    }
  }
]);

// 6. Use Cursors for Large Result Sets
const cursor = User.find({ status: 'active' }).cursor();

for (let user = await cursor.next(); user != null; user = await cursor.next()) {
  // Process each user
  await processUser(user);
}

// Or use async iteration
for await (const user of User.find({ status: 'active' }).cursor()) {
  await processUser(user);
}

// 7. Optimize Sort Operations
// Create index on sort field
userSchema.index({ createdAt: -1 });

// Use compound index for sort with filter
userSchema.index({ status: 1, createdAt: -1 });

// Query with efficient sort
const recentUsers = await User.find({ status: 'active' })
  .sort({ createdAt: -1 })
  .limit(100);

// 8. Use Explain() to Analyze Queries
const explanation = await User.find({ email: 'test@example.com' })
  .explain('executionStats');

console.log('Query Stats:', {
  executionTime: explanation.executionStats.executionTimeMillis,
  totalDocsExamined: explanation.executionStats.totalDocsExamined,
  totalKeysExamined: explanation.executionStats.totalKeysExamined,
  indexUsed: explanation.executionStats.executionStages.inputStage?.indexName
});
```

### Index Optimization Strategies

```javascript
// 1. Create Indexes Based on Query Patterns
// Analyze common queries and create appropriate indexes

// Query: find users by email
userSchema.index({ email: 1 });

// Query: find active users sorted by creation date
userSchema.index({ status: 1, createdAt: -1 });

// Query: find users by location within radius
userSchema.index({ 'location.coordinates': '2dsphere' });

// 2. Use Compound Indexes Wisely
// ESR Rule: Equality → Sort → Range
// Good: { category: 1, price: -1 }
// Good: { status: 1, createdAt: -1, userId: 1 }

// 3. Monitor Index Usage
const indexStats = await User.collection.aggregate([
  { $indexStats: {} }
]).toArray();

indexStats.forEach(stat => {
  console.log(`Index: ${stat.name}`);
  console.log(`Accesses: ${stat.accesses.ops}`);
  console.log(`Hit Rate: ${(stat.accesses.ops / stat.accesses.total) * 100}%`);
});

// 4. Remove Unused Indexes
const unusedIndexes = indexStats.filter(stat => stat.accesses.ops === 0);
unusedIndexes.forEach(index => {
  console.log(`Consider removing: ${index.name}`);
});

// 5. Use Partial Indexes
// Index only documents that match a filter
userSchema.index(
  { email: 1 },
  { 
    partialFilterExpression: { 
      email: { $exists: true },
      status: 'active'
    }
  }
);

// 6. Use Sparse Indexes for Optional Fields
userSchema.index({ phoneNumber: 1 }, { sparse: true });

// 7. Consider Index Size vs Performance
const stats = await User.collection.stats();
console.log('Index sizes:', stats.indexSizes);
console.log('Total index size:', stats.totalIndexSize);
```

### Connection and Pool Optimization

```javascript
// 1. Configure Connection Pool
mongoose.connect('mongodb://localhost:27017/mydb', {
  maxPoolSize: 50, // Maximum number of connections in pool
  minPoolSize: 10, // Minimum number of connections to maintain
  maxIdleTimeMS: 30000, // Close idle connections after 30s
  waitQueueTimeoutMS: 5000, // Timeout for connection acquisition
  socketTimeoutMS: 45000, // Socket timeout
  connectTimeoutMS: 30000, // Connection timeout
  serverSelectionTimeoutMS: 5000, // Server selection timeout
  heartbeatFrequencyMS: 10000 // How often to check connection
});

// 2. Monitor Connection Pool
mongoose.connection.on('connectionCreated', (event) => {
  console.log('New connection created:', event.id);
});

mongoose.connection.on('connectionClosed', (event) => {
  console.log('Connection closed:', event.id);
});

mongoose.connection.on('connectionCheckOutStarted', (event) => {
  console.log('Connection checked out:', event);
});

mongoose.connection.on('connectionCheckOutFailed', (event) => {
  console.error('Connection check out failed:', event);
});

// 3. Use Read Preferences for Read Scaling
const readOnlyConnection = mongoose.createConnection('mongodb://localhost:27017/mydb', {
  readPreference: 'secondary', // Read from secondary nodes
  readPreferenceTags: [{ region: 'us-east' }]
});

// 4. Implement Connection Retry Logic
async function connectWithRetry(url, options, maxRetries = 5) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      await mongoose.connect(url, options);
      console.log('Connected to MongoDB');
      return;
    } catch (error) {
      console.error(`Connection attempt ${i + 1} failed:`, error.message);
      
      if (i === maxRetries - 1) {
        throw error;
      }
      
      // Exponential backoff
      const delay = Math.pow(2, i) * 1000;
      console.log(`Retrying in ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}
```

### Caching Strategies

```javascript
class QueryCache {
  constructor(redisClient) {
    this.redis = redisClient;
  }
  
  async getCachedQuery(cacheKey, queryFn, ttl = 300) {
    // Try to get from cache
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }
    
    // Execute query
    const result = await queryFn();
    
    // Cache the result
    if (result) {
      await this.redis.setex(cacheKey, ttl, JSON.stringify(result));
    }
    
    return result;
  }
  
  generateCacheKey(model, query, options = {}) {
    const keyParts = [
      model.modelName.toLowerCase(),
      JSON.stringify(query),
      JSON.stringify(options.fields || {}),
      options.sort ? JSON.stringify(options.sort) : '',
      options.limit || '',
      options.skip || ''
    ];
    
    return `query:${md5(keyParts.join(':'))}`;
  }
  
  async cachedFind(model, query, options = {}) {
    const cacheKey = this.generateCacheKey(model, query, options);
    
    return this.getCachedQuery(cacheKey, async () => {
      let queryBuilder = model.find(query);
      
      if (options.fields) {
        queryBuilder = queryBuilder.select(options.fields);
      }
      
      if (options.sort) {
        queryBuilder = queryBuilder.sort(options.sort);
      }
      
      if (options.limit) {
        queryBuilder = queryBuilder.limit(options.limit);
      }
      
      if (options.skip) {
        queryBuilder = queryBuilder.skip(options.skip);
      }
      
      if (options.populate) {
        queryBuilder = queryBuilder.populate(options.populate);
      }
      
      if (options.lean) {
        queryBuilder = queryBuilder.lean();
      }
      
      return queryBuilder.exec();
    }, options.ttl || 300);
  }
}

// Usage
const cache = new QueryCache(redisClient);
const users = await cache.cachedFind(User, { status: 'active' }, {
  fields: 'name email',
  sort: { createdAt: -1 },
  limit: 50,
  ttl: 600 // 10 minutes
});
```

### Query Monitoring and Analysis

```javascript
// 1. Enable Query Logging
mongoose.set('debug', function(collectionName, method, query, doc) {
  console.log(`Mongoose: ${collectionName}.${method}`, {
    query: JSON.stringify(query),
    doc: doc
  });
});

// 2. Custom Query Logger with Performance Tracking
class QueryLogger {
  constructor() {
    this.slowQueryThreshold = 100; // milliseconds
    this.queryLog = [];
  }
  
  logQuery(collection, operation, query, duration) {
    const logEntry = {
      timestamp: new Date(),
      collection,
      operation,
      query: JSON.stringify(query),
      duration,
      isSlow: duration > this.slowQueryThreshold
    };
    
    this.queryLog.push(logEntry);
    
    if (logEntry.isSlow) {
      console.warn('Slow query detected:', logEntry);
    }
    
    // Keep only last 1000 queries
    if (this.queryLog.length > 1000) {
      this.queryLog.shift();
    }
  }
  
  getSlowQueries() {
    return this.queryLog.filter(log => log.isSlow);
  }
  
  getQueryStats() {
    const stats = {
      totalQueries: this.queryLog.length,
      slowQueries: this.getSlowQueries().length,
      averageDuration: 0,
      maxDuration: 0
    };
    
    if (this.queryLog.length > 0) {
      const totalDuration = this.queryLog.reduce((sum, log) => sum + log.duration, 0);
      stats.averageDuration = totalDuration / this.queryLog.length;
      stats.maxDuration = Math.max(...this.queryLog.map(log => log.duration));
    }
    
    return stats;
  }
}

// 3. Middleware for Query Tracking
const queryLogger = new QueryLogger();

mongoose.plugin((schema) => {
  schema.pre(/^find/, function(next) {
    this._startTime = Date.now();
    next();
  });
  
  schema.post(/^find/, function(docs) {
    const duration = Date.now() - this._startTime;
    queryLogger.logQuery(
      this.model.modelName,
      this.op,
      this.getFilter(),
      duration
    );
  });
});

// 4. Use MongoDB Profiler
// Enable profiling
await mongoose.connection.db.command({ profile: 2 }); // 0=off, 1=slow, 2=all

// Get profiler data
const profileData = await mongoose.connection.db.collection('system.profile')
  .find({})
  .sort({ ts: -1 })
  .limit(100)
  .toArray();

// Analyze slow operations
const slowOps = profileData.filter(op => op.millis > 100);
```

### Real-World Optimization Examples

```javascript
// Example 1: E-commerce Product Search Optimization
class ProductSearch {
  constructor() {
    // Create optimized indexes
    productSchema.index({ category: 1, price: 1 });
    productSchema.index({ name: 'text', description: 'text' });
    productSchema.index({ tags: 1, createdAt: -1 });
  }
  
  async searchProducts(filters, page = 1, limit = 20) {
    const query = {};
    const sort = {};
    
    // Build query based on filters
    if (filters.category) {
      query.category = filters.category;
    }
    
    if (filters.minPrice || filters.maxPrice) {
      query.price = {};
      if (filters.minPrice) query.price.$gte = filters.minPrice;
      if (filters.maxPrice) query.price.$lte = filters.maxPrice;
    }
    
    if (filters.tags && filters.tags.length > 0) {
      query.tags = { $all: filters.tags };
    }
    
    if (filters.inStock) {
      query.stock = { $gt: 0 };
    }
    
    // Text search
    if (filters.search) {
      query.$text = { $search: filters.search };
      sort.score = { $meta: 'textScore' };
    } else {
      // Default sort
      sort.createdAt = -1;
    }
    
    // Use lean for better performance
    const [products, total] = await Promise.all([
      Product.find(query)
        .select('name price images rating stock category')
        .sort(sort)
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      
      Product.countDocuments(query)
    ]);
    
    return { products, total, page, limit };
  }
}

// Example 2: Social Media Feed Optimization
class FeedService {
  async getUserFeed(userId, page = 1, limit = 20) {
    // Get user's followed users
    const user = await User.findById(userId).select('following');
    
    // Use aggregation for complex feed logic
    const feed = await Post.aggregate([
      // Match posts from followed users or user's own posts
      {
        $match: {
          $or: [
            { author: { $in: user.following } },
            { author: userId }
          ],
          status: 'published',
          visibility: { $in: ['public', 'friends'] }
        }
      },
      
      // Lookup author details
      {
        $lookup: {
          from: 'users',
          localField: 'author',
          foreignField: '_id',
          as: 'author'
        }
      },
      { $unwind: '$author' },
      
      // Lookup likes
      {
        $lookup: {
          from: 'likes',
          localField: '_id',
          foreignField: 'post',
          as: 'likes'
        }
      },
      
      // Lookup comments count
      {
        $lookup: {
          from: 'comments',
          localField: '_id',
          foreignField: 'post',
          pipeline: [
            { $match: { status: 'approved' } },
            { $count: 'count' }
          ],
          as: 'comments'
        }
      },
      
      // Add computed fields
      {
        $addFields: {
          likeCount: { $size: '$likes' },
          commentCount: { $arrayElemAt: ['$comments.count', 0] },
          isLiked: {
            $in: [userId, '$likes.user']
          },
          authorName: '$author.name',
          authorAvatar: '$author.avatar'
        }
      },
      
      // Sort by engagement score (weighted combination)
      {
        $addFields: {
          engagementScore: {
            $add: [
              { $multiply: ['$likeCount', 2] },
              { $multiply: ['$commentCount', 3] },
              {
                $cond: {
                  if: { $eq: ['$author', userId] },
                  then: 10,
                  else: 0
                }
              }
            ]
          }
        }
      },
      
      // Final projection
      {
        $project: {
          title: 1,
          content: 1,
          images: 1,
          createdAt: 1,
          authorName: 1,
          authorAvatar: 1,
          likeCount: 1,
          commentCount: 1,
          isLiked: 1,
          engagementScore: 1
        }
      },
      
      // Sort by engagement and time
      { $sort: { engagementScore: -1, createdAt: -1 } },
      
      // Pagination
      { $skip: (page - 1) * limit },
      { $limit: limit }
    ]);
    
    return feed;
  }
}

// Example 3: Analytics Dashboard Optimization
class AnalyticsService {
  async getRealTimeMetrics(startDate, endDate) {
    // Use parallel aggregation for different metrics
    const [revenueStats, userStats, productStats] = await Promise.all([
      // Revenue analytics
      Order.aggregate([
        {
          $match: {
            status: 'completed',
            createdAt: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $group: {
            _id: null,
            totalRevenue: { $sum: '$totalAmount' },
            avgOrderValue: { $avg: '$totalAmount' },
            orderCount: { $sum: 1 },
            uniqueCustomers: { $addToSet: '$userId' }
          }
        },
        {
          $project: {
            totalRevenue: 1,
            avgOrderValue: { $round: ['$avgOrderValue', 2] },
            orderCount: 1,
            uniqueCustomerCount: { $size: '$uniqueCustomers' }
          }
        }
      ]),
      
      // User analytics
      User.aggregate([
        {
          $match: {
            createdAt: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $group: {
            _id: null,
            totalUsers: { $sum: 1 },
            activeUsers: {
              $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
            },
            vipUsers: {
              $sum: { $cond: [{ $eq: ['$tier', 'vip'] }, 1, 0] }
            }
          }
        }
      ]),
      
      // Product analytics
      Order.aggregate([
        {
          $match: {
            status: 'completed',
            createdAt: { $gte: startDate, $lte: endDate }
          }
        },
        { $unwind: '$items' },
        {
          $group: {
            _id: '$items.productId',
            totalSold: { $sum: '$items.quantity' },
            revenue: {
              $sum: { $multiply: ['$items.quantity', '$items.price'] }
            }
          }
        },
        { $sort: { revenue: -1 } },
        { $limit: 10 },
        {
          $lookup: {
            from: 'products',
            localField: '_id',
            foreignField: '_id',
            as: 'product'
          }
        },
        { $unwind: '$product' },
        {
          $project: {
            productName: '$product.name',
            totalSold: 1,
            revenue: 1
          }
        }
      ])
    ]);
    
    return {
      revenue: revenueStats[0] || {},
      users: userStats[0] || {},
      topProducts: productStats
    };
  }
}
```

---

## Interview Questions

### Junior to Mid-Level

**Schemas & Models:**
1. What is the difference between a Mongoose Schema and a Model?
2. How do you define a one-to-many relationship in Mongoose?
3. What are virtual properties and when would you use them?
4. How do you create a compound index in Mongoose?
5. What is the purpose of the `timestamps` option in a schema?

**Validators:**
1. What built-in validators does Mongoose provide?
2. How do you create a custom validator?
3. What's the difference between synchronous and asynchronous validators?
4. How do you handle validation errors?
5. How can you make validation conditional based on other fields?

**Basic Queries:**
1. What's the difference between `findOne()` and `findById()`?
2. How do you update multiple documents at once?
3. What is population and when would you use it?
4. How do you implement pagination with Mongoose?
5. What's the purpose of the `lean()` method?

### Senior Level

**Schema Design:**
1. How would you design a schema for a social media application with users, posts, comments, and likes?
2. When would you choose embedding over referencing for related data?
3. How do you handle schema evolution in a production application?
4. What strategies would you use for versioning your schemas?
5. How would you design a multi-tenant application schema?

**Performance & Optimization:**
1. How would you identify and fix slow queries in a production application?
2. What indexing strategies would you use for an e-commerce product search?
3. How do you optimize aggregation pipelines for large datasets?
4. What are covered queries and how do they improve performance?
5. How would you implement caching with Mongoose queries?

**Advanced Features:**
1. How do transactions work in MongoDB and when should you use them?
2. What are change streams and how can they be used for real-time features?
3. How would you implement full-text search with MongoDB?
4. What are the differences between `$lookup` and population?
5. How do you handle database migrations with Mongoose?

**Scalability:**
1. How would you shard a MongoDB collection for horizontal scaling?
2. What strategies would you use for read/write splitting?
3. How do you handle database connections in a serverless environment?
4. What are the considerations for using MongoDB in a microservices architecture?
5. How would you implement data partitioning for a multi-region application?

### Real-World Scenarios

**Scenario 1: E-commerce Platform**
You're building an e-commerce platform that needs to handle:
- 10,000+ products with real-time inventory
- 100,000+ daily orders during peak seasons
- Complex product search with filters and sorting
- Real-time order tracking and notifications

**Questions:**
1. How would you design the product schema to support fast search?
2. What indexing strategy would you implement for product searches?
3. How would you handle inventory updates during flash sales to prevent overselling?
4. How would you optimize the order processing pipeline?
5. What caching strategy would you implement for frequently accessed products?

**Scenario 2: Social Media Application**
You're building a social media app that needs to:
- Support millions of users with personalized feeds
- Handle real-time updates (likes, comments, notifications)
- Implement complex privacy settings
- Provide analytics on user engagement

**Questions:**
1. How would you design the schema for posts, comments, and user relationships?
2. What strategy would you use for implementing the news feed feature?
3. How would you handle real-time notifications at scale?
4. How would you implement privacy controls at the database level?
5. What aggregation queries would you use for engagement analytics?

**Scenario 3: Financial Application**
You're building a banking application that needs:
- ACID compliance for financial transactions
- Audit trails for all transactions
- Real-time balance updates
- Support for batch processing of transactions

**Questions:**
1. How would you ensure data consistency for money transfers?
2. What transaction isolation levels would you use and why?
3. How would you implement an audit trail for all database operations?
4. How would you handle concurrent balance updates?
5. What backup and recovery strategy would you implement?

**Scenario 4: Analytics Platform**
You're building an analytics platform that needs to:
- Process billions of events per day
- Provide real-time dashboards
- Support complex aggregations and calculations
- Handle data retention policies

**Questions:**
1. How would you structure your data for efficient aggregation?
2. What indexing strategy would you use for time-series data?
3. How would you implement real-time aggregation updates?
4. How would you handle data partitioning for historical data?
5. What strategy would you use for archiving old data?

**Scenario 5: Multi-tenant SaaS Application**
You're building a SaaS platform that needs to:
- Support thousands of tenants with isolated data
- Allow tenant-specific custom fields
- Provide cross-tenant analytics (for platform admin)
- Scale horizontally as tenant count grows

**Questions:**
1. How would you implement data isolation between tenants?
2. What schema design would you use for tenant-specific customizations?
3. How would you handle database migrations across all tenants?
4. How would you optimize queries for multi-tenant data?
5. What sharding strategy would you use for horizontal scaling?