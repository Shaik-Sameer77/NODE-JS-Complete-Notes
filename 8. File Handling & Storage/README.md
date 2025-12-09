# File Handling & Storage - Comprehensive Guide

## 📚 Table of Contents
1. [Multer](#multer)
2. [Busboy](#busboy)
3. [Cloudinary Upload](#cloudinary-upload)
4. [S3 File Upload](#s3-file-upload)
5. [Pre-signed URLs](#pre-signed-urls)
6. [Local Storage Structure](#local-storage-structure)
7. [Interview Questions](#interview-questions)
8. [Real-World Scenarios](#real-world-scenarios)

---

## 1. Multer {#multer}

### Overview
Multer is a Node.js middleware for handling `multipart/form-data`, primarily used for uploading files. It's built on top of busboy for maximum efficiency.

### Key Features
- File filtering based on type/size
- Disk and memory storage options
- Limits on file size and field sizes
- Customizable storage engines

### Basic Implementation
```javascript
const multer = require('multer');
const path = require('path');

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|pdf/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  
  if (extname && mimetype) {
    return cb(null, true);
  }
  cb('Error: File type not allowed!');
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: fileFilter
});

// Usage in Express
app.post('/upload', upload.single('file'), (req, res) => {
  // req.file contains file information
  res.json({ 
    message: 'File uploaded successfully',
    file: req.file 
  });
});
```

### Advanced Configuration
```javascript
// Multiple file uploads with different fields
const uploadMultiple = upload.fields([
  { name: 'avatar', maxCount: 1 },
  { name: 'gallery', maxCount: 8 }
]);

// Array of files with same field name
const uploadArray = upload.array('documents', 10);

// Memory storage for processing before upload to cloud
const memoryStorage = multer.memoryStorage();
const uploadMemory = multer({ storage: memoryStorage });
```

### Best Practices
1. Always validate file types on server-side (not just client-side)
2. Implement proper error handling
3. Set appropriate file size limits
4. Sanitize file names to prevent path traversal attacks
5. Consider stream processing for large files

---

## 2. Busboy {#busboy}

### Overview
Busboy is a low-level streaming parser for HTML form data, specifically for `multipart/form-data`. Multer is built on top of Busboy, but sometimes direct Busboy usage is needed for more control.

### When to Use Busboy Instead of Multer
- When you need fine-grained control over parsing
- When handling extremely large files (streaming processing)
- When you want to avoid disk writes entirely
- Custom multipart parsing requirements

### Direct Busboy Implementation
```javascript
const http = require('http');
const busboy = require('busboy');

const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    const bb = busboy({ 
      headers: req.headers,
      limits: {
        fileSize: 10 * 1024 * 1024 // 10MB
      }
    });
    
    const files = [];
    const fields = [];
    
    // Handle file uploads
    bb.on('file', (fieldname, file, info) => {
      const { filename, encoding, mimeType } = info;
      const chunks = [];
      
      file.on('data', (chunk) => {
        chunks.push(chunk);
      });
      
      file.on('end', () => {
        const buffer = Buffer.concat(chunks);
        files.push({
          fieldname,
          filename,
          encoding,
          mimeType,
          size: buffer.length,
          buffer
        });
      });
    });
    
    // Handle text fields
    bb.on('field', (fieldname, val) => {
      fields.push({ fieldname, val });
    });
    
    // Handle errors
    bb.on('error', (err) => {
      console.error('Busboy error:', err);
      res.statusCode = 500;
      res.end('Upload error');
    });
    
    // Handle finish
    bb.on('finish', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ fields, files }));
    });
    
    req.pipe(bb);
  }
});

server.listen(3000);
```

### Streaming File Processing Example
```javascript
const { createWriteStream } = require('fs');
const { pipeline } = require('stream/promises');

bb.on('file', async (fieldname, file, info) => {
  // Stream directly to disk or cloud storage
  const writeStream = createWriteStream(`./uploads/${info.filename}`);
  
  try {
    await pipeline(file, writeStream);
    console.log(`File ${info.filename} uploaded successfully`);
  } catch (err) {
    console.error('Stream error:', err);
  }
});
```

### Advantages Over Multer
1. More memory efficient for large files
2. Better error handling granularity
3. Ability to abort parsing mid-stream
4. Custom event-driven architecture

---

## 3. Cloudinary Upload {#cloudinary-upload}

### Overview
Cloudinary is a cloud-based image and video management service with powerful transformation capabilities.

### Setup and Configuration
```javascript
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');

// Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
```

### Upload Methods

#### 1. Direct Upload from Server
```javascript
// Upload from local file path
const uploadResult = await cloudinary.uploader.upload(
  'local/image.jpg',
  {
    folder: 'user_uploads',
    public_id: 'custom_filename',
    resource_type: 'auto',
    transformation: [
      { width: 800, height: 600, crop: 'limit' },
      { quality: 'auto' }
    ]
  }
);
```

#### 2. Upload from Buffer/Memory
```javascript
const uploadFromBuffer = async (buffer) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'documents',
        resource_type: 'raw'
      },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    
    streamifier.createReadStream(buffer).pipe(uploadStream);
  });
};
```

#### 3. Upload from URL
```javascript
const uploadFromUrl = async (url) => {
  return await cloudinary.uploader.upload(url, {
    folder: 'external_sources',
    fetch_format: 'auto',
    quality: 'auto'
  });
};
```

#### 4. Large File/Video Upload
```javascript
// For files larger than 100MB
const uploadLargeFile = async (filePath) => {
  return await cloudinary.uploader.upload_large(filePath, {
    resource_type: 'video',
    chunk_size: 6000000, // 6MB chunks
    folder: 'videos',
    eager: [
      { width: 300, height: 300, crop: 'pad', audio_codec: 'none' },
      { width: 160, height: 100, crop: 'crop', gravity: 'south', audio_codec: 'none' }
    ]
  });
};
```

### Advanced Features

#### 1. Image Transformations on Upload
```javascript
const transformedUpload = await cloudinary.uploader.upload('image.jpg', {
  transformation: [
    { width: 500, height: 500, gravity: 'face', crop: 'thumb' },
    { radius: 'max' },
    { effect: 'sharpen:100' },
    { background: 'rgb:ffffff' }
  ],
  eager: [
    { width: 200, crop: 'scale' },
    { width: 100, crop: 'scale' }
  ]
});
```

#### 2. Secure Upload with Signatures
```javascript
const generateSignature = (paramsToSign) => {
  const signature = cloudinary.utils.api_sign_request(
    paramsToSign,
    process.env.CLOUDINARY_API_SECRET
  );
  return signature;
};

// Client-side can use this signature for direct uploads
```

#### 3. Tagging and Categorization
```javascript
const uploadWithTags = await cloudinary.uploader.upload('image.jpg', {
  tags: ['profile', 'user_123', 'verified'],
  context: {
    caption: 'User profile picture',
    alt: 'Profile image for user 123'
  },
  categorization: 'google_tagging',
  auto_tagging: 0.7
});
```

### Best Practices
1. Use appropriate resource_type (auto, image, video, raw)
2. Implement upload presets for consistency
3. Use eager transformations for frequently accessed variants
4. Implement proper error handling and retry logic
5. Set appropriate timeout for large files

---

## 4. S3 File Upload {#s3-file-upload}

### Overview
Amazon S3 (Simple Storage Service) is an object storage service offering industry-leading scalability, data availability, security, and performance.

### Setup and Configuration
```javascript
const AWS = require('aws-sdk');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// Configure AWS SDK
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION
});

const s3 = new AWS.S3();
```

### Upload Methods

#### 1. Basic Upload
```javascript
const uploadToS3 = async (fileBuffer, fileName, mimeType) => {
  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: `uploads/${uuidv4()}-${fileName}`,
    Body: fileBuffer,
    ContentType: mimeType,
    ACL: 'private', // or 'public-read' based on requirements
    Metadata: {
      uploadedBy: 'user_123',
      originalName: fileName
    }
  };

  try {
    const data = await s3.upload(params).promise();
    return {
      url: data.Location,
      key: data.Key,
      etag: data.ETag
    };
  } catch (error) {
    console.error('S3 Upload Error:', error);
    throw error;
  }
};
```

#### 2. Multipart Upload for Large Files
```javascript
const multipartUpload = async (filePath, fileName) => {
  const fileStream = fs.createReadStream(filePath);
  
  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: `large-files/${fileName}`,
    Body: fileStream
  };

  const options = {
    partSize: 10 * 1024 * 1024, // 10MB parts
    queueSize: 4 // Number of parallel uploads
  };

  return await s3.upload(params, options).promise();
};
```

#### 3. Stream Upload (No Disk Storage)
```javascript
const streamUpload = (req, res) => {
  const passThrough = new stream.PassThrough();
  const key = `stream-uploads/${Date.now()}-${req.headers['x-filename']}`;
  
  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: key,
    Body: passThrough,
    ContentType: req.headers['content-type']
  };

  s3.upload(params, (err, data) => {
    if (err) {
      console.error('Stream upload error:', err);
      res.status(500).send('Upload failed');
    } else {
      res.json({ 
        message: 'Upload successful',
        key: data.Key,
        url: data.Location 
      });
    }
  });

  req.pipe(passThrough);
};
```

#### 4. Upload with Server-Side Encryption
```javascript
const uploadWithEncryption = async (buffer, fileName) => {
  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: `encrypted/${fileName}`,
    Body: buffer,
    ServerSideEncryption: 'AES256', // or 'aws:kms'
    // For KMS:
    // SSEKMSKeyId: process.env.KMS_KEY_ID,
    // ServerSideEncryption: 'aws:kms'
  };

  return await s3.upload(params).promise();
};
```

### Advanced Features

#### 1. Upload with Progress Tracking
```javascript
const uploadWithProgress = (fileBuffer, fileName) => {
  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: `uploads/${fileName}`,
    Body: fileBuffer
  };

  const options = {
    partSize: 5 * 1024 * 1024,
    queueSize: 1 // For better progress tracking
  };

  const upload = s3.upload(params, options);

  upload.on('httpUploadProgress', (progress) => {
    const percentage = Math.round((progress.loaded / progress.total) * 100);
    console.log(`Upload progress: ${percentage}%`);
    // Emit progress to client via WebSocket or SSE
  });

  return upload.promise();
};
```

#### 2. Upload with Lifecycle Policies
```javascript
const uploadWithLifecycle = async (buffer, fileName) => {
  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: `temp-uploads/${fileName}`,
    Body: buffer,
    // Set expiration headers
    Expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    // Or use tags for lifecycle rules
    Tagging: 'type=temporary&deleteAfter=7days'
  };

  return await s3.upload(params).promise();
};
```

#### 3. Concurrent Batch Uploads
```javascript
const uploadMultipleFiles = async (files) => {
  const uploadPromises = files.map(file => {
    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: `batch/${Date.now()}-${file.originalname}`,
      Body: file.buffer,
      ContentType: file.mimetype
    };
    return s3.upload(params).promise();
  });

  const results = await Promise.allSettled(uploadPromises);
  
  return results.map((result, index) => {
    if (result.status === 'fulfilled') {
      return { 
        success: true, 
        key: result.value.Key,
        fileName: files[index].originalname 
      };
    } else {
      return { 
        success: false, 
        fileName: files[index].originalname,
        error: result.reason.message 
      };
    }
  });
};
```

### S3 Upload Best Practices
1. **Use IAM Roles** instead of access keys when possible
2. **Implement retry logic** with exponential backoff
3. **Use multipart upload** for files > 100MB
4. **Enable versioning** for important buckets
5. **Implement lifecycle policies** for cost optimization
6. **Use appropriate storage classes** (Standard, Intelligent-Tiering, Glacier)
7. **Enable encryption** (SSE-S3, SSE-KMS, or SSE-C)
8. **Set up CloudTrail** for audit logging
9. **Implement CORS** for browser-based uploads
10. **Use bucket policies** for fine-grained access control

### Error Handling and Monitoring
```javascript
class S3UploadService {
  constructor() {
    this.s3 = new AWS.S3({
      maxRetries: 3,
      retryDelayOptions: { base: 300 },
      httpOptions: { timeout: 60000 }
    });
  }

  async uploadWithRetry(params, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await this.s3.upload(params).promise();
      } catch (error) {
        if (attempt === maxRetries) throw error;
        
        if (error.code === 'RequestTimeout' || 
            error.code === 'SlowDown' || 
            error.code === 'ServiceUnavailable') {
          
          // Exponential backoff
          const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
        throw error;
      }
    }
  }
}
```

### Cost Optimization Strategies
1. **Use S3 Transfer Acceleration** for geographically distant users
2. **Implement client-side compression** before upload
3. **Use Intelligent-Tiering** for unpredictable access patterns
4. **Set up S3 Analytics** to optimize storage classes
5. **Implement data lifecycle rules** to archive/delete old files

### Security Considerations
1. **Enable bucket encryption** at rest
2. **Use bucket policies** and ACLs appropriately
3. **Implement presigned URLs** for temporary access
4. **Enable MFA Delete** for sensitive buckets
5. **Use VPC Endpoints** for private network access
6. **Regularly audit S3 access logs**

---

## 5. Pre-signed URLs {#pre-signed-urls}

### Overview
Pre-signed URLs provide temporary access to S3 objects without requiring AWS credentials. They're useful for secure direct uploads/downloads from client applications.

### Types of Pre-signed URLs

#### 1. Pre-signed PUT URL (Client-side Upload)
```javascript
const generatePresignedUploadUrl = async (fileName, contentType) => {
  const key = `user-uploads/${uuidv4()}-${fileName}`;
  
  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: key,
    Expires: 3600, // URL expires in 1 hour
    ContentType: contentType,
    // Additional constraints
    Metadata: {
      uploadedBy: 'user_123'
    }
  };

  try {
    const url = await s3.getSignedUrlPromise('putObject', params);
    return {
      uploadUrl: url,
      key: key,
      publicUrl: `https://${process.env.S3_BUCKET_NAME}.s3.amazonaws.com/${key}`
    };
  } catch (error) {
    console.error('Error generating presigned URL:', error);
    throw error;
  }
};
```

#### 2. Pre-signed GET URL (Client-side Download)
```javascript
const generatePresignedDownloadUrl = async (objectKey, expiresIn = 300) => {
  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: objectKey,
    Expires: expiresIn, // Default 5 minutes
    // Optional: Force download with specific filename
    ResponseContentDisposition: `attachment; filename="${objectKey.split('/').pop()}"`,
    // Optional: Override content type
    // ResponseContentType: 'application/octet-stream'
  };

  return await s3.getSignedUrlPromise('getObject', params);
};
```

### Advanced Pre-signed URL Features

#### 1. Upload with Conditions
```javascript
const generateConditionalUploadUrl = async (fileName) => {
  const conditions = [
    ['content-length-range', 1024, 10485760], // 1KB to 10MB
    ['starts-with', '$Content-Type', 'image/'],
    ['eq', '$x-amz-meta-userid', 'user_123']
  ];

  const params = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: `uploads/${fileName}`,
    Expires: 3600,
    Conditions: conditions,
    Fields: {
      'Content-Type': 'image/jpeg',
      'x-amz-meta-userid': 'user_123',
      'success_action_redirect': 'https://app.example.com/success'
    }
  };

  return s3.createPresignedPost(params);
};
```

#### 2. Multi-part Upload with Pre-signed URLs
```javascript
const initiateMultipartUploadWithPresignedUrls = async (fileName, fileSize) => {
  // 1. Initiate multipart upload
  const multipartParams = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: `large-files/${fileName}`,
    ContentType: 'application/octet-stream'
  };

  const multipartData = await s3.createMultipartUpload(multipartParams).promise();
  const uploadId = multipartData.UploadId;

  // 2. Generate presigned URLs for each part
  const partSize = 5 * 1024 * 1024; // 5MB parts
  const numParts = Math.ceil(fileSize / partSize);
  const partUrls = [];

  for (let partNumber = 1; partNumber <= numParts; partNumber++) {
    const urlParams = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: `large-files/${fileName}`,
      UploadId: uploadId,
      PartNumber: partNumber,
      Expires: 3600
    };

    const presignedUrl = await s3.getSignedUrlPromise('uploadPart', urlParams);
    partUrls.push({
      partNumber,
      url: presignedUrl,
      start: (partNumber - 1) * partSize,
      end: Math.min(partNumber * partSize, fileSize) - 1
    });
  }

  return {
    uploadId,
    key: multipartParams.Key,
    partUrls
  };
};
```

### Security Best Practices

#### 1. URL Validation Middleware
```javascript
const validatePresignedUrl = (req, res, next) => {
  const { key, expires, signature } = req.query;
  
  // Validate expiration
  if (Date.now() / 1000 > parseInt(expires)) {
    return res.status(403).json({ error: 'URL has expired' });
  }

  // Validate signature (simplified example)
  const expectedSignature = generateSignature(key, expires);
  if (signature !== expectedSignature) {
    return res.status(403).json({ error: 'Invalid signature' });
  }

  next();
};
```

#### 2. Rate Limiting for URL Generation
```javascript
const rateLimit = require('express-rate-limit');

const presignedUrlLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many URL generation requests'
});

app.use('/generate-presigned-url', presignedUrlLimiter);
```

#### 3. Audit Logging
```javascript
const logPresignedUrlAccess = async (urlData, action, userId, ip) => {
  await auditLog.create({
    action,
    resource: urlData.key,
    userId,
    ipAddress: ip,
    metadata: {
      expires: urlData.expires,
      timestamp: new Date(),
      userAgent: req.headers['user-agent']
    }
  });
};
```

### Client-Side Implementation Example
```javascript
// React/JavaScript client-side upload using presigned URL
async function uploadFileToS3(file, presignedUrl) {
  const xhr = new XMLHttpRequest();
  
  xhr.open('PUT', presignedUrl);
  xhr.setRequestHeader('Content-Type', file.type);
  
  // Add progress tracking
  xhr.upload.onprogress = (event) => {
    if (event.lengthComputable) {
      const percentComplete = (event.loaded / event.total) * 100;
      console.log(`Upload progress: ${percentComplete.toFixed(2)}%`);
    }
  };

  return new Promise((resolve, reject) => {
    xhr.onload = () => {
      if (xhr.status === 200) {
        resolve(xhr.responseURL.split('?')[0]);
      } else {
        reject(new Error(`Upload failed: ${xhr.statusText}`));
      }
    };
    
    xhr.onerror = () => reject(new Error('Network error'));
    xhr.send(file);
  });
}
```

### Common Use Cases and Patterns

#### 1. Secure Document Sharing
```javascript
class SecureDocumentService {
  async generateShareableLink(documentId, userId, expiresInHours = 24) {
    const document = await db.documents.findById(documentId);
    
    // Verify user has permission
    if (!this.hasPermission(userId, document)) {
      throw new Error('Unauthorized');
    }

    const presignedUrl = await this.generatePresignedDownloadUrl(
      document.s3Key,
      expiresInHours * 3600
    );

    // Track usage
    await this.logDocumentAccess(documentId, userId, 'share_link_created');

    return {
      url: presignedUrl,
      expiresAt: new Date(Date.now() + expiresInHours * 3600 * 1000),
      documentName: document.name
    };
  }
}
```

#### 2. Bulk Export with Pre-signed URLs
```javascript
async function generateBulkExportUrls(userId, fileKeys) {
  const urls = await Promise.all(
    fileKeys.map(async (key) => {
      const url = await generatePresignedDownloadUrl(key, 3600); // 1 hour
      return { key, url };
    })
  );

  // Create a manifest file
  const manifest = {
    userId,
    generatedAt: new Date().toISOString(),
    files: urls.map(u => u.key)
  };

  // Upload manifest to S3 and generate its presigned URL
  const manifestUrl = await uploadManifestAndGetUrl(manifest);

  return {
    manifestUrl,
    files: urls
  };
}
```

#### 3. Direct Browser Upload with Progress
```javascript
// Server-side
app.post('/initiate-upload', async (req, res) => {
  const { fileName, fileSize, fileType } = req.body;
  
  const { uploadUrl, key } = await generatePresignedUploadUrl(
    fileName,
    fileType
  );

  // Return upload instructions to client
  res.json({
    uploadUrl,
    key,
    chunkSize: 5 * 1024 * 1024, // 5MB chunks for progress tracking
    maxFileSize: 100 * 1024 * 1024 // 100MB limit
  });
});
```

### Performance Optimization

#### 1. Caching Pre-signed URLs
```javascript
const NodeCache = require('node-cache');
const urlCache = new NodeCache({ stdTTL: 300 }); // 5 minute TTL

async function getCachedPresignedUrl(key, operation = 'getObject') {
  const cacheKey = `${operation}:${key}`;
  let url = urlCache.get(cacheKey);
  
  if (!url) {
    url = await generatePresignedDownloadUrl(key);
    urlCache.set(cacheKey, url);
  }
  
  return url;
}
```

#### 2. Batch URL Generation
```javascript
async function batchGeneratePresignedUrls(keys, expiresIn = 300) {
  const urlPromises = keys.map(key =>
    s3.getSignedUrlPromise('getObject', {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
      Expires: expiresIn
    })
  );

  const urls = await Promise.all(urlPromises);
  
  return keys.reduce((acc, key, index) => {
    acc[key] = urls[index];
    return acc;
  }, {});
}
```

### Security Considerations

1. **Short Expiration Times**: Keep URLs valid for the minimum necessary time
2. **IP Restriction**: Optionally restrict URLs to specific IP ranges
3. **Usage Limits**: Implement rate limiting on URL generation
4. **Audit Logging**: Log all URL generation and usage
5. **HTTPS Only**: Generate URLs for HTTPS only
6. **Signature Validation**: Always validate signatures server-side if needed
7. **One-time Use**: Consider implementing one-time-use URLs for sensitive data

### Error Handling
```javascript
class PresignedUrlService {
  async generateSecureUrl(key, operation, options = {}) {
    try {
      const defaultParams = {
        Bucket: process.env.S3_BUCKET_NAME,
        Key: key,
        Expires: options.expiresIn || 300
      };

      // Add operation-specific params
      const params = this.addOperationParams(defaultParams, operation, options);

      // Generate URL
      const url = await s3.getSignedUrlPromise(operation, params);

      // Log generation
      await this.auditLog('generate', key, options.userId);

      return url;

    } catch (error) {
      console.error('Failed to generate presigned URL:', error);
      
      // Handle specific S3 errors
      if (error.code === 'NoSuchKey') {
        throw new Error('Requested file does not exist');
      }
      
      if (error.code === 'AccessDenied') {
        throw new Error('Access denied to generate URL');
      }
      
      throw new Error('Failed to generate secure URL');
    }
  }
}
```

---

## 6. Local Storage Structure {#local-storage-structure}

### Overview
A well-organized local storage structure is crucial for maintainability, security, and performance, even when using cloud storage for production.

### Recommended Directory Structure
```
uploads/
├── temp/                    # Temporary files (auto-cleaned)
│   ├── uploads/            # In-progress uploads
│   └── processing/         # Files being processed
├── persistent/             # Permanent local storage
│   ├── users/             # User-uploaded content
│   │   ├── avatars/       # User profile pictures
│   │   ├── documents/     # User documents
│   │   └── media/         # User media files
│   ├── system/            # System-generated files
│   │   ├── backups/       # Database backups
│   │   ├── logs/          # Application logs
│   │   └── cache/         # Cached files
│   └── shared/            # Shared across users
│       ├── templates/     # Document templates
│       ├── assets/        # Static assets
│       └── exports/       # Exported data
├── secure/                 # Encrypted/secure storage
│   ├── private/           # Private user data
│   └── sensitive/         # Sensitive documents
└── archive/               # Archived/old files
    ├── year-2023/
    ├── year-2024/
    └── retention-log/     # Log of archived/deleted files
```

### Implementation Example

#### 1. Storage Service Class
```javascript
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class LocalStorageService {
  constructor(basePath = './uploads') {
    this.basePath = path.resolve(basePath);
    this.initStorageStructure();
  }

  async initStorageStructure() {
    const directories = [
      'temp/uploads',
      'temp/processing',
      'persistent/users/avatars',
      'persistent/users/documents',
      'persistent/users/media',
      'persistent/system/backups',
      'persistent/system/logs',
      'persistent/system/cache',
      'persistent/shared/templates',
      'persistent/shared/assets',
      'persistent/shared/exports',
      'secure/private',
      'secure/sensitive',
      'archive/retention-log'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(this.basePath, dir), { recursive: true });
    }

    // Create .gitignore to exclude uploads from version control
    const gitignoreContent = `# Ignore uploaded files
*
!.gitignore
!README.md
`;
    await fs.writeFile(
      path.join(this.basePath, '.gitignore'),
      gitignoreContent
    );
  }

  async saveFile(fileBuffer, category, userId = null, options = {}) {
    const fileName = options.fileName || this.generateUniqueFileName();
    const filePath = this.getFilePath(category, userId, fileName);
    
    // Ensure directory exists
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    
    // Save file
    await fs.writeFile(filePath, fileBuffer);
    
    // Set permissions (Unix-based systems)
    if (options.permissions) {
      await fs.chmod(filePath, options.permissions);
    }

    // Log metadata
    await this.logFileMetadata({
      filePath,
      category,
      userId,
      fileName,
      size: fileBuffer.length,
      uploadedAt: new Date().toISOString()
    });

    return {
      path: filePath,
      url: this.getFileUrl(category, userId, fileName),
      fileName,
      size: fileBuffer.length
    };
  }

  generateUniqueFileName(originalName = 'file') {
    const timestamp = Date.now();
    const randomString = crypto.randomBytes(8).toString('hex');
    const extension = path.extname(originalName) || '';
    const name = path.basename(originalName, extension);
    
    return `${name}-${timestamp}-${randomString}${extension}`;
  }

  getFilePath(category, userId, fileName) {
    const safeUserId = userId ? this.sanitizePath(userId.toString()) : 'anonymous';
    const safeFileName = this.sanitizePath(fileName);
    
    const categoryMap = {
      avatar: `persistent/users/avatars/${safeUserId}`,
      document: `persistent/users/documents/${safeUserId}`,
      media: `persistent/users/media/${safeUserId}`,
      template: 'persistent/shared/templates',
      asset: 'persistent/shared/assets',
      backup: 'persistent/system/backups',
      log: 'persistent/system/logs',
      cache: 'persistent/system/cache',
      export: 'persistent/shared/exports',
      temp: 'temp/uploads',
      secure: `secure/private/${safeUserId}`
    };

    const baseDir = categoryMap[category] || 'persistent/shared';
    return path.join(this.basePath, baseDir, safeFileName);
  }

  sanitizePath(input) {
    // Remove path traversal attempts
    return input
      .replace(/\.\./g, '')
      .replace(/\//g, '_')
      .replace(/\\/g, '_')
      .replace(/[^a-zA-Z0-9._-]/g, '');
  }

  getFileUrl(category, userId, fileName) {
    const relativePath = path.relative(
      this.basePath,
      this.getFilePath(category, userId, fileName)
    );
    
    return `/uploads/${relativePath.replace(/\\/g, '/')}`;
  }

  async logFileMetadata(metadata) {
    const logFile = path.join(this.basePath, 'persistent/system/logs/file-metadata.jsonl');
    const logEntry = JSON.stringify({
      ...metadata,
      loggedAt: new Date().toISOString()
    }) + '\n';
    
    await fs.appendFile(logFile, logEntry, 'utf8');
  }
}
```

#### 2. Express Middleware for File Serving
```javascript
const express = require('express');
const path = require('path');

class FileServerMiddleware {
  constructor(uploadsPath = './uploads') {
    this.uploadsPath = path.resolve(uploadsPath);
    this.router = express.Router();
    this.setupRoutes();
  }

  setupRoutes() {
    // Public access for certain directories
    this.router.use('/public', express.static(
      path.join(this.uploadsPath, 'persistent/shared/assets'),
      { maxAge: '1y' } // Long cache for assets
    ));

    // User content with authentication
    this.router.use('/users/:userId/:category', this.authenticateUser.bind(this));
    this.router.use('/users/:userId/:category', express.static(
      path.join(this.uploadsPath, 'persistent/users')
    ));

    // Protected access with token validation
    this.router.get('/secure/:token/:filePath', this.serveSecureFile.bind(this));
  }

  async authenticateUser(req, res, next) {
    const { userId, category } = req.params;
    
    // Verify user has access to this file
    const hasAccess = await this.verifyUserAccess(req.user.id, userId, category);
    
    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    next();
  }

  async serveSecureFile(req, res) {
    const { token, filePath } = req.params;
    
    // Validate token
    const isValid = await this.validateAccessToken(token, filePath);
    
    if (!isValid) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    const fullPath = path.join(this.uploadsPath, 'secure', filePath);
    
    // Check if file exists
    try {
      await fs.access(fullPath);
    } catch {
      return res.status(404).json({ error: 'File not found' });
    }

    // Serve file with appropriate headers
    res.sendFile(fullPath, {
      headers: {
        'Content-Disposition': 'inline', // or 'attachment' for download
        'Cache-Control': 'private, max-age=300' // 5 minutes cache for private files
      }
    });
  }

  getMiddleware() {
    return this.router;
  }
}
```

### Advanced Features

#### 1. File Processing Pipeline
```javascript
class FileProcessingPipeline {
  constructor() {
    this.processors = new Map();
    this.registerDefaultProcessors();
  }

  registerDefaultProcessors() {
    // Image processing
    this.registerProcessor('image', 'thumbnail', this.createThumbnail.bind(this));
    this.registerProcessor('image', 'optimize', this.optimizeImage.bind(this));
    this.registerProcessor('image', 'watermark', this.addWatermark.bind(this));

    // Document processing
    this.registerProcessor('document', 'compress', this.compressPDF.bind(this));
    this.registerProcessor('document', 'extract-text', this.extractText.bind(this));

    // Video processing
    this.registerProcessor('video', 'transcode', this.transcodeVideo.bind(this));
    this.registerProcessor('video', 'generate-thumbnail', this.generateVideoThumbnail.bind(this));
  }

  async processFile(filePath, operations) {
    const fileType = this.detectFileType(filePath);
    const results = {};

    for (const operation of operations) {
      const processor = this.processors.get(`${fileType}.${operation}`);
      
      if (processor) {
        try {
          results[operation] = await processor(filePath);
        } catch (error) {
          console.error(`Failed to process ${operation}:`, error);
          results[operation] = { error: error.message };
        }
      }
    }

    return results;
  }

  async createThumbnail(filePath) {
    const thumbnailsDir = path.join(path.dirname(filePath), 'thumbnails');
    await fs.mkdir(thumbnailsDir, { recursive: true });

    const sizes = [
      { width: 100, height: 100, suffix: 'xs' },
      { width: 300, height: 300, suffix: 'sm' },
      { width: 600, height: 600, suffix: 'md' },
      { width: 1200, height: 1200, suffix: 'lg' }
    ];

    const results = [];
    for (const size of sizes) {
      const outputPath = path.join(
        thumbnailsDir,
        `${path.basename(filePath, path.extname(filePath))}-${size.suffix}${path.extname(filePath)}`
      );

      // Use sharp or similar library for image processing
      await sharp(filePath)
        .resize(size.width, size.height, { fit: 'inside' })
        .toFile(outputPath);

      results.push({
        size: `${size.width}x${size.height}`,
        path: outputPath,
        url: this.getFileUrl(outputPath)
      });
    }

    return results;
  }
}
```

#### 2. Automated Cleanup Service
```javascript
class StorageCleanupService {
  constructor(storageService) {
    this.storageService = storageService;
    this.cleanupIntervals = new Map();
  }

  startScheduledCleanup() {
    // Clean temp files every hour
    this.scheduleCleanup('temp', '*/60 * * * *', this.cleanTempFiles.bind(this));
    
    // Clean old cache files daily at 2 AM
    this.scheduleCleanup('cache', '0 2 * * *', this.cleanCacheFiles.bind(this));
    
    // Archive old files monthly
    this.scheduleCleanup('archive', '0 3 1 * *', this.archiveOldFiles.bind(this));
  }

  async cleanTempFiles() {
    const tempDir = path.join(this.storageService.basePath, 'temp');
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    try {
      const files = await this.getFilesOlderThan(tempDir, maxAge);
      
      for (const file of files) {
        await fs.unlink(file.path);
        console.log(`Cleaned temp file: ${file.path}`);
      }

      return { cleaned: files.length, timestamp: new Date().toISOString() };
    } catch (error) {
      console.error('Failed to clean temp files:', error);
      throw error;
    }
  }

  async getFilesOlderThan(directory, maxAge) {
    const oldFiles = [];
    
    async function scanDir(currentDir) {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        
        if (entry.isDirectory()) {
          await scanDir(fullPath);
        } else {
          const stats = await fs.stat(fullPath);
          const fileAge = now - stats.mtimeMs;
          
          if (fileAge > maxAge) {
            oldFiles.push({
              path: fullPath,
              age: fileAge,
              size: stats.size,
              lastModified: stats.mtime
            });
          }
        }
      }
    }

    await scanDir(directory);
    return oldFiles;
  }

  async archiveOldFiles() {
    const archiveDir = path.join(this.storageService.basePath, 'archive');
    const year = new Date().getFullYear();
    const yearDir = path.join(archiveDir, `year-${year}`);
    
    await fs.mkdir(yearDir, { recursive: true });

    // Archive files older than 1 year from persistent storage
    const persistentDir = path.join(this.storageService.basePath, 'persistent');
    const oneYearAgo = Date.now() - (365 * 24 * 60 * 60 * 1000);
    
    const oldFiles = await this.getFilesOlderThan(persistentDir, oneYearAgo);
    
    for (const file of oldFiles) {
      const relativePath = path.relative(this.storageService.basePath, file.path);
      const archivePath = path.join(yearDir, relativePath);
      
      // Ensure directory exists in archive
      await fs.mkdir(path.dirname(archivePath), { recursive: true });
      
      // Move file to archive
      await fs.rename(file.path, archivePath);
      
      // Create symbolic link or placeholder in original location
      await fs.writeFile(
        file.path,
        `This file has been archived to: ${archivePath}\nArchived on: ${new Date().toISOString()}`
      );
    }

    return { archived: oldFiles.length, year };
  }
}
```

### Security Considerations

#### 1. File Upload Security
```javascript
class SecureUploadValidator {
  constructor() {
    this.allowedMimeTypes = new Set([
      'image/jpeg',
      'image/png',
      'image/gif',
      'application/pdf',
      'text/plain',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ]);

    this.maxFileSize = 10 * 1024 * 1024; // 10MB
    this.blockedExtensions = new Set([
      '.exe', '.bat', '.sh', '.php', '.js', '.py',
      '.jar', '.war', '.ear', '.dll', '.sys'
    ]);
  }

  async validateFile(fileBuffer, fileName, mimeType) {
    const validations = [
      this.validateFileSize(fileBuffer),
      this.validateMimeType(mimeType),
      this.validateFileName(fileName),
      this.validateFileContent(fileBuffer, mimeType)
    ];

    const results = await Promise.allSettled(validations);
    
    const errors = results
      .filter(result => result.status === 'rejected')
      .map(result => result.reason);

    if (errors.length > 0) {
      throw new Error(`File validation failed: ${errors.join(', ')}`);
    }

    return true;
  }

  async validateFileContent(buffer, mimeType) {
    // Check for magic numbers
    const magicNumbers = {
      'image/jpeg': Buffer.from([0xFF, 0xD8, 0xFF]),
      'image/png': Buffer.from([0x89, 0x50, 0x4E, 0x47]),
      'application/pdf': Buffer.from([0x25, 0x50, 0x44, 0x46])
    };

    const expectedMagic = magicNumbers[mimeType];
    if (expectedMagic && !buffer.slice(0, expectedMagic.length).equals(expectedMagic)) {
      throw new Error('File content does not match its MIME type');
    }

    // Scan for potentially malicious content
    if (this.containsMaliciousPatterns(buffer)) {
      throw new Error('File contains potentially malicious content');
    }

    return true;
  }

  containsMaliciousPatterns(buffer) {
    const bufferString = buffer.toString('latin1');
    const maliciousPatterns = [
      /<\?php/i,
      /<script.*?>.*?<\/script>/is,
      /javascript:/i,
      /onload=|onerror=|onclick=/i,
      /eval\(/i,
      /base64_decode\(/i
    ];

    return maliciousPatterns.some(pattern => pattern.test(bufferString));
  }
}
```

#### 2. Access Control Implementation
```javascript
class FileAccessController {
  constructor() {
    this.permissions = new Map();
  }

  async checkPermission(userId, filePath, action) {
    const fileMetadata = await this.getFileMetadata(filePath);
    
    if (!fileMetadata) {
      throw new Error('File not found');
    }

    // Check ownership
    if (fileMetadata.ownerId === userId) {
      return true; // Owners have full access
    }

    // Check shared permissions
    const sharedPermissions = fileMetadata.sharedWith?.[userId];
    if (sharedPermissions && sharedPermissions.includes(action)) {
      return true;
    }

    // Check role-based permissions
    const userRoles = await this.getUserRoles(userId);
    const roleHasAccess = userRoles.some(role => 
      this.roleHasPermission(role, filePath, action)
    );

    if (!roleHasAccess) {
      throw new Error(`User ${userId} does not have ${action} permission for ${filePath}`);
    }

    return true;
  }

  async setPermissions(filePath, permissions) {
    const metadata = await this.getFileMetadata(filePath) || {};
    metadata.sharedWith = metadata.sharedWith || {};
    metadata.sharedWith = { ...metadata.sharedWith, ...permissions };
    
    await this.updateFileMetadata(filePath, metadata);
  }

  async generateAccessToken(filePath, userId, expiresIn = 3600) {
    const payload = {
      filePath,
      userId,
      exp: Math.floor(Date.now() / 1000) + expiresIn,
      iat: Math.floor(Date.now() / 1000)
    };

    // Sign token
    const token = jwt.sign(payload, process.env.JWT_SECRET);
    
    // Store token for validation
    await this.storeAccessToken(token, payload);
    
    return token;
  }
}
```

### Performance Optimization

#### 1. File Caching Strategy
```javascript
class FileCacheManager {
  constructor(cacheDir = './uploads/persistent/system/cache') {
    this.cacheDir = cacheDir;
    this.maxCacheSize = 100 * 1024 * 1024; // 100MB
    this.cache = new Map();
    this.initCache();
  }

  async initCache() {
    await fs.mkdir(this.cacheDir, { recursive: true });
    await this.cleanOldCache();
  }

  async getCachedFile(key, generator) {
    const cacheKey = this.hashKey(key);
    const cachePath = path.join(this.cacheDir, cacheKey);

    // Check memory cache first
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey);
    }

    // Check disk cache
    try {
      const stats = await fs.stat(cachePath);
      const cachedData = await fs.readFile(cachePath);
      
      // Update memory cache
      this.cache.set(cacheKey, cachedData);
      
      return cachedData;
    } catch {
      // Not cached, generate and cache
      const data = await generator();
      
      // Cache to disk
      await fs.writeFile(cachePath, data);
      
      // Cache to memory
      this.cache.set(cacheKey, data);
      
      // Manage cache size
      await this.manageCacheSize();
      
      return data;
    }
  }

  async manageCacheSize() {
    const files = await fs.readdir(this.cacheDir);
    let totalSize = 0;
    const fileStats = [];

    for (const file of files) {
      const filePath = path.join(this.cacheDir, file);
      const stats = await fs.stat(filePath);
      
      totalSize += stats.size;
      fileStats.push({
        path: filePath,
        size: stats.size,
        mtime: stats.mtime
      });
    }

    // Remove oldest files if over limit
    if (totalSize > this.maxCacheSize) {
      fileStats.sort((a, b) => a.mtime - b.mtime);
      
      for (const file of fileStats) {
        await fs.unlink(file.path);
        totalSize -= file.size;
        
        if (totalSize <= this.maxCacheSize * 0.8) {
          break;
        }
      }
    }
  }
}
```

#### 2. Lazy Loading for Large Directories
```javascript
class LazyFileLoader {
  constructor(directory) {
    this.directory = directory;
    this.fileIndex = new Map();
    this.isIndexed = false;
  }

  async getFiles(page = 1, pageSize = 50) {
    if (!this.isIndexed) {
      await this.buildIndex();
    }

    const start = (page - 1) * pageSize;
    const end = start + pageSize;
    
    const files = Array.from(this.fileIndex.values())
      .sort((a, b) => b.mtime - a.mtime)
      .slice(start, end);

    return {
      files,
      page,
      pageSize,
      total: this.fileIndex.size,
      totalPages: Math.ceil(this.fileIndex.size / pageSize)
    };
  }

  async buildIndex() {
    const files = [];
    
    async function scanDir(currentDir) {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        
        if (entry.isDirectory()) {
          await scanDir(fullPath);
        } else {
          const stats = await fs.stat(fullPath);
          
          files.push({
            path: fullPath,
            name: entry.name,
            size: stats.size,
            mtime: stats.mtime,
            type: path.extname(entry.name).toLowerCase()
          });
        }
      }
    }

    await scanDir(this.directory);
    
    // Index files by various criteria
    for (const file of files) {
      this.fileIndex.set(file.path, file);
    }
    
    this.isIndexed = true;
  }
}
```

### Monitoring and Maintenance

#### 1. Storage Health Monitor
```javascript
class StorageHealthMonitor {
  constructor(storageService) {
    this.storageService = storageService;
    this.metrics = {
      totalFiles: 0,
      totalSize: 0,
      byCategory: {},
      byUser: {},
      lastScan: null
    };
  }

  async scanStorage() {
    const results = {
      totalFiles: 0,
      totalSize: 0,
      categories: {},
      users: {},
      errors: []
    };

    async function scanDirectory(dirPath, basePath) {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        if (entry.isDirectory()) {
          await scanDirectory(fullPath, basePath);
        } else {
          try {
            const stats = await fs.stat(fullPath);
            const relativePath = path.relative(basePath, fullPath);
            
            results.totalFiles++;
            results.totalSize += stats.size;
            
            // Categorize by directory
            const category = this.extractCategory(relativePath);
            results.categories[category] = results.categories[category] || { files: 0, size: 0 };
            results.categories[category].files++;
            results.categories[category].size += stats.size;
            
            // Extract user ID if present
            const userId = this.extractUserId(relativePath);
            if (userId) {
              results.users[userId] = results.users[userId] || { files: 0, size: 0 };
              results.users[userId].files++;
              results.users[userId].size += stats.size;
            }
          } catch (error) {
            results.errors.push({ path: fullPath, error: error.message });
          }
        }
      }
    }

    await scanDirectory.call(this, this.storageService.basePath, this.storageService.basePath);
    
    this.metrics = {
      ...results,
      lastScan: new Date().toISOString()
    };
    
    return results;
  }

  getHealthReport() {
    const report = {
      timestamp: new Date().toISOString(),
      ...this.metrics,
      health: this.calculateHealth()
    };

    // Check for potential issues
    const warnings = [];
    
    if (this.metrics.totalSize > 10 * 1024 * 1024 * 1024) { // 10GB
      warnings.push('Storage usage exceeds 10GB');
    }
    
    if (this.metrics.errors.length > 0) {
      warnings.push(`Found ${this.metrics.errors.length} file access errors`);
    }
    
    if (Object.keys(this.metrics.users).length > 1000) {
      warnings.push('Large number of users detected');
    }
    
    report.warnings = warnings;
    
    return report;
  }

  calculateHealth() {
    const errorRate = this.metrics.errors.length / Math.max(this.metrics.totalFiles, 1);
    const avgFileSize = this.metrics.totalSize / Math.max(this.metrics.totalFiles, 1);
    
    let score = 100;
    
    if (errorRate > 0.01) score -= 30;
    if (avgFileSize > 50 * 1024 * 1024) score -= 20; // Files too large
    if (Object.keys(this.metrics.categories).length < 3) score -= 10; // Not enough categorization
    
    return {
      score: Math.max(0, score),
      status: score >= 80 ? 'healthy' : score >= 60 ? 'warning' : 'critical'
    };
  }
}
```

### Best Practices Summary

1. **Directory Structure**: Organize files logically by type, user, and purpose
2. **Security**: Implement proper sanitization, validation, and access control
3. **Scalability**: Design for growth with proper categorization and archiving
4. **Maintenance**: Implement automated cleanup and monitoring
5. **Performance**: Use caching and lazy loading where appropriate
6. **Backup**: Regularly backup important files and metadata
7. **Monitoring**: Track storage usage, access patterns, and errors
8. **Documentation**: Maintain clear documentation of the storage structure
9. **Testing**: Test file operations, cleanup processes, and security measures
10. **Compliance**: Ensure storage practices comply with relevant regulations (GDPR, HIPAA, etc.)

---

## 7. Interview Questions {#interview-questions}

### Multer Interview Questions

#### Junior to Mid-Level
1. **Q:** What is Multer and when would you use it?
   **A:** Multer is a Node.js middleware for handling `multipart/form-data`, primarily used for uploading files. It's built on top of busboy and provides a higher-level API for file uploads with Express.

2. **Q:** How do you limit file size in Multer?
   **A:** Use the `limits` option: `limits: { fileSize: 5 * 1024 * 1024 }` for 5MB limit.

3. **Q:** What's the difference between `diskStorage` and `memoryStorage`?
   **A:** `diskStorage` saves files to disk, `memoryStorage` keeps files in memory as Buffer objects. Use memory for small files or when you need to process files before saving.

4. **Q:** How do you filter files by type in Multer?
   **A:** Use the `fileFilter` function to check file mimetype or extension.

#### Senior Level
5. **Q:** How would you handle concurrent file uploads with Multer?
   **A:** Implement connection pooling, use `upload.array()` with limits, implement rate limiting, and use stream processing for large files.

6. **Q:** Explain how you'd implement resumable uploads with Multer.
   **A:** Use chunked uploads, track upload progress, implement a checkpoint system, and handle partial file reassembly.

7. **Q:** What are the security considerations when using Multer?
   **A:** Validate file types server-side, sanitize filenames, set appropriate size limits, scan for malware, implement rate limiting, and use secure storage locations.

8. **Q:** How would you integrate Multer with cloud storage?
   **A:** Use `memoryStorage`, process the buffer in memory, then upload to cloud storage (S3, Cloudinary) using their SDKs.

### Busboy Interview Questions

#### Junior to Mid-Level
1. **Q:** What is Busboy and how does it differ from Multer?
   **A:** Busboy is a streaming parser for multipart form data. Multer is built on top of Busboy but provides a higher-level API. Busboy offers more control but requires more code.

2. **Q:** When would you use Busboy instead of Multer?
   **A:** When you need fine-grained control over parsing, handling very large files with streaming, or custom parsing logic.

3. **Q:** How do you handle file streams with Busboy?
   **A:** Listen to the 'file' event which provides a readable stream, then pipe it to a destination or process chunks.

#### Senior Level
4. **Q:** How would you implement progress tracking with Busboy?
   **A:** Track 'data' events on file streams, calculate bytes received, and emit progress updates via WebSocket or SSE.

5. **Q:** Explain how to abort a file upload mid-stream with Busboy.
   **A:** Destroy the request stream or close the connection, handle cleanup of partial data.

6. **Q:** How would you handle malformed multipart data with Busboy?
   **A:** Implement error event listeners, validate data structure, and implement graceful degradation.

### Cloudinary Interview Questions

#### Junior to Mid-Level
1. **Q:** What are the main advantages of using Cloudinary?
   **A:** Automatic image optimization, transformations, CDN delivery, responsive images, and video processing capabilities.

2. **Q:** How do you upload a file to Cloudinary from a Node.js server?
   **A:** Use `cloudinary.uploader.upload()` with file path or stream, or use the upload stream method for buffers.

3. **Q:** What are eager transformations?
   **A:** Transformations that are generated immediately on upload rather than on-the-fly, useful for frequently accessed variants.

#### Senior Level
4. **Q:** How would you implement a cost-effective Cloudinary strategy for a large media application?
   **A:** Use responsive breakpoints, implement lazy loading, use appropriate formats (WebP/AVIF), set up transformation presets, and implement caching strategies.

5. **Q:** Explain how you'd handle video uploads and processing at scale.
   **A:** Use async uploads with webhooks, implement chunked uploads for large videos, use eager transformations for common formats, and implement a queue system for processing.

6. **Q:** How would you migrate from local storage to Cloudinary with zero downtime?
   **A:** Implement dual-write strategy, create migration scripts with backoff retry logic, use CDN fallbacks, and implement gradual rollout.

### S3 File Upload Interview Questions

#### Junior to Mid-Level
1. **Q:** What is S3 and what are its main features?
   **A:** Amazon S3 is object storage with features like versioning, lifecycle policies, encryption, and cross-region replication.

2. **Q:** How do you handle large file uploads to S3?
   **A:** Use multipart upload for files > 100MB, implement chunking, and use the S3 Transfer Acceleration feature.

3. **Q:** What are S3 storage classes and when would you use each?
   **A:** Standard (frequent access), Intelligent-Tiering (unknown patterns), Standard-IA (infrequent), Glacier (archival), Deep Archive (long-term archival).

#### Senior Level
4. **Q:** How would you design a secure file upload system with S3?
   **A:** Implement server-side encryption (SSE-S3/KMS), use bucket policies, implement presigned URLs, enable access logging, and use VPC endpoints.

5. **Q:** Explain S3 consistency model and how it affects your application design.
   **A:** S3 offers read-after-write consistency for PUTs and eventual consistency for DELETEs and overwrite PUTs. Design for eventual consistency with retry logic.

6. **Q:** How would you implement a cost-effective S3 storage strategy?
   **A:** Use lifecycle policies, implement data tiering, use appropriate storage classes, enable S3 Intelligent-Tiering, and implement data compression.

7. **Q:** How do you handle S3 upload failures and implement retry logic?
   **A:** Implement exponential backoff, circuit breaker pattern, dead letter queues for failed uploads, and comprehensive error logging.

### Pre-signed URLs Interview Questions

#### Junior to Mid-Level
1. **Q:** What are pre-signed URLs and when would you use them?
   **A:** Temporary URLs that grant time-limited access to S3 objects without requiring AWS credentials. Used for secure direct uploads/downloads from client apps.

2. **Q:** How do you generate a pre-signed URL in Node.js?
   **A:** Use `s3.getSignedUrlPromise('getObject', params)` with bucket, key, and expiration parameters.

3. **Q:** What security considerations are there with pre-signed URLs?
   **A:** Short expiration times, HTTPS only, validate URLs server-side, implement rate limiting, and audit log access.

#### Senior Level
4. **Q:** How would you implement one-time-use pre-signed URLs?
   **A:** Store used tokens in a database or cache, validate on each access, and invalidate after use.

5. **Q:** Explain how to implement upload limits with pre-signed URLs.
   **A:** Use policy conditions with `content-length-range`, validate on server before generating URL, and implement server-side checks.

6. **Q:** How would you handle pre-signed URL revocation before expiration?
   **A:** Store active URLs in a cache/database, check validity on access, implement a revocation endpoint, or use S3 bucket policies.

7. **Q:** Design a system for sharing large files using pre-signed URLs with expiration and download limits.
   **A:** Generate URLs with expiration, track downloads in database, implement rate limiting, and provide email notifications.

### Local Storage Structure Interview Questions

#### Junior to Mid-Level
1. **Q:** Why is a good local storage structure important?
   **A:** For maintainability, security, scalability, performance, and ease of backup/restore operations.

2. **Q:** What are common security risks with local file storage?
   **A:** Path traversal attacks, insecure file permissions, storing sensitive data unencrypted, and lack of input validation.

3. **Q:** How do you prevent path traversal attacks?
   **A:** Sanitize filenames, use absolute paths with validation, restrict file system access, and implement proper access controls.

#### Senior Level
4. **Q:** Design a local storage system for a multi-tenant application.
   **A:** Implement tenant isolation, use encrypted storage for sensitive data, implement quota management, and separate by tenant ID in directory structure.

5. **Q:** How would you implement file versioning in local storage?
   **A:** Store versions in separate directories, maintain version metadata, implement cleanup policies, and provide rollback capabilities.

6. **Q:** Design a backup and recovery system for local file storage.
   **A:** Implement incremental backups, versioned backups, off-site replication, automated recovery testing, and monitoring.

7. **Q:** How would you migrate from local storage to cloud storage without downtime?
   **A:** Implement dual-write strategy, use symbolic links, implement gradual migration with monitoring, and maintain fallback capabilities.

---

## 8. Real-World Scenarios {#real-world-scenarios}

### Scenario 1: Social Media Platform

**Context:** You're building a social media platform where users can upload images, videos, and documents. The platform has 1M+ daily active users.

**Requirements:**
- Handle 10,000+ concurrent uploads
- Support files up to 1GB
- Generate multiple image thumbnails
- Apply watermarks to premium content
- Implement content moderation
- Ensure 99.9% availability

**Design Questions:**

1. **How would you architect the file upload system?**
   ```
   Answer: 
   - Use API Gateway with WebSocket for progress tracking
   - Implement S3 multipart upload with pre-signed URLs for direct uploads
   - Use SQS for async processing of uploaded files
   - Lambda functions for thumbnail generation and watermarking
   - CloudFront CDN for content delivery
   - Rekognition for content moderation
   - Implement circuit breakers and retry logic
   ```

2. **How would you handle video uploads and processing?**
   ```
   Answer:
   - Use S3 Transfer Acceleration for faster uploads
   - Implement chunked uploads with resumable capability
   - Use Elastic Transcoder for video processing
   - Generate multiple quality levels (240p, 360p, 720p, 1080p)
   - Extract thumbnails at key frames
   - Implement progress tracking via WebSocket
   ```

3. **How would you implement content moderation at scale?**
   ```
   Answer:
   - Use Rekognition for image/video analysis
   - Implement manual review queue for flagged content
   - Use Comprehend for text extraction and analysis
   - Implement user reputation system
   - Use S3 Object Lock for evidence preservation
   - Implement audit logging for compliance
   ```

### Scenario 2: Healthcare Document Management

**Context:** A healthcare application storing sensitive patient documents (medical records, scans, reports). Must be HIPAA compliant.

**Requirements:**
- HIPAA compliance
- Encryption at rest and in transit
- Access audit trails
- Document versioning
- Long-term retention (7+ years)
- Emergency access procedures

**Design Questions:**

1. **How would you design the storage architecture?**
   ```
   Answer:
   - Use S3 with SSE-KMS encryption
   - Implement VPC endpoints for private access
   - Use CloudTrail for audit logging
   - Implement S3 Object Lock for WORM compliance
   - Use Glacier Deep Archive for long-term retention
   - Implement client-side encryption for extra security
   ```

2. **How would you handle access control and audit trails?**
   ```
   Answer:
   - Implement ABAC (Attribute-Based Access Control)
   - Use temporary credentials via STS
   - Log all access attempts to CloudTrail
   - Implement break-glass emergency access
   - Regular access review audits
   - Integrate with hospital AD/LDAP
   ```

3. **How would you implement document versioning and retrieval?**
   ```
   Answer:
   - Enable S3 versioning
   - Maintain metadata in DynamoDB
   - Implement document lifecycle policies
   - Use S3 Select for partial retrieval
   - Implement search indexing
   - Create audit reports of document access
   ```

### Scenario 3: E-commerce Product Media

**Context:** Large e-commerce platform with millions of product images and videos. Need to support multiple vendors uploading their own media.

**Requirements:**
- Vendor-specific media management
- Automatic image optimization
- CDN delivery worldwide
- A/B testing for product images
- Media usage analytics
- Cost optimization

**Design Questions:**

1. **How would you handle vendor media uploads?**
   ```
   Answer:
   - Create vendor-specific S3 buckets or prefixes
   - Implement pre-signed URLs for direct uploads
   - Use S3 Batch Operations for bulk processing
   - Implement media validation (dimensions, format, size)
   - Create vendor portals with upload progress
   - Set vendor-specific quotas and limits
   ```

2. **How would you optimize media delivery globally?**
   ```
   Answer:
   - Use CloudFront with multiple origins
   - Implement Image Optimization at edge
   - Use Lambda@Edge for dynamic transformations
   - Implement cache policies per media type
   - Use Route53 latency-based routing
   - Monitor CDN performance metrics
   ```

3. **How would you implement A/B testing for product images?**
   ```
   Answer:
   - Store multiple image variants in S3
   - Use CloudFront cookies for variant selection
   - Implement analytics tracking per variant
   - Use S3 metadata for variant information
   - Create dashboard for A/B test results
   - Automate winning variant selection
   ```

### Scenario 4: Real-time Collaboration Platform

**Context:** A document collaboration platform like Google Docs where multiple users edit files simultaneously.

**Requirements:**
- Real-time file synchronization
- Conflict resolution
- Version history
- Offline editing support
- Large file support
- Cross-platform compatibility

**Design Questions:**

1. **How would you handle real-time file sync?**
   ```
   Answer:
   - Use WebSocket connections for real-time updates
   - Implement operational transformation or CRDTs
   - Use S3 for file storage with versioning
   - Implement delta updates to minimize data transfer
   - Use DynamoDB for real-time metadata
   - Implement presence detection
   ```

2. **How would you implement conflict resolution?**
   ```
   Answer:
   - Use vector clocks for version tracking
   - Implement automatic merge where possible
   - Create conflict resolution UI for manual merge
   - Store conflict versions for recovery
   - Implement user notification system
   - Maintain edit history with user attribution
   ```

3. **How would you support offline editing?**
   ```
   Answer:
   - Implement service worker for offline caching
   - Use IndexedDB for local storage
   - Implement sync queue for offline changes
   - Use background sync for uploads
   - Handle merge conflicts on reconnection
   - Provide offline status indication
   ```

### Scenario 5: IoT Device Data Upload

**Context:** Thousands of IoT devices uploading sensor data, images, and logs continuously.

**Requirements:**
- Handle high-frequency small file uploads
- Real-time processing pipeline
- Data aggregation
- Long-term storage for analytics
- Device management
- Cost-effective storage

**Design Questions:**

1. **How would you design the upload pipeline?**
   ```
   Answer:
   - Use IoT Core for device connectivity
   - Implement MQTT for efficient communication
   - Use Kinesis Data Streams for ingestion
   - Lambda for real-time processing
   - S3 for raw data storage
   - Athena for querying
   - Implement device health monitoring
   ```

2. **How would you optimize storage costs?**
   ```
   Answer:
   - Implement data compression before upload
   - Use S3 Intelligent-Tiering
   - Set lifecycle policies to move to Glacier
   - Aggregate small files into larger objects
   - Implement data deduplication
   - Use columnar formats (Parquet) for analytics
   ```

3. **How would you handle device failures and retries?**
   ```
   Answer:
   - Implement exponential backoff for retries
   - Store unsent data locally on devices
   - Use message queues for reliable delivery
   - Implement device health checks
   - Create alert system for failed devices
   - Provide over-the-air updates for fixes
   ```

### Scenario 6: Financial Document Processing

**Context:** Bank processing loan applications with thousands of documents daily.

**Requirements:**
- OCR processing
- Document classification
- Fraud detection
- Regulatory compliance
- Audit trails
- Fast retrieval

**Design Questions:**

1. **How would you process uploaded documents?**
   ```
   Answer:
   - Use Textract for OCR
   - Implement document classification with Comprehend
   - Use fraud detection algorithms
   - Store processed metadata in RDS
   - Implement workflow for manual review
   - Create processing status dashboard
   ```

2. **How would you ensure regulatory compliance?**
   ```
   Answer:
   - Implement S3 Object Lock for immutability
   - Use CloudTrail for audit logging
   - Encrypt all data with KMS
   - Implement access controls with IAM
   - Regular compliance audits
   - Data retention policies
   ```

3. **How would you implement fast document search?**
   ```
   Answer:
   - Use Elasticsearch for full-text search
   - Index OCR results and metadata
   - Implement faceted search
   - Use S3 Select for CSV/JSON queries
   - Cache frequent searches
   - Implement search analytics
   ```

These scenarios and questions cover a wide range of real-world challenges in file handling and storage systems. The key is to balance requirements for performance, security, cost, and maintainability while choosing the right tools and architecture for each specific use case.