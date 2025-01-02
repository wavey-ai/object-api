# Object API

A secure HTTP/3 and HTTP/2 compatible object storage API with presigned URL support.

The API interfaces with [store-stream](https://github.com/wavey-ai/store-stream) which handles the actual storage operations and S3 interactions.


## Features

- HTTP/3 (QUIC) and HTTP/2 support
- Presigned URL generation for secure temporary access
- Range request support for efficient partial content retrieval
- CORS-enabled for browser compatibility [TODO: config]
- TLS
- Identity provider integration for authentication [In Progress]
- Chunked upload support
- ETag support for caching

## API Endpoints

### GET /up
Health check endpoint.

### POST /presigned
Generates a presigned URL for temporary access. Requires authentication via identity provider.

Response: URL string with embedded authorization token

### GET /{bucket}/{object}
Retrieves an object from storage. Supports range requests via the `Range` header.

Headers:
- `Range`: Optional byte range specification (e.g., `bytes=0-1000`)
- `ETag`: Returned for caching

### POST /{bucket}/{object}
Uploads an object to storage. Requires either authentication or a valid presigned URL.

## Configuration

The API requires the following configuration:

```rust
ObjectApi::new(
    cert_pem_base64: String,   // TLS certificate in base64
    privkey_pem_base64: String, // TLS private key in base64 
    ssl_port: u16,             // Port for TLS connections
    idp_port: u16,             // Identity provider port
    storage: Arc<Storage>      // store-stream storage instance
)
```

## Dependencies

- `h3`: HTTP/3 protocol support
- `hyper`: HTTP/2 protocol support
- `tokio`: Async runtime
- `store-stream`: Underlying storage implementation
- `bytes`: Efficient byte buffer handling
- `tracing`: Logging and diagnostics

## Usage Example

```rust
let api = ObjectApi::new(
    cert_pem_base64,
    privkey_pem_base64,
    443,
    8080,
    storage
);

// Start the server
let shutdown_sender = api.start().await?;

// To shutdown gracefully
shutdown_sender.send(())?;
```

## License

MIT
