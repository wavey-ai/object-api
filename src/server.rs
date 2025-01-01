use crate::presigned::{generate_presigned_url, verify_presigned_url};
use anyhow::{anyhow, Result};
use bytes::Buf;
use bytes::Bytes;
use futures::stream::StreamExt;
use h3::server::RequestStream;
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};
use http::header::RANGE;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyStream, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_idp::client::get_profile;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use reqwest::Client;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use store_stream::Storage;
use svix_ksuid::*;
use tls_helpers::{load_certs_from_base64, load_keys_from_base64, tls_acceptor_from_base64};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{error, info};
use xxhash_rust::const_xxh3::xxh3_64 as const_xxh3;

const EXPIRY_SECONDS: u64 = 3600;
const ISSUE_PRESIGNED_URL_PATH: &str = "presigned";
const UP_PATH: &str = "up";

fn add_cors_headers<T>(res: &mut Response<T>) {
    let headers = res.headers_mut();
    headers.insert("access-control-allow-origin", "*".parse().unwrap());
    headers.insert(
        "access-control-allow-methods",
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    headers.insert("access-control-allow-headers", "*".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
}

fn with_cors_headers(builder: http::response::Builder) -> http::response::Builder {
    builder
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "*")
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .header(
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        )
}

pub struct ObjectApi {
    cert_pem_base64: String,
    privkey_pem_base64: String,
    ssl_port: u16,
    client: reqwest::Client,
    idp_port: u16,
    storage: Arc<Storage>,
}

impl ObjectApi {
    pub fn new(
        cert_pem_base64: String,
        privkey_pem_base64: String,
        ssl_port: u16,
        idp_port: u16,
        storage: Arc<Storage>,
    ) -> Self {
        Self {
            cert_pem_base64,
            privkey_pem_base64,
            ssl_port,
            client: Client::new(),
            idp_port,
            storage,
        }
    }

    pub async fn start(
        &self,
    ) -> Result<tokio::sync::watch::Sender<()>, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = watch::channel(());

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
        let tls_acceptor =
            tls_acceptor_from_base64(&self.cert_pem_base64, &self.privkey_pem_base64, false, true)?;

        info!("object server up at https://{}", addr);

        let client = self.client.clone();
        let idp_port = self.idp_port;
        let storage = self.storage.clone();

        let srv_h2 = {
            let mut shutdown_signal = rx.clone();
            async move {
                let incoming = TcpListener::bind(&addr).await.unwrap();
                let service = service_fn(move |req| {
                    handle_request_h2(req, client.clone(), idp_port, storage.clone())
                });

                loop {
                    tokio::select! {
                        _ = shutdown_signal.changed() => {
                            break;
                        }
                        result = incoming.accept() => {
                            let (tcp_stream, _remote_addr) = result.unwrap();
                            let tls_acceptor = tls_acceptor.clone();
                            let service = service.clone();

                            tokio::spawn(async move {
                                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                    Ok(tls_stream) => tls_stream,
                                    Err(err) => {
                                        error!("failed to perform tls handshake: {err:#}");
                                        return;
                                    }
                                };
                                if let Err(err) = ConnectionBuilder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls_stream), service)
                                    .await
                                {
                                    error!("failed to serve connection: {err:#}");
                                }
                            });
                        }
                    }
                }
            }
        };
        tokio::spawn(srv_h2);

        {
            let certs = load_certs_from_base64(&self.cert_pem_base64)?;
            let key = load_keys_from_base64(&self.privkey_pem_base64)?;
            let tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();

            let client = self.client.clone();
            let storage = self.storage.clone();
            let server_config =
                quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
            let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
            let endpoint = quinn::Endpoint::server(server_config, addr).unwrap();

            let srv_h3 = {
                let mut shutdown_signal = rx.clone();
                async move {
                    loop {
                        tokio::select! {
                            _ = shutdown_signal.changed() => {
                                break;
                            }
                            res = endpoint.accept() => {
                                if let Some(new_conn) = res {
                                    info!("New connection being attempted");
                                    let client = client.clone();
                                    let storage = storage.clone();
                                    tokio::spawn(async move {
                                        match new_conn.await {
                                            Ok(conn) => {
                                                let mut h3_conn = h3::server::builder()
                                                    .build(h3_quinn::Connection::new(conn))
                                                    .await
                                                    .unwrap();
                                                loop {
                                                    match h3_conn.accept().await {
                                                        Ok(Some((req, stream))) => {
                                                            let client = client.clone();
                                                            let storage = storage.clone();
                                                            tokio::spawn(async move {
                                                                if let Err(err) = handle_connection_h3(
                                                                    req,
                                                                    stream,
                                                                    client,
                                                                    idp_port,
                                                                    storage
                                                                ).await {
                                                                    error!("Failed to handle connection: {err:?}");
                                                                }
                                                            });
                                                        }
                                                        Ok(None) => {
                                                            break;
                                                        }
                                                        Err(err) => {
                                                            error!("error on accept {}", err);
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                error!("accepting connection failed: {:?}", err);
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            };
            tokio::spawn(srv_h3);
        }

        Ok(tx)
    }
}

async fn request_handler(
    method: &Method,
    headers: &http::HeaderMap,
    uri: &http::Uri,
    client: Client,
    idp_port: u16,
) -> Result<(
    http::response::Builder,
    Option<Bytes>,
    Option<(String, String)>,
)> {
    let mut res = http::Response::builder();
    let mut body = None;
    let mut bucket_obj: Option<(String, String)> = None;

    let keys: Vec<&str> = uri.path().split('/').filter(|s| !s.is_empty()).collect();

    match (method, keys.get(0)) {
        (&Method::GET, Some(&UP_PATH)) => {
            res = res.status(StatusCode::OK);
        }
        (&Method::POST, Some(&ISSUE_PRESIGNED_URL_PATH)) => {
            match get_profile(client, headers, idp_port).await {
                Ok(user) => {
                    let ksuid = Ksuid::new(None, None);
                    let path = format!("{}/{}", user.id(), ksuid);
                    match generate_presigned_url(&path, EXPIRY_SECONDS) {
                        Ok(query_string) => {
                            let base_url = "/";
                            let full_uri = Bytes::from(format!("{}?{}", base_url, query_string));
                            body = Some(full_uri);
                            res = res.status(StatusCode::OK);
                        }
                        Err(e) => {
                            error!("Error generating presigned URL: {}", e);
                            res = res.status(StatusCode::INTERNAL_SERVER_ERROR);
                        }
                    }
                }
                Err(_) => {
                    res = res.status(StatusCode::FORBIDDEN);
                }
            }
        }
        (&Method::GET, Some(_)) => {
            if keys.len() < 2 {
                res = res.status(StatusCode::BAD_REQUEST);
            } else {
                let bucket = keys[0].to_string();
                let object_key = keys[1..].join("/");
                bucket_obj = Some((bucket, object_key));
                res = res.status(StatusCode::OK);
            }
        }
        (&Method::POST, Some(_)) => {
            if keys.len() < 2 {
                res = res.status(StatusCode::BAD_REQUEST);
            } else {
                let bucket = keys[0].to_string();
                let object_key = keys[1..].join("/");
                if let Some(q) = uri.query() {
                    match verify_presigned_url(q) {
                        Ok(_key_from_query) => {
                            bucket_obj = Some((bucket, object_key));
                            res = res.status(StatusCode::OK);
                        }
                        Err(e) => {
                            error!("error verifying presigned url: {}", e);
                            res = res.status(StatusCode::FORBIDDEN);
                        }
                    }
                } else {
                    res = res.status(StatusCode::BAD_REQUEST);
                }
            }
        }
        (&Method::OPTIONS, _) => {
            res = res.status(StatusCode::NO_CONTENT);
        }
        (&Method::GET, None) => {
            res = res.status(StatusCode::NOT_FOUND);
        }
        (&Method::POST, None) => {
            res = res.status(StatusCode::BAD_REQUEST);
        }
        _ => {
            res = res.status(StatusCode::METHOD_NOT_ALLOWED);
        }
    }

    res = with_cors_headers(res);
    Ok((res, body, bucket_obj))
}

async fn handle_request_h2(
    req: Request<Incoming>,
    client: Client,
    idp_port: u16,
    storage: Arc<Storage>,
) -> Result<Response<Full<Bytes>>> {
    let (res, body, bucket_obj) =
        request_handler(req.method(), req.headers(), req.uri(), client, idp_port).await?;

    if let Some(b) = body {
        let mut response = res.body(Full::new(b)).unwrap();
        add_cors_headers(&mut response);
        return Ok(response);
    }

    match (req.method(), bucket_obj) {
        (&Method::GET, Some((bucket, key))) => {
            let range_header = req
                .headers()
                .get(RANGE)
                .and_then(|value| value.to_str().ok());
            let (range_start, range_end) = if let Some(range_str) = range_header {
                match parse_byte_range(range_str) {
                    Ok((start, end)) => (start, end),
                    Err(_) => {
                        let mut response = Response::builder()
                            .status(StatusCode::RANGE_NOT_SATISFIABLE)
                            .body(Full::new(Bytes::new()))
                            .unwrap();
                        add_cors_headers(&mut response);
                        return Ok(response);
                    }
                }
            } else {
                (0, None)
            };

            if let Some((bytes, hash)) =
                get_object(storage, &bucket, &key, range_start, range_end).await
            {
                let etag = format!("\"{:x}\"", hash);
                let mut response = res.header("ETag", etag).body(Full::new(bytes)).unwrap();
                add_cors_headers(&mut response);
                Ok(response)
            } else {
                let mut response = res
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                add_cors_headers(&mut response);
                Ok(response)
            }
        }
        (&Method::POST, Some((bucket, key))) => {
            let (tx, rx) = mpsc::channel(1);
            tokio::task::spawn(async move {
                if let Err(e) = storage.upload(&bucket, &key, rx).await {
                    error!("Error during upload: {:?}", e);
                }
            });

            let mut body_stream = BodyStream::new(req.into_body());
            while let Some(result) = body_stream.next().await {
                match result {
                    Ok(frame) => {
                        if let Some(chunk) = frame.into_data().ok() {
                            if tx.send(chunk).await.is_err() {
                                error!("Error sending chunk");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error reading chunk: {:?}", e);
                        break;
                    }
                }
            }
            let mut response = res.body(Full::new(Bytes::new())).unwrap();
            add_cors_headers(&mut response);
            Ok(response)
        }
        _ => {
            let mut response = res.body(Full::new(Bytes::new())).unwrap();
            add_cors_headers(&mut response);
            Ok(response)
        }
    }
}

async fn handle_connection_h3(
    req: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    client: Client,
    idp_port: u16,
    storage: Arc<Storage>,
) -> Result<()> {
    let (res, _, bucket_obj) =
        request_handler(req.method(), req.headers(), req.uri(), client, idp_port).await?;

    match (req.method(), bucket_obj) {
        (&Method::GET, Some((bucket, key))) => {
            let range_header = req
                .headers()
                .get(RANGE)
                .and_then(|value| value.to_str().ok());
            let (range_start, range_end) = if let Some(range_str) = range_header {
                match parse_byte_range(range_str) {
                    Ok((start, end)) => (start, end),
                    Err(_) => {
                        let response = with_cors_headers(Response::builder())
                            .status(StatusCode::RANGE_NOT_SATISFIABLE)
                            .body(())
                            .unwrap();
                        stream.send_response(response).await?;
                        return Ok(());
                    }
                }
            } else {
                (0, None)
            };

            if let Some((bytes, hash)) =
                get_object(storage, &bucket, &key, range_start, range_end).await
            {
                let etag = format!("\"{:x}\"", hash);
                let response = res.header("ETag", etag).body(()).unwrap();
                stream.send_response(response).await?;
                stream.send_data(bytes).await?;
            } else {
                let response = with_cors_headers(Response::builder())
                    .status(StatusCode::NOT_FOUND)
                    .body(())
                    .unwrap();
                stream.send_response(response).await?;
            }
        }
        (&Method::POST, Some((bucket, key))) => {
            let (tx, rx) = mpsc::channel::<Bytes>(1);
            tokio::spawn(async move {
                if let Err(e) = storage.upload(&bucket, &key, rx).await {
                    error!("Error during upload: {:?}", e);
                }
            });

            while let Ok(Some(mut data)) = stream.recv_data().await {
                let bytes = data.copy_to_bytes(data.remaining());
                if tx.send(bytes).await.is_err() {
                    break;
                }
            }
            let response = res.body(()).unwrap();
            stream.send_response(response).await?;
        }
        _ => {
            let response = res.body(()).unwrap();
            stream.send_response(response).await?;
        }
    }

    stream.finish().await?;
    Ok(())
}

async fn get_object(
    storage: Arc<Storage>,
    bucket_name: &str,
    path: &str,
    range_start: usize,
    range_end: Option<usize>,
) -> Option<(Bytes, u64)> {
    match storage
        .get_byte_range(bucket_name, path, range_start, range_end)
        .await
    {
        Ok(b) => {
            let h = const_xxh3(&b);
            Some((b, h))
        }
        Err(e) => {
            error!("error getting object: {:?}", e);
            None
        }
    }
}

fn parse_byte_range(s: &str) -> Result<(usize, Option<usize>)> {
    let s = s
        .strip_prefix("bytes=")
        .ok_or_else(|| anyhow!("Invalid range prefix"))?;

    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid range format"));
    }

    let start = if !parts[0].is_empty() {
        parts[0]
            .trim()
            .parse::<usize>()
            .map_err(|_| anyhow!("Invalid start number"))?
    } else {
        0
    };

    let end = if !parts[1].is_empty() {
        Some(
            parts[1]
                .trim()
                .parse::<usize>()
                .map_err(|_| anyhow!("Invalid end number"))?,
        )
    } else {
        None
    };

    Ok((start, end))
}
