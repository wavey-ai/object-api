use crate::presigned::{generate_presigned_url, verify_presigned_url};
use anyhow::{anyhow, Context, Result};
use bytes::Buf;
use bytes::Bytes;
use futures::stream::StreamExt;
use h3::server::RequestStream;
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
use storage::Storage;
use svix_ksuid::*;
use tls_helpers::{certs_from_base64, privkey_from_base64, tls_acceptor_from_base64};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{error, info};

const EXPIRY_SECONDS: u64 = 3600;
const ISSUE_PRESIGNED_URL_PATH: &str = "presigned";
const UPLOAD_PATH: &str = "upload";
const UPLOADS_BUCKET_NAME: &str = "uploads";
const UP_PATH: &str = "up";

pub struct ObjectApi {
    cert_pem_base64: String,
    privkey_pem_base64: String,
    ssl_port: u16,
    client: reqwest::Client,
    idp_port: u16,
    storage: Storage,
    bucket_prefix: String,
}

impl ObjectApi {
    pub fn new(
        cert_pem_base64: String,
        privkey_pem_base64: String,
        ssl_port: u16,
        idp_port: u16,
        storage: Storage,
        bucket_prefix: String,
    ) -> Self {
        Self {
            cert_pem_base64,
            privkey_pem_base64,
            ssl_port,
            client: Client::new(),
            idp_port,
            storage,
            bucket_prefix,
        }
    }

    pub async fn start(
        &self,
    ) -> Result<tokio::sync::watch::Sender<()>, Box<dyn std::error::Error + Send + Sync>> {
        let (tx, rx) = watch::channel(());

        let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);

        let tls_acceptor =
            tls_acceptor_from_base64(&self.cert_pem_base64, &self.privkey_pem_base64)?;

        info!("object server up at https://{}", addr);

        let client = self.client.clone();
        let idp_port = self.idp_port;
        let storage = self.storage.clone();
        let prefix = self.bucket_prefix.clone();
        let srv_h2 = {
            let mut shutdown_signal = rx.clone();

            async move {
                let incoming = TcpListener::bind(&addr).await.unwrap();
                let service = service_fn(move |req| {
                    handle_request_h2(
                        req,
                        client.clone(),
                        idp_port,
                        storage.clone(),
                        prefix.to_string(),
                    )
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
            let certs = certs_from_base64(&self.cert_pem_base64)?;
            let key = privkey_from_base64(&self.privkey_pem_base64)?;
            let mut tls_config = rustls::ServerConfig::builder()
                .with_safe_default_cipher_suites()
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();

            tls_config.max_early_data_size = u32::MAX;
            let alpn: Vec<Vec<u8>> = vec![
                b"h3".to_vec(),
                b"h3-32".to_vec(),
                b"h3-31".to_vec(),
                b"h3-30".to_vec(),
                b"h3-29".to_vec(),
            ];
            tls_config.alpn_protocols = alpn;

            let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_config));
            let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), self.ssl_port);
            let endpoint = quinn::Endpoint::server(server_config, addr).unwrap();
            let client = self.client.clone();
            let storage = self.storage.clone();
            let prefix = self.bucket_prefix.clone();

            let srv_h3 = {
                let mut shutdown_signal = rx.clone();

                async move {
                    loop {
                        tokio::select! {
                            _ = shutdown_signal.changed() => {
                                    break;
                            }
                            res = endpoint.accept()  => {
                                if let Some(new_conn) = res {
                                    info!("New connection being attempted");
                                    let client = client.clone();
                                    let storage = storage.clone();
                                    let prefix = prefix.clone();
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
                                                            let prefix = prefix.to_string();
                                                            tokio::spawn(async move {
                                                                if let Err(err) = handle_connection_h3(req, stream, client, idp_port, storage, prefix).await {
                                                                    error!("Failed to handle connection: {err:?}");
                                                                }
                                                            });
                                                        }
                                                        Ok(None) => {
                                                            break;
                                                        },
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
) -> Result<(http::response::Builder, Option<Bytes>, Option<String>)> {
    let mut res = http::Response::builder();
    let mut body = None;
    let mut object_key = None;

    let keys: Vec<&str> = uri.path().split('/').filter(|s| !s.is_empty()).collect();

    match (method, keys[0]) {
        (&Method::GET, UP_PATH) => {
            res = res.status(StatusCode::OK);
        }
        (&Method::GET, UPLOAD_PATH) => {
            if keys.len() == 3 {
                object_key = Some(format!("{}/{}", keys[1], keys[2]));
            }
        }

        (&Method::POST, UPLOAD_PATH) => {
            if let Some(q) = uri.query() {
                match verify_presigned_url(q) {
                    Ok(key) => {
                        object_key = Some(key);
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
        (&Method::POST, ISSUE_PRESIGNED_URL_PATH) => {
            match get_profile(client, headers, idp_port).await {
                Ok(user) => {
                    let ksuid = Ksuid::new(None, None);
                    let path = format!("{}/{}", user.id(), ksuid);
                    match generate_presigned_url(&path, EXPIRY_SECONDS) {
                        Ok(query_string) => {
                            let base_url = "/upload";
                            let full_uri = Bytes::from(format!("{}?{}", base_url, query_string));
                            body = Some(full_uri);
                        }
                        Err(e) => error!("Error generating presigned URL: {}", e),
                    }
                    res = res.status(StatusCode::OK);
                }
                Err(_) => {
                    res = res.status(StatusCode::FORBIDDEN);
                }
            };
        }
        _ => {
            res = res.status(StatusCode::NOT_FOUND);
        }
    };

    Ok((res, body, object_key))
}

async fn handle_request_h2(
    req: Request<Incoming>,
    client: Client,
    idp_port: u16,
    storage: Storage,
    bucket_prefix: String,
) -> Result<Response<Full<Bytes>>> {
    let (res, body, object_key) =
        request_handler(req.method(), req.headers(), req.uri(), client, idp_port).await?;

    let bucket = format!("{}-{}", bucket_prefix, UPLOADS_BUCKET_NAME);
    let keys: Vec<&str> = req
        .uri()
        .path()
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if let Some(b) = body {
        Ok(res.body(Full::new(b)).unwrap())
    } else {
        match (req.method(), keys[0]) {
            (&Method::GET, UPLOAD_PATH) => {
                let range_header = req
                    .headers()
                    .get("range")
                    .ok_or_else(|| anyhow!("Range header missing"))?;
                let range_str = range_header
                    .to_str()
                    .context("Failed to convert range header to string")?;
                let range = parse_byte_range(range_str)?;

                let (range_start, range_end) = match range {
                    Some((start, end)) => (start, end),
                    None => return Err(anyhow!("Invalid byte range")),
                };

                let bytes = storage
                    .get_byte_range(
                        &bucket,
                        object_key
                            .as_ref()
                            .ok_or_else(|| anyhow!("Object key is missing"))?,
                        range_start,
                        range_end,
                    )
                    .await?;
                Ok(res.body(Full::new(bytes)).unwrap())
            }
            (&Method::POST, UPLOAD_PATH) => {
                if let Some(object_key) = object_key {
                    let (tx, rx) = mpsc::channel(1);

                    tokio::task::spawn(async move {
                        if let Err(e) = storage.upload(&bucket, &object_key, rx).await {
                            error!("Error during upload: {:?}", e);
                        }
                    });

                    let body = req.into_body();
                    let mut body_stream = BodyStream::new(body);
                    while let Some(result) = body_stream.next().await {
                        match result {
                            Ok(frame) => {
                                if let Some(chunk) = frame.into_data().ok() {
                                    match tx.send(chunk).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            error!("error sending: {}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Error reading chunk: {:?}", e);
                                break;
                            }
                        }
                    }
                }

                Ok(res.body(Full::new(Bytes::new())).unwrap())
            }
            _ => Ok(res
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::new()))
                .unwrap()),
        }
    }
}

async fn handle_connection_h3(
    req: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    client: Client,
    idp_port: u16,
    storage: Storage,
    bucket_prefix: String,
) -> Result<()> {
    let (res, _, object_key) =
        request_handler(req.method(), req.headers(), req.uri(), client, idp_port).await?;

    let bucket = format!("{}-{}", bucket_prefix, UPLOADS_BUCKET_NAME);
    match req.method() {
        &Method::GET => {
            if let Some(object_key) = object_key {
                let range_header = req
                    .headers()
                    .get("Range")
                    .ok_or_else(|| anyhow!("Range header missing"))?;
                let range = parse_byte_range(range_header.to_str()?)?;

                let (range_start, range_end) = match range {
                    Some((start, end)) => (start, end),
                    None => return Err(anyhow!("Invalid byte range")),
                };

                let bytes = storage
                    .get_byte_range(&bucket, &object_key, range_start, range_end)
                    .await?;
                stream.send_response(res.body(()).unwrap()).await?;
                stream.send_data(bytes).await?;
            } else {
                stream
                    .send_response(res.status(StatusCode::NOT_FOUND).body(()).unwrap())
                    .await?;
            }
        }
        &Method::POST => {
            if let Some(object_key) = object_key {
                let (tx, rx) = mpsc::channel::<Bytes>(1);
                tokio::spawn(async move {
                    if let Err(e) = storage.upload(&bucket, &object_key, rx).await {
                        error!("Error during upload: {:?}", e);
                    }
                });

                while let Ok(Some(mut data)) = stream.recv_data().await {
                    let bytes = data.copy_to_bytes(data.remaining());
                    if tx.send(bytes).await.is_err() {
                        break;
                    }
                }
                stream.send_response(res.body(()).unwrap()).await?;
            } else {
                stream
                    .send_response(res.status(StatusCode::BAD_REQUEST).body(()).unwrap())
                    .await?;
            }
        }
        _ => {
            stream.send_response(res.body(()).unwrap()).await?;
        }
    }

    stream.finish().await?;
    Ok(())
}

fn parse_byte_range(range: &str) -> Result<Option<(usize, usize)>> {
    let parts: Vec<&str> = range.trim_start_matches("bytes=").split('-').collect();
    if parts.len() == 2 {
        let start: usize = parts[0].parse()?;
        let end: usize = parts[1].parse()?;
        Ok(Some((start, end)))
    } else {
        Ok(None)
    }
}
