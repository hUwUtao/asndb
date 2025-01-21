use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use asndb::store::IPDatabase;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::info;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

// type GenericError = Box<dyn std::error::Error + Send + Sync>;
// type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

// static INTERNAL_SERVER_ERROR: &[u8] = b"Internal Server Error";
// static NOTFOUND: &[u8] = b"Not Found";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    femme::start();

    let addr: SocketAddr = "127.0.0.1:1337".parse().unwrap();

    let listener = TcpListener::bind(&addr).await?;
    info!("Listening on http://{}", addr);

    let db = Arc::new(RwLock::new(IPDatabase::load_from_file(
        "./ip_database.bin",
    )?));
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let db = db.clone();
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |_req| {
                        let db = db.clone();
                        async move {
                            if _req.uri().path() != "/api/ip" {
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap());
                            }
                            if let Some(a) = db.read().await.query(_req.uri().query().unwrap()) {
                                let mut r = Response::new(Full::new(Bytes::from(
                                    serde_json::to_vec(&a)
                                        //todo
                                        .unwrap(),
                                )));
                                r.headers_mut().append(
                                    "Content-Type",
                                    HeaderValue::from_str("application/json").unwrap(),
                                );
                                Ok::<_, hyper::Error>(r)
                            } else {
                                Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap())
                            }
                        }
                    }),
                )
                .await
            {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}
