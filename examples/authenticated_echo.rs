use jsonrpsee::{
    core::client::ClientT,
    http_client::HttpClientBuilder,
    types::{ErrorCode, ErrorObject},
    ws_client::RpcServiceBuilder,
};

use tower_defense::{
    crypto::{Keypair, PeerId},
    middleware,
};

#[tokio::main]
async fn main() {
    let addr = run_server().await.unwrap();
    let url = format!("http://{addr}");

    let keypair = Keypair::from_secret_bytes(&[0; 32]);
    let client = HttpClientBuilder::new()
        .set_rpc_middleware(
            RpcServiceBuilder::new()
                .layer_fn(|inner| middleware::Sign::new(keypair.clone(), inner)),
        )
        .build(&url)
        .unwrap();

    let res = client.request::<String, _>("echo", ["foo"]).await;
    println!("{res:?}");
}

async fn run_server() -> Option<std::net::SocketAddr> {
    let server = jsonrpsee::server::Server::builder()
        .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(middleware::Verify::new))
        .build("127.0.0.1:6969")
        .await
        .ok()?;

    let mut module = jsonrpsee::RpcModule::new(());

    module
        .register_method("echo", |params, (), ext| {
            println!("Request by: {:?}", ext.get::<PeerId>());
            let string: String = params
                .one()
                .inspect_err(|e| eprintln!("Error: {e:?}"))
                .map_err(|_| ErrorObject::from(ErrorCode::InvalidParams))?;
            Ok::<String, ErrorObject>(format!("echo: {string}"))
        })
        .unwrap();

    let addr = server.local_addr().ok()?;
    let handle = server.start(module);

    // In this example we don't care about doing shutdown so let's it run forever.
    // You may use the `ServerHandle` to shut it down or manage it yourself.
    tokio::spawn(handle.stopped());

    Some(addr)
}
