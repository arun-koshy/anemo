use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsStream};

/// Configuration for outbound connections.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    pub(crate) tls: Arc<tokio_rustls::rustls::ClientConfig>,
}

impl ClientConfig {
    pub fn new(tls: tokio_rustls::rustls::ClientConfig) -> Self {
        Self { tls: Arc::new(tls) }
    }
}

/// Configuration for inbound connections.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Transport configuration to use
    pub(crate) tls: Arc<tokio_rustls::rustls::ServerConfig>,
}

impl ServerConfig {
    pub fn new(tls: tokio_rustls::rustls::ServerConfig) -> Self {
        Self { tls: Arc::new(tls) }
    }
}

/// A TLS connection.
///
/// May be cloned to obtain another handle to the same connection.
#[derive(Debug, Clone)]
pub struct Connection(ConnectionRef);

#[derive(Debug, Clone)]
pub(crate) struct ConnectionRef(Arc<ConnectionInner>);

#[derive(Debug)]
pub(crate) struct ConnectionInner {
    // TODO: use or remove.
    _stream: TlsStream<TcpStream>,
    _peer_address: SocketAddr,
}

/// A TLS endpoint.
///
/// An endpoint may host many connections, and may act as both client and server for different
/// connections.
///
/// May be cloned to obtain another handle to the same endpoint.
#[derive(Clone)]
pub struct Endpoint {
    pub(crate) inner: EndpointRef,
}

impl Endpoint {
    pub fn new(config: ServerConfig, listener: TcpListener) -> Self {
        let acceptor = TlsAcceptor::from(config.tls);
        Self {
            inner: EndpointRef(Arc::new(EndpointInner {
                listener,
                acceptor,
            })),
        }
    }

    /// Connect to a remote endpoint.
    pub async fn connect_with(
        &self,
        config: ClientConfig,
        addr: std::net::SocketAddr,
        server_name: &str,
    ) -> std::io::Result<Connection> {
        let connector = tokio_rustls::TlsConnector::from(config.tls.clone());
        let stream = TcpStream::connect(&addr).await?;

        // TODO-MUSTFIX does server_name work as DNS?
        let parsed_server_name = rustls::ServerName::try_from(server_name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid server_name: {server_name}"),
            )
        })?;
        // let server_name = rustls::ServerName::IpAddress(addr.ip());

        let stream = connector.connect(parsed_server_name, stream).await?;

        Ok(Connection(ConnectionRef(Arc::new(ConnectionInner {
            _peer_address: addr,
            _stream: TlsStream::Client(stream),
        }))))
    }

    pub async fn accept(&self) -> Result<Connection, std::io::Error> {
        // TODO-MUSTFIX add support for 'closed' endpoint.
        let (stream, peer_address) = self.inner.0.listener.accept().await?;
        let stream = self.inner.0.acceptor.accept(stream).await?;
        Ok(Connection(ConnectionRef(Arc::new(ConnectionInner {
            _peer_address: peer_address,
            _stream: TlsStream::Server(stream),
        }))))
    }
}

#[derive(Clone)]
pub(crate) struct EndpointRef(Arc<EndpointInner>);

pub(crate) struct EndpointInner {
    pub(crate) listener: TcpListener,
    pub(crate) acceptor: TlsAcceptor,
}
