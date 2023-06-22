use anyhow::Result;
use futures_util::StreamExt;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_rustls::{TlsAcceptor, TlsStream};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

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
#[derive(Clone)]
pub struct Connection(ConnectionRef);

impl Connection {
    fn new(stream: TlsStream<TcpStream>, peer_address: SocketAddr, mode: yamux::Mode) -> Self {
        let (_, state) = stream.get_ref();
        let peer_identity = state.peer_certificates().map(|certs| certs[0].to_owned());

        let (control, connection) = yamux::Control::new(yamux::Connection::new(
            stream.compat(),
            yamux::Config::default(),
            mode,
        ));

        Self(ConnectionRef(Arc::new(ConnectionInner {
            state: Mutex::new(ConnectionInnerState {
                control,
                connection,
            }),
            peer_address,
            peer_identity,
        })))
    }

    pub fn peer_identity(&self) -> Option<&rustls::Certificate> {
        self.0 .0.peer_identity.as_ref()
    }

    pub fn stable_id(&self) -> usize {
        &*self.0 .0 as *const _ as usize
    }

    pub fn peer_address(&self) -> SocketAddr {
        self.0 .0.peer_address
    }

    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream)> {
        let stream = self
            .0
             .0
            .state
            .lock()
            .await
            .control
            .open_stream()
            .await?
            .compat();
        let (read, write) = tokio::io::split(stream);
        Ok((SendStream(write), RecvStream(read)))
    }

    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
        let stream = self
            .0
             .0
            .state
            .lock()
            .await
            .connection
            .next()
            .await
            .ok_or(anyhow::anyhow!("connection closed"))??
            .compat();
        let (read, write) = tokio::io::split(stream);
        Ok((SendStream(write), RecvStream(read)))
    }
}

#[derive(Clone)]
pub(crate) struct ConnectionRef(Arc<ConnectionInner>);

pub(crate) struct ConnectionInner {
    state: Mutex<ConnectionInnerState>,
    peer_address: SocketAddr,
    peer_identity: Option<rustls::Certificate>,
}

pub(crate) struct ConnectionInnerState {
    control: yamux::Control,
    connection: yamux::ControlledConnection<Compat<TlsStream<TcpStream>>>,
}

// TODO-MUSTFIX: is it necessary to add a Drop handler to close anything here?
pub struct SendStream(WriteHalf<Compat<yamux::Stream>>);

impl std::ops::Deref for SendStream {
    type Target = WriteHalf<Compat<yamux::Stream>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SendStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// TODO-MUSTFIX: is it necessary to add a Drop handler to close anything here?
pub struct RecvStream(ReadHalf<Compat<yamux::Stream>>);

impl std::ops::Deref for RecvStream {
    type Target = ReadHalf<Compat<yamux::Stream>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RecvStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
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
            inner: EndpointRef(Arc::new(EndpointInner { listener, acceptor })),
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
        Ok(Connection::new(
            TlsStream::Client(stream),
            addr,
            yamux::Mode::Client,
        ))
    }

    pub async fn accept(&self) -> Result<Connection, std::io::Error> {
        // TODO-MUSTFIX add support for 'closed' endpoint.
        let (stream, peer_address) = self.inner.0.listener.accept().await?;
        let stream = self.inner.0.acceptor.accept(stream).await?;
        Ok(Connection::new(
            TlsStream::Server(stream),
            peer_address,
            yamux::Mode::Server,
        ))
    }
}

#[derive(Clone)]
pub(crate) struct EndpointRef(Arc<EndpointInner>);

pub(crate) struct EndpointInner {
    pub(crate) listener: TcpListener,
    pub(crate) acceptor: TlsAcceptor,
}
