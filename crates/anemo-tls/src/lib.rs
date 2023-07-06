use anyhow::Result;
use futures_util::{
    io::{ReadHalf, WriteHalf},
    StreamExt,
};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
};
use tokio_rustls::{TlsAcceptor, TlsStream};
use tokio_util::compat::{
    Compat, FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt,
};

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
        // TODO-MUSTFIX can/should I do something here to guarantee this returns Some?
        let peer_identity = state.peer_certificates().map(|certs| certs[0].to_owned());

        let (control, connection) = yamux::Control::new(yamux::Connection::new(
            stream.compat(),
            yamux::Config::default(),
            mode,
        ));

        // Weird quirk alert:
        // yamux requires us to constantly drive the ControlledConnection or else new *outbound*
        // streams will not be started, even if we never intend to accept inbound streams.
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(Self::yield_streams(connection, tx));

        Self(ConnectionRef(Arc::new(ConnectionInner {
            state: Mutex::new(ConnectionInnerState { rx_streams: rx }),
            control,
            peer_address,
            peer_identity,
        })))
    }

    async fn yield_streams(
        mut connection: yamux::ControlledConnection<Compat<TlsStream<TcpStream>>>,
        tx: mpsc::Sender<yamux::Stream>,
    ) {
        while let Some(stream) = connection.next().await {
            match stream {
                Ok(stream) => {
                    if tx.send(stream).await.is_err() {
                        // The receiver is gone, so we can stop.
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!("yamux stream error: {}", e);
                    break;
                }
            }
        }
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
        let stream = self.0 .0.control.clone().open_stream().await?;
        let display_str = stream.to_string();
        let (read, write) = futures_util::AsyncReadExt::split(stream);
        Ok((
            SendStream {
                stream: write.compat_write(),
                display_str: display_str.to_owned(),
            },
            RecvStream {
                stream: read.compat(),
                display_str,
            },
        ))
    }

    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
        // TODO-MUSTFIX: can this mutex be avoided?
        let stream = self
            .0
             .0
            .state
            .lock()
            .await
            .rx_streams
            .recv()
            .await
            .ok_or(anyhow::anyhow!("connection closed"))?;
        let display_str = stream.to_string();
        let (read, write) = futures_util::AsyncReadExt::split(stream);
        Ok((
            SendStream {
                stream: write.compat_write(),
                display_str: display_str.to_owned(),
            },
            RecvStream {
                stream: read.compat(),
                display_str,
            },
        ))
    }
}

#[derive(Clone)]
pub(crate) struct ConnectionRef(Arc<ConnectionInner>);

pub(crate) struct ConnectionInner {
    state: Mutex<ConnectionInnerState>,
    control: yamux::Control,
    peer_address: SocketAddr,
    peer_identity: Option<rustls::Certificate>,
}

pub(crate) struct ConnectionInnerState {
    rx_streams: mpsc::Receiver<yamux::Stream>,
}

// TODO-MUSTFIX: is it necessary to add a Drop handler to close anything here?
pub struct SendStream {
    stream: Compat<WriteHalf<yamux::Stream>>,
    display_str: String,
}

impl std::fmt::Display for SendStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_str)
    }
}

impl std::ops::Deref for SendStream {
    type Target = Compat<WriteHalf<yamux::Stream>>;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl std::ops::DerefMut for SendStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl tokio::io::AsyncWrite for SendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

// TODO-MUSTFIX: is it necessary to add a Drop handler to close anything here?
pub struct RecvStream {
    stream: Compat<ReadHalf<yamux::Stream>>,
    display_str: String,
}

impl std::fmt::Display for RecvStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_str)
    }
}

impl std::ops::Deref for RecvStream {
    type Target = Compat<ReadHalf<yamux::Stream>>;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl std::ops::DerefMut for RecvStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl tokio::io::AsyncRead for RecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl futures::AsyncRead for RecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.stream.get_mut()).poll_read(cx, buf)
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
        let parsed_server_name = rustls::ServerName::try_from(server_name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid server_name: {server_name}"),
            )
        })?;

        let connector = tokio_rustls::TlsConnector::from(config.tls.clone());
        let stream = TcpStream::connect(&addr).await?;

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
        // TODO-MUSTFIX this will drop/lose the TCP connection if the future is dropped before
        // completion because ConnectionManager select loop finishes something else first.
        // I should save the connection here.
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
