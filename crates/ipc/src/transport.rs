use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::error::IpcError;

/// Maximum frame size: 16 MB. Prevents a malformed length prefix
/// from causing unbounded allocation.
const MAX_FRAME_SIZE: u64 = 16 * 1024 * 1024;

/// Reads length-prefixed Cap'n Proto messages from any
/// `AsyncRead + Unpin` source.
///
/// Wire format: [4-byte big-endian length][capnp message bytes]
///
/// The length prefix is NOT part of Cap'n Proto — it's a framing
/// layer so we know where one message ends and the next begins on
/// the stream. Generic over the reader type so the same framing
/// layer works over unix sockets and windows named pipes.
pub struct FrameReader<R: AsyncRead + Unpin> {
    reader: R,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Read one Cap'n Proto message from the stream.
    pub async fn read_message(
        &mut self,
    ) -> Result<capnp::message::Reader<capnp::serialize::OwnedSegments>, IpcError> {
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                IpcError::ConnectionClosed
            } else {
                IpcError::Io(e)
            }
        })?;

        let len = u32::from_be_bytes(len_buf) as u64;
        if len > MAX_FRAME_SIZE {
            return Err(IpcError::FrameTooLarge {
                size: len,
                max: MAX_FRAME_SIZE,
            });
        }

        let mut msg_buf = vec![0u8; len as usize];
        self.reader.read_exact(&mut msg_buf).await?;

        let options = capnp::message::ReaderOptions {
            traversal_limit_in_words: Some(64 * 1024 * 1024),
            nesting_limit: 64,
        };

        let cursor = std::io::Cursor::new(msg_buf);
        let message = capnp::serialize::read_message(cursor, options)?;
        Ok(message)
    }
}

/// Writes length-prefixed Cap'n Proto messages to any
/// `AsyncWrite + Unpin` sink.
pub struct FrameWriter<W: AsyncWrite + Unpin> {
    writer: W,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub async fn write_message<A: capnp::message::Allocator>(
        &mut self,
        message: &capnp::message::Builder<A>,
    ) -> Result<(), IpcError> {
        let mut buf = Vec::new();
        capnp::serialize::write_message(&mut buf, message)?;

        let len = buf.len() as u32;
        self.writer.write_all(&len.to_be_bytes()).await?;
        self.writer.write_all(&buf).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

/// Split any `AsyncRead + AsyncWrite + Unpin` stream into framed
/// reader/writer halves.
pub fn split_stream<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    stream: S,
) -> (FrameReader<ReadHalf<S>>, FrameWriter<WriteHalf<S>>) {
    let (read_half, write_half) = tokio::io::split(stream);
    (FrameReader::new(read_half), FrameWriter::new(write_half))
}

/// Type alias for a framed reader over a boxed [`crate::Stream`]
/// trait object. Production callers that hold a boxed stream and
/// have split it into halves use this alias to refer to the read
/// side without spelling out the full generic.
pub type IpcFrameReader = FrameReader<ReadHalf<crate::stream::BoxStream>>;

/// Counterpart to [`IpcFrameReader`].
pub type IpcFrameWriter = FrameWriter<WriteHalf<crate::stream::BoxStream>>;
