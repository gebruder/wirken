use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use crate::error::IpcError;

/// Maximum frame size: 16 MB. Prevents a malformed length prefix
/// from causing unbounded allocation.
const MAX_FRAME_SIZE: u64 = 16 * 1024 * 1024;

/// Reads length-prefixed Cap'n Proto messages from a Unix socket.
///
/// Wire format: [4-byte big-endian length][capnp message bytes]
///
/// The length prefix is NOT part of Cap'n Proto — it's a framing layer
/// so we know where one message ends and the next begins on the stream.
pub struct FrameReader {
    reader: OwnedReadHalf,
}

impl FrameReader {
    pub fn new(reader: OwnedReadHalf) -> Self {
        Self { reader }
    }

    /// Read one Cap'n Proto message from the stream.
    /// Returns the deserialized message with default traversal limits.
    pub async fn read_message(&mut self) -> Result<capnp::message::Reader<capnp::serialize::OwnedSegments>, IpcError> {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        self.reader.read_exact(&mut len_buf).await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    IpcError::ConnectionClosed
                } else {
                    IpcError::Io(e)
                }
            })?;

        let len = u32::from_be_bytes(len_buf) as u64;
        if len > MAX_FRAME_SIZE {
            return Err(IpcError::FrameTooLarge { size: len, max: MAX_FRAME_SIZE });
        }

        // Read message bytes
        let mut msg_buf = vec![0u8; len as usize];
        self.reader.read_exact(&mut msg_buf).await?;

        // Deserialize with traversal limit (Cap'n Proto's built-in DoS protection)
        let options = capnp::message::ReaderOptions {
            traversal_limit_in_words: Some(64 * 1024 * 1024), // 512 MB word limit
            nesting_limit: 64,
        };

        let cursor = std::io::Cursor::new(msg_buf);
        let message = capnp::serialize::read_message(cursor, options)?;
        Ok(message)
    }
}

/// Writes length-prefixed Cap'n Proto messages to a Unix socket.
pub struct FrameWriter {
    writer: OwnedWriteHalf,
}

impl FrameWriter {
    pub fn new(writer: OwnedWriteHalf) -> Self {
        Self { writer }
    }

    /// Write one Cap'n Proto message to the stream.
    pub async fn write_message<A: capnp::message::Allocator>(
        &mut self,
        message: &capnp::message::Builder<A>,
    ) -> Result<(), IpcError> {
        // Serialize to bytes
        let mut buf = Vec::new();
        capnp::serialize::write_message(&mut buf, message)?;

        // Write length prefix + message
        let len = buf.len() as u32;
        self.writer.write_all(&len.to_be_bytes()).await?;
        self.writer.write_all(&buf).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

/// Create a FrameReader/FrameWriter pair from a UnixStream.
pub fn split_stream(stream: tokio::net::UnixStream) -> (FrameReader, FrameWriter) {
    let (read_half, write_half) = stream.into_split();
    (FrameReader::new(read_half), FrameWriter::new(write_half))
}
