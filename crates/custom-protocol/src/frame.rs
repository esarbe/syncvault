use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{ProtocolError, Result};
use crate::MAX_FRAME_SIZE;

pub const DEFAULT_MAX_FRAME_SIZE: usize = MAX_FRAME_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub payload: Bytes,
}

impl Frame {
    pub fn new(payload: impl Into<Bytes>) -> Result<Self> {
        let payload = payload.into();
        if payload.len() > MAX_FRAME_SIZE {
            return Err(ProtocolError::InvalidFrame(format!(
                "payload is {} bytes, maximum is {}",
                payload.len(),
                MAX_FRAME_SIZE
            )));
        }
        Ok(Self { payload })
    }
}

pub async fn read_frame<R>(reader: &mut R, max_frame_size: usize) -> Result<Frame>
where
    R: AsyncRead + Unpin,
{
    if max_frame_size == 0 || max_frame_size > MAX_FRAME_SIZE {
        return Err(ProtocolError::InvalidFrame(
            "invalid configured frame limit".to_string(),
        ));
    }

    let length = reader.read_u32().await? as usize;
    if length > max_frame_size {
        return Err(ProtocolError::InvalidFrame(format!(
            "frame is {} bytes, maximum is {}",
            length, max_frame_size
        )));
    }

    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Frame::new(payload)
}

pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if frame.payload.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::InvalidFrame(format!(
            "payload is {} bytes, maximum is {}",
            frame.payload.len(),
            MAX_FRAME_SIZE
        )));
    }

    writer.write_u32(frame.payload.len() as u32).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn round_trips_a_frame() {
        let (mut writer, mut reader) = duplex(64);
        let frame = Frame::new(Bytes::from_static(b"hello")).unwrap();
        write_frame(&mut writer, &frame).await.unwrap();
        assert_eq!(
            read_frame(&mut reader, MAX_FRAME_SIZE).await.unwrap(),
            frame
        );
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_allocating_payload() {
        let (mut writer, mut reader) = duplex(4);
        writer.write_u32((MAX_FRAME_SIZE as u32) + 1).await.unwrap();
        assert!(matches!(
            read_frame(&mut reader, MAX_FRAME_SIZE).await,
            Err(ProtocolError::InvalidFrame(_))
        ));
    }
}
