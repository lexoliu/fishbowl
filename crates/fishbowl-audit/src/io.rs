use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{AuditError, AuditRecord};

/// Append-only writer for the audit trail.
///
/// The gateway holds the only instance. Each record is written as one JSON line and
/// flushed immediately, so a reader on the host never sees a partial record and a
/// gateway crash loses at most the record in flight.
#[derive(Debug)]
pub struct AuditWriter {
    path: PathBuf,
    file: tokio::fs::File,
}

impl AuditWriter {
    /// Opens the trail at `path`, creating it if absent and appending otherwise.
    ///
    /// # Errors
    /// Fails when the trail cannot be created or opened for appending.
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        let path = path.into();
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(|source| AuditError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Self { path, file })
    }

    /// Appends one record and flushes it to the trail.
    ///
    /// # Errors
    /// Fails when the record cannot be encoded or the trail cannot be written.
    pub async fn append(&mut self, record: &AuditRecord) -> Result<(), AuditError> {
        let mut line = serde_json::to_vec(record).map_err(AuditError::Encode)?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .await
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        self.file.flush().await.map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })
    }
}

/// Sequential reader for the audit trail.
#[derive(Debug)]
pub struct AuditReader {
    path: PathBuf,
    lines: tokio::io::Lines<BufReader<tokio::fs::File>>,
    line_number: u64,
}

impl AuditReader {
    /// Opens the trail at `path` for reading from the beginning.
    ///
    /// # Errors
    /// Fails when the trail does not exist or cannot be opened.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|source| AuditError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path,
            lines: BufReader::new(file).lines(),
            line_number: 0,
        })
    }

    /// Reads the next record, or `None` at end of trail.
    ///
    /// # Errors
    /// Fails when the trail cannot be read or a line is not a valid record.
    pub async fn next_record(&mut self) -> Result<Option<AuditRecord>, AuditError> {
        let Some(line) = self
            .lines
            .next_line()
            .await
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?
        else {
            return Ok(None);
        };
        self.line_number += 1;
        serde_json::from_str(&line)
            .map(Some)
            .map_err(|source| AuditError::Malformed {
                line: self.line_number,
                source,
            })
    }
}
