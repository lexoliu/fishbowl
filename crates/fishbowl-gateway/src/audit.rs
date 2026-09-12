use std::{path::Path, sync::Arc};

use fishbowl_audit::{AuditEvent, AuditRecord, AuditWriter};
use jiff::Timestamp;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::error::Result;

/// Number of records that may queue up before producers wait for the writer.
///
/// A bounded channel is what makes the gateway fail closed under audit pressure: when the
/// trail cannot keep up, the connections producing records slow down rather than the
/// records being dropped.
const QUEUE_DEPTH: usize = 1024;

/// Handle every connection uses to report what it observed.
///
/// The audit trail has exactly one writer — the task [`spawn`] owns — and every producer
/// reaches it through this channel, so no lock is ever taken on the file.
#[derive(Debug, Clone)]
pub struct AuditSink {
    sandbox: Arc<str>,
    uid: Option<u32>,
    records: mpsc::Sender<AuditRecord>,
}

impl AuditSink {
    /// The same trail, with every record written through it naming `uid`.
    ///
    /// Attribution belongs to a connection rather than to an event, so it is fixed once —
    /// where the account is still recoverable — and carried by the handle the tasks
    /// serving that connection already pass around.
    #[must_use]
    pub fn attributed_to(&self, uid: Option<u32>) -> Self {
        Self {
            sandbox: Arc::clone(&self.sandbox),
            uid,
            records: self.records.clone(),
        }
    }

    /// Appends one event to the trail, waiting if the writer is behind.
    pub async fn record(&self, event: AuditEvent) {
        let record = AuditRecord {
            at: Timestamp::now(),
            sandbox: self.sandbox.to_string(),
            uid: self.uid,
            event,
        };
        if self.records.send(record).await.is_err() {
            tracing::error!(
                "the audit writer stopped; the gateway can no longer account for traffic"
            );
        }
    }
}

/// Starts the single audit writer and returns the handle producers clone.
///
/// # Errors
/// Fails when the trail cannot be opened for appending.
pub async fn spawn(sandbox: &str, trail: &Path) -> Result<(AuditSink, JoinHandle<()>)> {
    let mut writer = AuditWriter::open(trail).await?;
    let (records, mut incoming) = mpsc::channel(QUEUE_DEPTH);
    let task = tokio::spawn(async move {
        while let Some(record) = incoming.recv().await {
            if let Err(error) = writer.append(&record).await {
                tracing::error!(%error, "failed to append an audit record");
            }
        }
    });
    Ok((
        AuditSink {
            sandbox: Arc::from(sandbox),
            uid: None,
            records,
        },
        task,
    ))
}
