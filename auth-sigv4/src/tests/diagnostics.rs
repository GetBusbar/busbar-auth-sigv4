// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SigV4 diagnostic assertions read a plain tracing fmt writer.
use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Default)]
struct Bytes(Arc<Mutex<Vec<u8>>>);
impl Write for Bytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct Log {
    bytes: Bytes,
    level: tracing::Level,
}
impl Log {
    pub(crate) fn new(level: tracing::Level) -> Self {
        use tracing_subscriber::layer::SubscriberExt;
        // Parallel captures are short-lived, while another test can register the same
        // callsite without a subscriber. Keep dynamic interest registered for the
        // process lifetime so it cannot cache an empty subscriber set between them.
        // This dispatch is never installed as a default and records no events.
        static INTEREST: OnceLock<tracing::Dispatch> = OnceLock::new();
        let _ = INTEREST.get_or_init(|| {
            tracing::Dispatch::new(
                tracing_subscriber::registry()
                    .with(tracing_subscriber::filter::dynamic_filter_fn(|_, _| false)),
            )
        });
        Self {
            bytes: Bytes::default(),
            level,
        }
    }
    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        use tracing_subscriber::{layer::SubscriberExt, Layer};
        let bytes = self.bytes.clone();
        let level = self.level;
        // Each parallel capture consults its own dispatch instead of a static callsite interest.
        let filter = tracing_subscriber::filter::dynamic_filter_fn(move |metadata, _| {
            *metadata.level() <= level
        });
        tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false)
                .with_target(false)
                .with_level(false)
                .with_writer(move || bytes.clone())
                .with_filter(filter),
        )
    }
    pub(crate) fn messages(&self) -> Vec<String> {
        String::from_utf8(self.bytes.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}
