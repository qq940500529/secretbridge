// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public-key observation stops at key exchange, before SSH user authentication.
use super::{Transport, TransportGuard};
use russh::{
    client,
    keys::{HashAlg, PublicKeyOrCertificate},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type Active = Arc<Mutex<HashMap<Uuid, (Uuid, CancellationToken)>>>;
#[derive(Clone)]
pub(crate) struct HostKeyProbes {
    capacity: Arc<Semaphore>,
    active: Active,
}
impl Default for HostKeyProbes {
    fn default() -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(2)),
            active: Arc::default(),
        }
    }
}
impl HostKeyProbes {
    pub(crate) fn begin(&self, resource: Uuid, id: Uuid) -> Result<ProbeLease, &'static str> {
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| "probe_busy")?;
        let mut active = self.active.lock().map_err(|_| "probe_busy")?;
        if active.contains_key(&id) {
            return Err("probe_busy");
        }
        let stop = CancellationToken::new();
        active.insert(id, (resource, stop.clone()));
        Ok(ProbeLease {
            id,
            active: self.active.clone(),
            stop,
            _permit: permit,
        })
    }
    pub(crate) fn cancel(&self, resource: Uuid, id: Uuid) {
        if let Ok(active) = self.active.lock()
            && let Some((owner, stop)) = active.get(&id)
            && *owner == resource
        {
            stop.cancel();
        }
    }
}
pub(crate) struct ProbeLease {
    id: Uuid,
    active: Active,
    pub(crate) stop: CancellationToken,
    _permit: OwnedSemaphorePermit,
}
impl Drop for ProbeLease {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.id);
        }
    }
}

struct Observer(Arc<Mutex<Option<(String, String)>>>);
impl client::Handler for Observer {
    type Error = russh::Error;
    fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        // Refuse trust even after observing a key. connect_stream then terminates
        // without exposing a handle capable of authentication or opening channels.
        if !matches!(key, PublicKeyOrCertificate::Certificate(_)) {
            let public = key.public_key();
            if !public.algorithm().is_rsa()
                && !public.algorithm().is_dsa()
                && let Ok(mut observed) = self.0.lock()
            {
                *observed = Some((
                    public.fingerprint(HashAlg::Sha256).to_string(),
                    public.algorithm().to_string(),
                ));
            }
        }
        std::future::ready(Ok(false))
    }
}

pub(crate) async fn observe_host_key(
    host: &str,
    port: u16,
) -> Result<(String, String), &'static str> {
    if host.is_empty()
        || host.len() > 253
        || port == 0
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c))
    {
        return Err("configuration_incomplete");
    }
    let stop = CancellationToken::new();
    let _guard = TransportGuard(stop.clone());
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|_| "connection_failed")?;
    let observed = Arc::new(Mutex::new(None));
    let _ = client::connect_stream(
        Arc::new(client::Config::default()),
        Transport {
            stream,
            cancelled: Box::pin(stop.cancelled_owned()),
        },
        Observer(observed.clone()),
    )
    .await;
    observed
        .lock()
        .map_err(|_| "connection_failed")?
        .take()
        .ok_or("host_key_unavailable")
}
