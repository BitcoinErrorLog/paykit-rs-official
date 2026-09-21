use std::{any::Any, sync::Arc};

use async_trait::async_trait;
use futures::lock::Mutex;
use js_sys::{Promise, Uint8Array};
use paykit_sdk::storage::{
    run_storage_state_transaction, StorageAdapter, StorageState, StorageTransactionCallback,
};
use paykit_sdk::PaykitSdkError;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;

const DATABASE_NAME: &str = "hypercolor-paykit-sdk";
const STORE_NAME: &str = "state";
const STATE_BLOB_VERSION: u32 = 1;

#[wasm_bindgen(inline_js = r#"
const request = (value) => new Promise((resolve, reject) => {
  value.onsuccess = () => resolve(value.result);
  value.onerror = () => reject(value.error ?? new Error("IndexedDB request failed"));
});

const complete = (transaction) => new Promise((resolve, reject) => {
  transaction.oncomplete = () => resolve();
  transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
});

const open = (databaseName, storeName) => new Promise((resolve, reject) => {
  if (!globalThis.indexedDB) {
    reject(new Error("IndexedDB is unavailable in this browser context"));
    return;
  }
  const request = globalThis.indexedDB.open(databaseName, 1);
  request.onupgradeneeded = () => {
    const database = request.result;
    if (!database.objectStoreNames.contains(storeName)) {
      database.createObjectStore(storeName);
    }
  };
  request.onsuccess = () => resolve(request.result);
  request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
});

const revision = () => {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
};

export async function loadStateBlob(databaseName, storeName, owner) {
  const database = await open(databaseName, storeName);
  try {
    const transaction = database.transaction(storeName, "readonly");
    const value = await request(transaction.objectStore(storeName).get(owner));
    await complete(transaction);
    if (value === undefined) return undefined;
    return { blob: new Uint8Array(value.blob), revision: value.revision };
  } finally {
    database.close();
  }
}

export async function saveStateBlobAtomically(databaseName, storeName, owner, blob, expectedRevision) {
  const database = await open(databaseName, storeName);
  try {
    const transaction = database.transaction(storeName, "readwrite");
    const store = transaction.objectStore(storeName);
    const current = await request(store.get(owner));
    const actualRevision = current === undefined ? undefined : current.revision;
    if (actualRevision !== expectedRevision) {
      transaction.abort();
      throw new Error("IndexedDB state revision changed");
    }
    const nextRevision = revision();
    await request(store.put({ blob: new Uint8Array(blob), revision: nextRevision }, owner));
    await complete(transaction);
    return nextRevision;
  } finally {
    database.close();
  }
}

export async function deleteStateBlob(databaseName, storeName, owner) {
  const database = await open(databaseName, storeName);
  try {
    const transaction = database.transaction(storeName, "readwrite");
    await request(transaction.objectStore(storeName).delete(owner));
    await complete(transaction);
  } finally {
    database.close();
  }
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = loadStateBlob)]
    fn load_state_blob_js(
        database_name: &str,
        store_name: &str,
        owner: &str,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = saveStateBlobAtomically)]
    fn save_state_blob_atomically_js(
        database_name: &str,
        store_name: &str,
        owner: &str,
        blob: &Uint8Array,
        expected_revision: &JsValue,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = deleteStateBlob)]
    fn delete_state_blob_js(
        database_name: &str,
        store_name: &str,
        owner: &str,
    ) -> Result<Promise, JsValue>;
}

/// Browser-owned durable state blob for one Pubky identity.
///
/// It stores a single opaque SDK state envelope in IndexedDB. The receiver
/// Noise key and browser session credential intentionally remain outside this
/// store: callers provide them through `PaykitSdkHandle` on each runtime
/// construction.
#[derive(Clone)]
pub(crate) struct IndexedDbBlobStore {
    owner: String,
}

struct BlobSnapshot {
    blob: Vec<u8>,
    revision: String,
}

impl IndexedDbBlobStore {
    pub(crate) fn new(owner: String) -> Self {
        Self { owner }
    }

    async fn load(&self) -> Result<Option<BlobSnapshot>, PaykitSdkError> {
        let promise = load_state_blob_js(DATABASE_NAME, STORE_NAME, &self.owner)
            .map_err(|_| storage_error("open IndexedDB state"))?;
        let value = JsFuture::from(promise)
            .await
            .map_err(|_| storage_error("load IndexedDB state"))?;
        if value.is_undefined() || value.is_null() {
            return Ok(None);
        }

        let blob = js_sys::Reflect::get(&value, &JsValue::from_str("blob"))
            .map_err(|_| storage_error("read IndexedDB state blob"))?
            .dyn_into::<Uint8Array>()
            .map_err(|_| storage_error("read IndexedDB state blob"))?
            .to_vec();
        let revision = js_sys::Reflect::get(&value, &JsValue::from_str("revision"))
            .map_err(|_| storage_error("read IndexedDB state revision"))?
            .as_string()
            .ok_or_else(|| storage_error("read IndexedDB state revision"))?;

        Ok(Some(BlobSnapshot { blob, revision }))
    }

    async fn save(
        &self,
        blob: &[u8],
        expected_revision: Option<&str>,
    ) -> Result<String, PaykitSdkError> {
        let blob = Uint8Array::from(blob);
        let expected = expected_revision
            .map(JsValue::from_str)
            .unwrap_or(JsValue::UNDEFINED);
        let promise =
            save_state_blob_atomically_js(DATABASE_NAME, STORE_NAME, &self.owner, &blob, &expected)
                .map_err(|_| storage_error("open IndexedDB state for save"))?;
        JsFuture::from(promise)
            .await
            .map_err(|_| storage_error("save IndexedDB state atomically"))?
            .as_string()
            .ok_or_else(|| storage_error("save IndexedDB state atomically"))
    }

    pub(crate) async fn delete(&self) -> Result<(), PaykitSdkError> {
        let promise = delete_state_blob_js(DATABASE_NAME, STORE_NAME, &self.owner)
            .map_err(|_| storage_error("open IndexedDB state for delete"))?;
        JsFuture::from(promise)
            .await
            .map_err(|_| storage_error("delete IndexedDB state"))?;
        Ok(())
    }
}

/// `paykit-sdk::StorageAdapter` backed by one revisioned IndexedDB blob.
///
/// A per-handle async mutex serializes local transactions. IndexedDB revision
/// comparison rejects stale writers from a second tab instead of overwriting
/// link generations, leases, or recovery-marker state.
#[derive(Clone)]
pub(crate) struct WasmSdkStorage {
    blob_store: IndexedDbBlobStore,
    transaction_lock: Arc<Mutex<()>>,
}

impl WasmSdkStorage {
    pub(crate) fn new(blob_store: IndexedDbBlobStore) -> Self {
        Self {
            blob_store,
            transaction_lock: Arc::new(Mutex::new(())),
        }
    }
}

#[async_trait(?Send)]
impl StorageAdapter for WasmSdkStorage {
    async fn transaction_erased<'a>(
        &self,
        operation: StorageTransactionCallback<'a>,
    ) -> paykit_sdk::Result<Box<dyn Any + Send>> {
        let _guard = self.transaction_lock.lock().await;
        let snapshot = self.blob_store.load().await?;
        let expected_revision = snapshot.as_ref().map(|snapshot| snapshot.revision.as_str());
        let initial_state = snapshot
            .map(|snapshot| decode_storage_state(&snapshot.blob))
            .transpose()?
            .unwrap_or_default();
        let (updated_state, result) =
            run_storage_state_transaction(initial_state.clone(), operation)?;

        if updated_state != initial_state {
            let encoded = encode_storage_state(&updated_state)?;
            self.blob_store.save(&encoded, expected_revision).await?;
        }

        Ok(result)
    }
}

#[derive(Serialize, Deserialize)]
struct StorageStateEnvelope {
    version: u32,
    state: StorageState,
}

fn encode_storage_state(state: &StorageState) -> Result<Vec<u8>, PaykitSdkError> {
    postcard::to_allocvec(&StorageStateEnvelope {
        version: STATE_BLOB_VERSION,
        state: state.clone(),
    })
    .map_err(|_| storage_error("encode SDK state"))
}

fn decode_storage_state(bytes: &[u8]) -> Result<StorageState, PaykitSdkError> {
    let envelope: StorageStateEnvelope =
        postcard::from_bytes(bytes).map_err(|_| storage_error("decode SDK state"))?;
    if envelope.version != STATE_BLOB_VERSION {
        return Err(PaykitSdkError::Storage {
            context: format!(
                "unsupported SDK state blob version {}, expected {}",
                envelope.version, STATE_BLOB_VERSION
            ),
            source: None,
        });
    }
    Ok(envelope.state)
}

fn storage_error(context: &str) -> PaykitSdkError {
    PaykitSdkError::Storage {
        context: context.into(),
        source: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_state_envelope_roundtrips() {
        let state = StorageState::default();
        assert_eq!(
            decode_storage_state(&encode_storage_state(&state).unwrap()).unwrap(),
            state
        );
    }
}
