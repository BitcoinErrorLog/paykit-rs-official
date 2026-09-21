
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
