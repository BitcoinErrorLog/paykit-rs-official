use std::time::Duration;

use reqwest::Response;

use crate::errors::{Error, RequestError, Result};

/// Homeserver write-ack bodies are empty or a few bytes; a healthy drain
/// finishes in milliseconds even on slow mobile. Five seconds is above
/// jitter and below the sequential-drain stall window (minutes). Timeout
/// is a transport error so the write stays owed and retries.
pub(crate) const WRITE_BODY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Convert non-2xx responses into a structured error that includes the server body.
///
/// If the status is successful (2xx), the original response is returned.
/// If the status is an error (4xx or 5xx), the response body is consumed
/// to create a `PubkyError::Request(RequestError::Server)` and returned as an `Err`.
pub async fn check_http_status(response: Response) -> Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status();
    // Same bound as the 2xx write-ack drain: a hostile homeserver can
    // trickle an error body forever. Timeout keeps the HTTP error and
    // substitutes the canonical reason — it must not become Timeout,
    // because the write already failed with a non-2xx status.
    let message = match race_write_body_drain(response.text(), WRITE_BODY_DRAIN_TIMEOUT).await {
        Ok(text) => text,
        Err(_) => status
            .canonical_reason()
            .unwrap_or("Unknown Error")
            .to_string(),
    };

    Err(Error::from(RequestError::Server { status, message }))
}

/// Finish an issued HTTP write so dropping the `Response` cannot cancel it.
///
/// On wasm, reqwest attaches an `AbortController` to every `fetch` and aborts
/// that controller when `Response` is dropped — including after headers have
/// already arrived. Homeserver PUT/DELETE callers treat a 2xx `send()` as
/// success and discard the `Response` without reading the body, which cancels
/// the still-open fetch (`net::ERR_ABORTED`, `canceled=true`) and can prevent
/// the write from committing. Drain the body while the abort guard is still
/// alive; abort after a completed fetch is a no-op.
///
/// The drain is raced against [`WRITE_BODY_DRAIN_TIMEOUT`]. A hostile or
/// stalled homeserver can send 2xx headers and trickle the body forever;
/// timeout surfaces as [`RequestError::Timeout`] so the write stays owed.
/// Dropping the unfinished `bytes()` future on timeout aborts the wasm
/// fetch, which is correct: the write is already unconfirmed.
///
/// GET callers must keep the unread body. Only call this on write responses.
pub(crate) async fn commit_issued_http_write(response: Response) -> Result<()> {
    race_write_body_drain(response.bytes(), WRITE_BODY_DRAIN_TIMEOUT)
        .await
        .map(|_| ())
}

fn write_body_drain_timeout_error() -> Error {
    Error::from(RequestError::Timeout {
        message: "homeserver write-ack body drain exceeded the bound".into(),
    })
}

/// Race a body-read future against `timeout`. Shared by the production drain,
/// the error-body read in [`check_http_status`], and native unit tests that
/// model a stream that never completes.
pub(crate) async fn race_write_body_drain<F, T>(drain: F, timeout: Duration) -> Result<T>
where
    F: Future<Output = std::result::Result<T, reqwest::Error>>,
{
    #[cfg(not(target_arch = "wasm32"))]
    {
        match tokio::time::timeout(timeout, drain).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(err.into()),
            Err(_) => Err(write_body_drain_timeout_error()),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        use futures_util::future::{Either, select};
        use std::pin::pin;

        let drain = pin!(drain);
        let timer = pin!(wasm_sleep(timeout));
        match select(drain, timer).await {
            Either::Left((Ok(value), _)) => Ok(value),
            Either::Left((Err(err), _)) => Err(err.into()),
            Either::Right((_, _drain)) => Err(write_body_drain_timeout_error()),
        }
    }
}

/// Clears the `setTimeout` handle if the sleep future is dropped (the drain
/// won the race). A fired timer is a no-op to `clearTimeout`.
#[cfg(target_arch = "wasm32")]
struct WasmTimeoutGuard {
    id: Option<i32>,
}

#[cfg(target_arch = "wasm32")]
impl Drop for WasmTimeoutGuard {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let global = js_sys::global();
        let Ok(clear) = js_sys::Reflect::get(&global, &"clearTimeout".into()) else {
            return;
        };
        let clear = js_sys::Function::from(clear);
        let _ = clear.call1(&global, &id.into());
    }
}

#[cfg(target_arch = "wasm32")]
async fn wasm_sleep(timeout: Duration) {
    let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let id_cell = std::cell::Cell::new(None::<i32>);
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        let Ok(set_timeout) = js_sys::Reflect::get(&global, &"setTimeout".into()) else {
            let _ = resolve.call0(&wasm_bindgen::JsValue::UNDEFINED);
            return;
        };
        let set_timeout = js_sys::Function::from(set_timeout);
        match set_timeout.call2(&global, &resolve, &ms.into()) {
            Ok(handle) => {
                if let Some(n) = handle.as_f64() {
                    id_cell.set(Some(n as i32));
                }
            }
            Err(_) => {
                let _ = resolve.call0(&wasm_bindgen::JsValue::UNDEFINED);
            }
        }
    });
    // Promise executor runs synchronously; the id is set before we await.
    let _guard = WasmTimeoutGuard { id: id_cell.get() };
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use crate::errors::{Error, RequestError};

    use super::race_write_body_drain;

    /// Models reqwest's wasm `AbortGuard`: Drop aborts unless the body was
    /// taken first (the fetch completed).
    struct WriteResponse {
        body: Option<Vec<u8>>,
        aborted_unread: Rc<Cell<bool>>,
    }

    impl Drop for WriteResponse {
        fn drop(&mut self) {
            if self.body.take().is_some() {
                self.aborted_unread.set(true);
            }
        }
    }

    fn consume_write_body(mut response: WriteResponse) -> Vec<u8> {
        response.body.take().unwrap_or_default()
    }

    #[test]
    fn dropping_unread_write_response_aborts() {
        let aborted = Rc::new(Cell::new(false));
        drop(WriteResponse {
            body: Some(vec![1, 2, 3]),
            aborted_unread: Rc::clone(&aborted),
        });
        assert!(aborted.get());
    }

    #[test]
    fn consuming_write_body_before_drop_does_not_abort_unread() {
        let aborted = Rc::new(Cell::new(false));
        let response = WriteResponse {
            body: Some(vec![1, 2, 3]),
            aborted_unread: Rc::clone(&aborted),
        };
        let body = consume_write_body(response);
        assert_eq!(body, vec![1, 2, 3]);
        assert!(!aborted.get());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn never_completing_body_times_out_as_typed_error() {
        let started = Instant::now();
        let err = race_write_body_drain(
            std::future::pending::<reqwest::Result<()>>(),
            Duration::from_millis(50),
        )
        .await
        .expect_err("stalled body must not hang");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "timeout path hung: {:?}",
            started.elapsed()
        );
        match err {
            Error::Request(RequestError::Timeout { message }) => {
                assert!(
                    message.contains("drain"),
                    "unexpected timeout message: {message}"
                );
            }
            other => panic!("expected RequestError::Timeout, got {other:?}"),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn completing_body_drain_succeeds_before_timeout() {
        race_write_body_drain(
            async { Ok::<(), reqwest::Error>(()) },
            Duration::from_secs(1),
        )
        .await
        .expect("empty body must drain");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn stalled_error_body_falls_back_to_canonical_reason() {
        let started = Instant::now();
        let err = race_write_body_drain(
            std::future::pending::<reqwest::Result<String>>(),
            Duration::from_millis(50),
        )
        .await
        .expect_err("stalled error body must not hang");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "error-body timeout path hung: {:?}",
            started.elapsed()
        );
        match err {
            Error::Request(RequestError::Timeout { .. }) => {}
            other => panic!("expected RequestError::Timeout, got {other:?}"),
        }
        let message = reqwest::StatusCode::INTERNAL_SERVER_ERROR
            .canonical_reason()
            .unwrap_or("Unknown Error");
        assert_eq!(message, "Internal Server Error");
    }
}
