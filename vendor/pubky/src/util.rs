use reqwest::Response;

use crate::errors::{Error, RequestError, Result};

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
    let message = response.text().await.unwrap_or_else(|_| {
        status
            .canonical_reason()
            .unwrap_or("Unknown Error")
            .to_string()
    });

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
/// GET callers must keep the unread body. Only call this on write responses.
pub(crate) async fn commit_issued_http_write(response: Response) -> Result<()> {
    #[cfg(target_arch = "wasm32")]
    {
        response.bytes().await?;
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        drop(response);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

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
}
