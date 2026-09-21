//! Drain-then-clear-then-handshake replacement for a recovered Encrypted Link.
//!
//! One `ensure_link_with_peer` tick performs at most one of: confirm peer
//! capability, drain the retained inbox, clear the local write path, start a
//! replacement handshake, or resume a stored handshake. Crash windows are
//! recovered from durable flags plus the stored role; the orchestrator never
//! invents a role after `save_link_handshake_state`.

use super::EncryptedLinkHandshakeRole;
use crate::storage::ReplacementHandshakeProgress;

/// Evidence that the peer can participate in Encrypted Link Recovery Markers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerCapabilityEvidence {
    /// No prior snapshot exists, so this is a first link, not a replacement.
    FirstLink,
    /// The peer published a recovery marker, or observe already recorded one.
    Advertised,
    /// Marker GET succeeded with no document. Old clients look like this.
    Absent,
    /// Homeserver or transport failed. Never a recovery clear.
    Transport,
    /// Marker GET returned a not-found that is not a clean empty document.
    NotFound,
    /// Marker bytes or protocol data could not be interpreted.
    Protocol,
}

/// Durable inputs that decide the next replacement action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplacementView {
    pub has_prior_snapshot: bool,
    pub handshake_role: Option<EncryptedLinkHandshakeRole>,
    pub has_handshake_snapshot: bool,
    pub progress: ReplacementHandshakeProgress,
    pub capability: PeerCapabilityEvidence,
}

/// One exclusive action for the current `ensure` tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplacementStep {
    ConfirmPeerCapability,
    WaitForPeerCapability,
    DrainOldInbox,
    ClearLocalWritePath,
    StartReplacementHandshake,
    ResumeReplacementHandshake { role: EncryptedLinkHandshakeRole },
    FailClosed,
}

impl ReplacementStep {
    pub(crate) fn clears_write_path(self) -> bool {
        matches!(self, Self::ClearLocalWritePath)
    }

    pub(crate) fn starts_or_resumes_handshake(self) -> bool {
        matches!(
            self,
            Self::StartReplacementHandshake | Self::ResumeReplacementHandshake { .. }
        )
    }
}

/// Decide the next replacement action. Callers persist the matching flag
/// before attempting the following action on a later tick.
pub(crate) fn next_replacement_step(view: &ReplacementView) -> ReplacementStep {
    if !view.has_prior_snapshot || matches!(view.capability, PeerCapabilityEvidence::FirstLink) {
        return handshake_step(view);
    }

    if !view.progress.peer_capability_confirmed {
        return match view.capability {
            PeerCapabilityEvidence::Advertised | PeerCapabilityEvidence::FirstLink => {
                ReplacementStep::ConfirmPeerCapability
            }
            PeerCapabilityEvidence::Absent => ReplacementStep::WaitForPeerCapability,
            PeerCapabilityEvidence::Transport
            | PeerCapabilityEvidence::NotFound
            | PeerCapabilityEvidence::Protocol => ReplacementStep::FailClosed,
        };
    }

    if !view.progress.drain_acknowledged {
        return ReplacementStep::DrainOldInbox;
    }

    if !view.progress.write_path_cleared {
        return ReplacementStep::ClearLocalWritePath;
    }

    handshake_step(view)
}

fn handshake_step(view: &ReplacementView) -> ReplacementStep {
    if view.has_handshake_snapshot {
        return match view.handshake_role {
            Some(role) => ReplacementStep::ResumeReplacementHandshake { role },
            None => ReplacementStep::FailClosed,
        };
    }
    ReplacementStep::StartReplacementHandshake
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_view() -> ReplacementView {
        ReplacementView {
            has_prior_snapshot: true,
            handshake_role: None,
            has_handshake_snapshot: false,
            progress: ReplacementHandshakeProgress::default(),
            capability: PeerCapabilityEvidence::Advertised,
        }
    }

    #[test]
    fn first_link_skips_capability_drain_and_clear() {
        let view = ReplacementView {
            has_prior_snapshot: false,
            handshake_role: None,
            has_handshake_snapshot: false,
            progress: ReplacementHandshakeProgress::default(),
            capability: PeerCapabilityEvidence::FirstLink,
        };
        let step = next_replacement_step(&view);
        assert_eq!(step, ReplacementStep::StartReplacementHandshake);
        assert!(!step.clears_write_path());
    }

    #[test]
    fn absent_capability_never_clears() {
        let mut view = recovery_view();
        view.capability = PeerCapabilityEvidence::Absent;
        let step = next_replacement_step(&view);
        assert_eq!(step, ReplacementStep::WaitForPeerCapability);
        assert!(!step.clears_write_path());
    }

    #[test]
    fn transport_not_found_and_protocol_fail_closed_without_deletes() {
        for capability in [
            PeerCapabilityEvidence::Transport,
            PeerCapabilityEvidence::NotFound,
            PeerCapabilityEvidence::Protocol,
        ] {
            let mut view = recovery_view();
            view.capability = capability;
            let step = next_replacement_step(&view);
            assert_eq!(step, ReplacementStep::FailClosed);
            assert!(!step.clears_write_path());
            assert!(!step.starts_or_resumes_handshake());
        }
    }

    #[test]
    fn advertised_capability_then_drain_then_clear_then_start() {
        let mut view = recovery_view();
        assert_eq!(
            next_replacement_step(&view),
            ReplacementStep::ConfirmPeerCapability
        );
        view.progress.peer_capability_confirmed = true;
        assert_eq!(next_replacement_step(&view), ReplacementStep::DrainOldInbox);
        view.progress.drain_acknowledged = true;
        assert_eq!(
            next_replacement_step(&view),
            ReplacementStep::ClearLocalWritePath
        );
        view.progress.write_path_cleared = true;
        assert_eq!(
            next_replacement_step(&view),
            ReplacementStep::StartReplacementHandshake
        );
    }

    #[test]
    fn drain_loop_thirty_ticks_never_clears() {
        let mut view = recovery_view();
        view.progress.peer_capability_confirmed = true;
        for _ in 0..30 {
            let step = next_replacement_step(&view);
            assert_eq!(step, ReplacementStep::DrainOldInbox);
            assert!(!step.clears_write_path());
        }
        assert!(!view.progress.drain_acknowledged);
        assert!(!view.progress.write_path_cleared);
    }

    #[test]
    fn crash_after_clear_before_save_does_not_clear_again_or_invent_role() {
        let view = ReplacementView {
            has_prior_snapshot: true,
            handshake_role: None,
            has_handshake_snapshot: false,
            progress: ReplacementHandshakeProgress {
                drain_acknowledged: true,
                write_path_cleared: true,
                peer_capability_confirmed: true,
            },
            capability: PeerCapabilityEvidence::Advertised,
        };
        let step = next_replacement_step(&view);
        assert_eq!(step, ReplacementStep::StartReplacementHandshake);
        assert!(!step.clears_write_path());
    }

    #[test]
    fn crash_after_save_before_clear_clears_once_then_resumes_stored_role() {
        let mut view = ReplacementView {
            has_prior_snapshot: true,
            handshake_role: Some(EncryptedLinkHandshakeRole::Responder),
            has_handshake_snapshot: true,
            progress: ReplacementHandshakeProgress {
                drain_acknowledged: true,
                write_path_cleared: false,
                peer_capability_confirmed: true,
            },
            capability: PeerCapabilityEvidence::Advertised,
        };
        let step = next_replacement_step(&view);
        assert_eq!(step, ReplacementStep::ClearLocalWritePath);
        view.progress.write_path_cleared = true;
        assert_eq!(
            next_replacement_step(&view),
            ReplacementStep::ResumeReplacementHandshake {
                role: EncryptedLinkHandshakeRole::Responder
            }
        );
    }

    #[test]
    fn missing_stored_role_after_handshake_bytes_fail_closed() {
        let view = ReplacementView {
            has_prior_snapshot: true,
            handshake_role: None,
            has_handshake_snapshot: true,
            progress: ReplacementHandshakeProgress {
                drain_acknowledged: true,
                write_path_cleared: true,
                peer_capability_confirmed: true,
            },
            capability: PeerCapabilityEvidence::Advertised,
        };
        assert_eq!(next_replacement_step(&view), ReplacementStep::FailClosed);
    }
}
