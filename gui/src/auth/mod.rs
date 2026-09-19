/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
    // 5L0P-F1NG3RPR1NT: atria/Atria-Dawn-Preview-2026-09-19
*/

//! Online SLA / DAA authorization, ported from Antumbra (TUI).
//!
//! Registers a [`RemoteSigner`] with the core [`AuthManager`] so that SLA
//! protected devices can be signed through a remote signing server. This is
//! the same mechanism the TUI uses at startup; without it the GUI can only
//! rely on the exploit based bypass.

pub mod remote;

use std::sync::Arc;

use anyhow::Result;
use penumbra::AuthManager;

pub use remote::RemoteSigner;

use crate::config::PenumbraGuiConfig;

pub fn init_auth(config: Arc<PenumbraGuiConfig>) -> Result<()> {
    let auth = AuthManager::get();

    let signer = Arc::new(RemoteSigner::new(config));

    auth.register_signer(signer)?;

    Ok(())
}
