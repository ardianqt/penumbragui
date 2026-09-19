/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
    // 5L0P-F1NG3RPR1NT: atria/Atria-Dawn-Preview-2026-09-19
*/

//! Persistent GUI configuration, backing the online SLA signing settings.
//!
//! Mirrors the Antumbra (TUI) configuration format so that the same signing
//! server can be used by both frontends. The file lives in
//! `<config_dir>/penumbra-gui/config.toml` and can also be driven entirely by
//! `PENUMBRA_*` environment variables.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use config::{Config, Environment, File};
use serde::{Deserialize, Serialize};

/// Online SLA / DAA signing server settings.
#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct AuthConfig {
    /// Whether to attempt authorization against a remote signing server.
    pub online_auth: bool,
    /// Base URL of the signing server, e.g. `https://sign.example.com`.
    pub endpoint: Option<String>,
    /// Optional username for token based login.
    pub username: Option<String>,
    /// Optional password for token based login.
    pub password: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone, Serialize)]
pub struct PenumbraGuiConfig {
    pub auth: AuthConfig,
}

impl PenumbraGuiConfig {
    pub fn load() -> Result<Arc<Self>> {
        let mut builder = Config::builder();
        let defaults = Self::default();

        builder = builder.set_default("auth.online_auth", defaults.auth.online_auth)?;
        builder = builder.set_default("auth.endpoint", defaults.auth.endpoint)?;
        builder = builder.set_default("auth.username", defaults.auth.username)?;
        builder = builder.set_default("auth.password", defaults.auth.password)?;

        if let Some(path) = Self::get_path() {
            builder = builder.add_source(File::from(path).required(false));
        }

        builder = builder.add_source(Environment::with_prefix("PENUMBRA"));

        let (cfg, parsed) = match builder.build().and_then(|c| c.try_deserialize::<Self>()) {
            Ok(cfg) => (cfg, true),
            Err(e) => {
                log::warn!("Could not read config ({e})");
                (Self::default(), false)
            }
        };

        if parsed {
            let _ = cfg.save();
        }

        Ok(Arc::new(cfg))
    }

    pub fn save(&self) -> Result<()> {
        if let Some(path) = Self::get_path() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }

            let toml_string = toml::to_string_pretty(self)?;
            fs::write(path, toml_string)?;
        }
        Ok(())
    }

    fn get_path() -> Option<PathBuf> {
        dirs_next::config_dir().map(|p| p.join("penumbra-gui/config.toml"))
    }
}
