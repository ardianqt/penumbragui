/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2026 Shomy, Penumbra Contributors
*/

//! Modern, human-crafted desktop interface for Penumbra Flasher.
//! Follows clean developer-tool layout with a dedicated left sidebar,
//! rich device status cards, and zero AI-slop empty voids.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::time::Instant;

use eframe::egui::{
    self, Align, Align2, Color32, Frame, Layout, Margin, RichText, Rounding, ScrollArea, Stroke,
    Ui, Vec2,
};
use egui_extras::{Column, TableBuilder};
use human_bytes::human_bytes;
use penumbra::da::{BootMode, ScatterFile};
use penumbra::port::PortBackend;
use penumbra::storage::Partition;
use serde::{Deserialize, Serialize};

use crate::messages::{
    Command, ConnStatus, DeviceSummary, Event, LockAction, LogLine, is_critical_partition,
};
use crate::theme::{self, Palette, ThemeId};
use crate::worker::WorkerHandle;

const LOG_MAX_ENTRIES: usize = 5000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Tab {
    #[default]
    Flasher,
    Partitions,
    Tools,
    Settings,
}

impl Tab {
    pub fn label(self) -> &'static str {
        match self {
            Tab::Flasher => "Flasher",
            Tab::Partitions => "Partitions",
            Tab::Tools => "Bypass & Power",
            Tab::Settings => "Settings",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Tab::Flasher => "Partition image flashing & scatter layout",
            Tab::Partitions => "PGPT partition table inspector & backup",
            Tab::Tools => "Bootloader & RPMB bypass, reboot modes & power state",
            Tab::Settings => "Connection backends, binary paths & SLA signing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum BackendChoice {
    #[default]
    Auto,
    Libusb,
    Usb,
    Serial,
}

impl BackendChoice {
    pub fn to_port_backend(self) -> PortBackend {
        match self {
            BackendChoice::Auto => PortBackend::Auto,
            BackendChoice::Libusb => PortBackend::Libusb,
            BackendChoice::Usb => PortBackend::Usb,
            BackendChoice::Serial => PortBackend::Serial,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            BackendChoice::Auto => "Auto (Recommended)",
            BackendChoice::Libusb => "libusb (Direct USB)",
            BackendChoice::Usb => "nusb (WinUSB / Modern USB)",
            BackendChoice::Serial => "Serial (Virtual COM Port)",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            BackendChoice::Auto => "Automatically detects connected BROM / Preloader port",
            BackendChoice::Libusb => "Uses libusb for low-level asynchronous USB bulk transfers",
            BackendChoice::Usb => "Cross-platform pure user-mode asynchronous USB stack",
            BackendChoice::Serial => "Connects via /dev/ttyUSB or COM ports directly",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct Persisted {
    pub theme: ThemeId,
    pub tab: Tab,
    pub da_path: Option<PathBuf>,
    pub preloader_path: Option<PathBuf>,
    pub auth_path: Option<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub scatter_path: Option<PathBuf>,
    pub firmware_dir: Option<PathBuf>,
    pub backend: BackendChoice,
}

impl Default for Persisted {
    fn default() -> Self {
        Self {
            theme: ThemeId::WarmGraphite,
            tab: Tab::Flasher,
            da_path: None,
            preloader_path: None,
            auth_path: None,
            output_dir: dirs_next::download_dir()
                .or_else(dirs_next::home_dir)
                .map(|p| p.join("penumbra_backup")),
            scatter_path: None,
            firmware_dir: None,
            backend: BackendChoice::Auto,
        }
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct PartitionRow {
    pub partition: Partition,
    pub selected: bool,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct ScatterRow {
    pub name: String,
    pub file_name: String,
    pub file_path: Option<PathBuf>,
    pub size: usize,
    pub address: u64,
    pub selected: bool,
    pub file_exists: bool,
}

#[derive(Default)]
pub struct ProgressState {
    pub written: u64,
    pub total: Option<u64>,
    pub message: String,
    pub active: bool,
    pub finished_at: Option<std::time::Instant>,
    pub finished_msg: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFilter {
    #[default]
    All,
    Info,
    Warn,
    Error,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ConfirmModal {
    FlashScatter(Vec<(String, PathBuf)>),
    FlashPartition { name: String, path: PathBuf },
    ErasePartition(String),
    UnlockBootloader,
    LockBootloader,
    UnlockRpmb,
    LockRpmb,
    Reboot(BootMode),
    Shutdown,
}

pub struct App {
    persisted: Persisted,
    status: ConnStatus,
    devinfo: Option<DeviceSummary>,
    partitions: Vec<PartitionRow>,
    partition_filter: String,
    scatter_rows: Vec<ScatterRow>,
    scatter_filter: String,
    progress: ProgressState,
    input_enabled: bool,
    logs: Vec<LogLine>,
    log_filter: LogFilter,
    log_search: String,
    log_autoscroll: bool,
    info_toast: Option<(String, Instant)>,
    error_modal: Option<String>,
    confirm_modal: Option<ConfirmModal>,
    /// Hex encoded RPMB authentication key (bypass / security tooling).
    rpmb_key: String,
    /// Online SLA signing server configuration (editable copy; applied on restart).
    auth_online: bool,
    auth_endpoint: String,
    auth_username: String,
    auth_password: String,
    /// Set by the Settings tab UI; acted on once the panel closure has dropped its borrows.
    auth_save_requested: bool,
    patch_da_requested: bool,

    handle: WorkerHandle,
    evt_rx: Receiver<Event>,
    log_rx: Receiver<LogLine>,
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        handle: WorkerHandle,
        evt_rx: Receiver<Event>,
        log_rx: Receiver<LogLine>,
    ) -> Self {
        let mut persisted: Persisted = cc
            .storage
            .and_then(|s| eframe::get_value(s, eframe::APP_KEY))
            .unwrap_or_default();

        // Migrate default from legacy SlateDark to WarmGraphite hardware theme
        if persisted.theme == ThemeId::SlateDark {
            persisted.theme = ThemeId::WarmGraphite;
        }

        theme::setup_fonts(&cc.egui_ctx);
        theme::apply(persisted.theme.palette(), &cc.egui_ctx);

        // Load the persisted online SLA signing configuration so the Settings
        // tab shows the values that the registered signer is currently using.
        let auth_cfg = crate::config::PenumbraGuiConfig::load().map(|c| (*c).clone()).unwrap_or_default();

        let mut initial_logs = Vec::with_capacity(1000);
        initial_logs.push(LogLine {
            level: log::Level::Info,
            target: "penumbra".into(),
            message: "Penumbra Flasher v2.0.0 session initialized.".into(),
        });
        initial_logs.push(LogLine {
            level: log::Level::Info,
            target: "penumbra-mtk".into(),
            message: "Core engine: penumbra-mtk 2.0.0 (MediaTek V5 XFlash & V6 XML DA)".into(),
        });
        initial_logs.push(LogLine {
            level: log::Level::Info,
            target: "port".into(),
            message: format!("Hardware port backend: {}", persisted.backend.label()),
        });
        initial_logs.push(LogLine {
            level: log::Level::Info,
            target: "penumbra".into(),
            message: "Ready. Connect device in BROM or Preloader mode to begin.".into(),
        });

        let mut app = Self {
            persisted,
            status: ConnStatus::Disconnected,
            devinfo: None,
            partitions: Vec::new(),
            partition_filter: String::new(),
            scatter_rows: Vec::new(),
            scatter_filter: String::new(),
            progress: ProgressState::default(),
            input_enabled: true,
            logs: initial_logs,
            log_filter: LogFilter::All,
            log_search: String::new(),
            log_autoscroll: true,
            info_toast: None,
            error_modal: None,
            confirm_modal: None,
            rpmb_key: String::new(),
            auth_online: auth_cfg.auth.online_auth,
            auth_endpoint: auth_cfg.auth.endpoint.clone().unwrap_or_default(),
            auth_username: auth_cfg.auth.username.clone().unwrap_or_default(),
            auth_password: auth_cfg.auth.password.clone().unwrap_or_default(),
            auth_save_requested: false,
            patch_da_requested: false,
            handle,
            evt_rx,
            log_rx,
        };

        if let Some(ref path) = app.persisted.scatter_path.clone() {
            if path.exists() {
                app.load_scatter_file(path);
            } else {
                app.persisted.scatter_path = None;
            }
        }

        app
    }

    fn poll_events(&mut self) {
        while let Ok(log) = self.log_rx.try_recv() {
            if self.logs.len() >= LOG_MAX_ENTRIES {
                self.logs.drain(0..500);
            }
            self.logs.push(log);
        }

        while let Ok(evt) = self.evt_rx.try_recv() {
            match evt {
                Event::StatusChanged(status) => {
                    let was_disconnected = matches!(self.status, ConnStatus::Disconnected | ConnStatus::Connecting);
                    self.status = status;
                    if matches!(self.status, ConnStatus::Disconnected) {
                        self.devinfo = None;
                        self.progress.active = false;
                    } else if matches!(self.status, ConnStatus::Connected(_)) && was_disconnected {
                        self.send_cmd(Command::LoadPartitions);
                    }
                }
                Event::DeviceInfo(summary) => {
                    self.devinfo = Some(summary);
                }
                Event::PartitionsLoaded(parts) => {
                    self.partitions = parts
                        .into_iter()
                        .map(|p| PartitionRow {
                            partition: p,
                            selected: false,
                        })
                        .collect();
                    self.toast("Loaded device partition table (PGPT)");
                }
                Event::ProgressStart {
                    total_bytes,
                    message,
                } => {
                    self.progress = ProgressState {
                        written: 0,
                        total: if total_bytes > 0 {
                            Some(total_bytes)
                        } else {
                            None
                        },
                        message,
                        active: true,
                        finished_at: None,
                        finished_msg: None,
                    };
                }
                Event::ProgressUpdate {
                    written,
                    total_bytes,
                    message,
                } => {
                    self.progress.active = true;
                    self.progress.finished_at = None;
                    self.progress.finished_msg = None;
                    self.progress.written = written;
                    if let Some(t) = total_bytes {
                        self.progress.total = Some(t);
                    }
                    if let Some(m) = message {
                        self.progress.message = m;
                    }
                }
                Event::ProgressFinish { message } => {
                    self.progress.active = false;
                    // Ensure progress reflects 100% completion
                    if let Some(total) = self.progress.total {
                        self.progress.written = total;
                    } else if self.progress.written > 0 {
                        self.progress.total = Some(self.progress.written);
                    }
                    self.progress.finished_at = Some(std::time::Instant::now());
                    self.progress.finished_msg = Some(message.clone());
                    self.toast(message);
                }
                Event::Error(err) => {
                    self.progress.active = false;
                    self.progress.finished_at = None;
                    self.progress.finished_msg = None;
                    self.error_modal = Some(err);
                }
                Event::Info(msg) => {
                    self.toast(msg);
                }
                Event::InputEnabled(enabled) => {
                    self.input_enabled = enabled;
                }
            }
        }
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.info_toast = Some((msg.into(), Instant::now()));
    }

    fn connect(&self) {
        self.send_cmd(Command::Connect {
            da_path: self.persisted.da_path.clone(),
            preloader_path: self.persisted.preloader_path.clone(),
            auth_path: self.persisted.auth_path.clone(),
            backend: self.persisted.backend.to_port_backend(),
        });
    }

    fn disconnect(&self) {
        self.handle.cancel.store(true, Ordering::SeqCst);
        self.send_cmd(Command::Disconnect);
    }

    fn load_scatter_file(&mut self, path: &Path) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                self.error_modal = Some(format!("Failed to read scatter file: {e}"));
                return;
            }
        };

        let scatter = if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.eq_ignore_ascii_case("xml"))
            .unwrap_or(false)
        {
            ScatterFile::from_xml(&content)
        } else {
            ScatterFile::from_yaml(&content)
        };

        let scatter = match scatter {
            Ok(s) => s,
            Err(e) => {
                self.error_modal = Some(format!("Invalid scatter format: {e}"));
                return;
            }
        };

        self.persisted.scatter_path = Some(path.to_path_buf());
        if self.persisted.firmware_dir.is_none() {
            if let Some(parent) = path.parent() {
                self.persisted.firmware_dir = Some(parent.to_path_buf());
            }
        }

        let dir = self.persisted.firmware_dir.clone();
        let mut rows = Vec::new();

        for sp in scatter.partitions() {
            let file_name = sp
                .path
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|f| f.to_str())
                .unwrap_or("")
                .to_string();
            let mut file_path = None;
            let mut file_exists = false;

            if !file_name.is_empty() {
                if let Some(ref d) = dir {
                    let p = d.join(&file_name);
                    if p.is_file() {
                        file_exists = true;
                        file_path = Some(p);
                    }
                }
            }

            let selected = file_exists && !sp.part.name.eq_ignore_ascii_case("userdata");

            rows.push(ScatterRow {
                name: sp.part.name.clone(),
                file_name,
                file_path,
                size: sp.part.size,
                address: sp.part.address,
                selected,
                file_exists,
            });
        }

        self.scatter_rows = rows;
        self.toast(format!("Loaded scatter with {} partitions", self.scatter_rows.len()));
    }

    fn send_cmd(&self, cmd: Command) {
        let _ = self.handle.cmd_tx.send(cmd);
    }
}

impl eframe::App for App {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.persisted);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();

        if self.progress.active || self.progress.finished_at.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }

        let palette = self.persisted.theme.palette();

        // 1. Dedicated Left Sidebar Navigation Panel
        egui::SidePanel::left("left_sidebar")
            .resizable(false)
            .exact_width(235.0)
            .frame(
                Frame::none()
                    .fill(palette.sidebar)
                    .stroke(Stroke::new(1.0_f32, palette.border))
                    .inner_margin(Margin::same(14.0)),
            )
            .show(ctx, |ui| {
                self.render_sidebar(ui, &palette);
            });

        // 2. Bottom Activity & Progress Dock
        egui::TopBottomPanel::bottom("dock_panel")
            .frame(
                Frame::none()
                    .fill(palette.panel)
                    .stroke(Stroke::new(1.0_f32, palette.border))
                    .inner_margin(Margin::symmetric(16.0, 8.0)),
            )
            .show(ctx, |ui| {
                self.render_dock(ui, &palette);
            });

        // 3. Central Main Content Area
        egui::CentralPanel::default()
            .frame(
                Frame::none()
                    .fill(palette.background)
                    .inner_margin(Margin::same(18.0)),
            )
            .show(ctx, |ui| {
                self.render_screen_header(ui, &palette);
                ui.add_space(12.0);

                match self.persisted.tab {
                    Tab::Flasher => self.render_flasher_tab(ui, &palette),
                    Tab::Partitions => self.render_partitions_tab(ui, &palette),
                    Tab::Tools => self.render_tools_tab(ui, &palette),
                    Tab::Settings => self.render_settings_tab(ui, &palette),
                }
            });

        // 4. Floating Toast Notification
        if let Some((msg, created)) = &self.info_toast {
            if created.elapsed().as_secs() > 4 {
                self.info_toast = None;
            } else {
                egui::Area::new(egui::Id::new("toast_area"))
                    .anchor(Align2::RIGHT_BOTTOM, egui::vec2(-20.0, -50.0))
                    .show(ctx, |ui| {
                        Frame::none()
                            .fill(palette.panel_alt)
                            .stroke(Stroke::new(1.0_f32, palette.accent))
                            .rounding(Rounding::same(3.0))
                            .inner_margin(Margin::symmetric(14.0, 10.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let (icon_rect, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), egui::Sense::hover());
                                    let stroke = Stroke::new(1.8_f32, palette.success);
                                    let p1 = icon_rect.left_center() + egui::vec2(1.5, 0.0);
                                    let p2 = icon_rect.center() + egui::vec2(-1.0, 3.0);
                                    let p3 = icon_rect.right_center() + egui::vec2(-1.5, -3.0);
                                    ui.painter().line_segment([p1, p2], stroke);
                                    ui.painter().line_segment([p2, p3], stroke);
                                    ui.label(RichText::new(msg).color(palette.text));
                                });
                            });
                    });
            }
        }

        // 5. Error Modal Dialog
        if let Some(err) = self.error_modal.clone() {
            egui::Window::new(RichText::new("Hardware Error").color(palette.error).strong())
                .collapsible(false)
                .resizable(false)
                .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                .frame(
                    Frame::none()
                        .fill(palette.panel)
                        .stroke(Stroke::new(1.0_f32, palette.error))
                        .rounding(Rounding::same(3.0))
                        .inner_margin(Margin::same(18.0)),
                )
                .show(ctx, |ui| {
                    ui.set_width(420.0);
                    ui.label(
                        RichText::new("An operation failed or the device returned an error:")
                            .color(palette.text_muted),
                    );
                    ui.add_space(8.0);

                    Frame::none()
                        .fill(palette.panel_alt)
                        .stroke(Stroke::new(1.0_f32, palette.border))
                        .rounding(Rounding::same(3.0))
                        .inner_margin(Margin::same(10.0))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(&err)
                                    .color(palette.error)
                                    .monospace()
                                    .size(12.0),
                            );
                        });

                    ui.add_space(14.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .button(RichText::new("Dismiss").color(palette.text).strong())
                            .clicked()
                        {
                            self.error_modal = None;
                        }
                    });
                });
        }

        // 6. Confirmation Modals for Destructive Operations
        self.render_confirm_modal(ctx, &palette);
    }
}

// ---------------------------------------------------------------------------
// Left Sidebar & Navigation Implementation
// ---------------------------------------------------------------------------

impl App {
    fn render_sidebar(&mut self, ui: &mut Ui, palette: &Palette) {
        // App Header & Branding
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("PENUMBRA")
                            .color(palette.text)
                            .size(17.0)
                            .strong(),
                    );
                    ui.label(
                        RichText::new("v2.0")
                            .color(palette.accent)
                            .size(10.0),
                    );
                });
                ui.label(
                    RichText::new("MediaTek Flash Suite")
                        .color(palette.text_muted)
                        .size(10.5),
                );
            });
        });

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);

        // Hardware Device Status Card (Key panel with connector-notch accents)
        let card_resp = Frame::none()
            .fill(palette.panel_alt)
            .stroke(Stroke::new(1.0_f32, palette.border))
            .rounding(Rounding::same(3.0))
            .inner_margin(Margin::same(12.0))
            .show(ui, |ui| {
                // Connection status row
                ui.horizontal(|ui| {
                    let (dot_color, label_text) = match self.status {
                        ConnStatus::Connected(_) => (palette.success, "Connected"),
                        ConnStatus::Connecting => (palette.warn, "Connecting..."),
                        ConnStatus::Disconnected => (palette.text_faint, "No Device"),
                    };
                    theme::status_led(ui, dot_color, 11.0);
                    ui.add_space(2.0);
                    ui.label(RichText::new(label_text).color(palette.text).strong().size(12.0));
                });

                ui.add_space(6.0);

                if let Some(ref dev) = self.devinfo {
                    ui.label(
                        RichText::new(&dev.chip_name)
                            .color(palette.accent)
                            .strong()
                            .size(13.0),
                    );
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("HW: ").color(palette.text_muted).size(11.0));
                        ui.label(
                            RichText::new(format!("0x{:04X}", dev.hw_code))
                                .color(palette.text_muted)
                                .monospace()
                                .size(11.0),
                        );
                        ui.label(
                            RichText::new(format!(" / {}", dev.storage_type))
                                .color(palette.text_muted)
                                .size(11.0),
                        );
                    });

                    ui.add_space(6.0);
                    // Security chips badge row
                    ui.horizontal(|ui| {
                        Self::chip_badge(ui, "SBC", dev.sbc, palette);
                        Self::chip_badge(ui, "SLA", dev.sla, palette);
                        Self::chip_badge(ui, "DAA", dev.daa, palette);
                    });
                } else {
                    ui.label(
                        RichText::new("Turn off phone & hold Vol- to connect USB.")
                            .color(palette.text_muted)
                            .size(10.5),
                    );
                }

                ui.add_space(10.0);

                // Connect / Disconnect Action Button
                let is_busy = !self.input_enabled || self.progress.active;
                match self.status {
                    ConnStatus::Connected(_) => {
                        let btn = egui::Button::new(
                            RichText::new("Disconnect Device").color(palette.error).size(11.5),
                        )
                        .min_size(Vec2::new(ui.available_width().max(0.0), 28.0));
                        if ui.add_enabled(!is_busy, btn).clicked() {
                            self.disconnect();
                        }
                    }
                    ConnStatus::Connecting => {
                        let btn = egui::Button::new(
                            RichText::new("Cancel Connecting").color(palette.text_muted).size(11.5),
                        )
                        .min_size(Vec2::new(ui.available_width().max(0.0), 28.0));
                        if ui.add(btn).clicked() {
                            self.disconnect();
                        }
                    }
                    ConnStatus::Disconnected => {
                        let btn = egui::Button::new(
                            RichText::new("Connect Device")
                                .color(palette.btn_text_dark)
                                .strong()
                                .size(12.0),
                        )
                        .fill(palette.accent)
                        .min_size(Vec2::new(ui.available_width().max(0.0), 30.0));
                        if ui.add_enabled(!is_busy, btn).clicked() {
                            self.connect();
                        }
                    }
                }
            });

        // Key panel connector-notch accents on top corners (--signal-amber)
        let card_rect = card_resp.response.rect;
        let notch_w = 12.0_f32;
        let notch_h = 2.0_f32;
        ui.painter().rect_filled(
            egui::Rect::from_min_size(card_rect.min, egui::vec2(notch_w, notch_h)),
            Rounding::ZERO,
            palette.accent,
        );
        ui.painter().rect_filled(
            egui::Rect::from_min_size(
                egui::pos2(card_rect.max.x - notch_w, card_rect.min.y),
                egui::vec2(notch_w, notch_h),
            ),
            Rounding::ZERO,
            palette.accent,
        );

        ui.add_space(14.0);
        ui.label(
            RichText::new("NAVIGATION")
                .color(palette.text_muted)
                .size(10.0)
                .strong(),
        );
        ui.add_space(4.0);

        // Vertical Navigation Tabs
        let tabs = [
            Tab::Flasher,
            Tab::Partitions,
            Tab::Tools,
            Tab::Settings,
        ];

        for tab in tabs {
            let is_selected = self.persisted.tab == tab;
            let (bg_fill, border_stroke, text_color) = if is_selected {
                (
                    palette.accent_dim,
                    Stroke::new(1.0_f32, palette.accent),
                    palette.text,
                )
            } else {
                (
                    Color32::TRANSPARENT,
                    Stroke::NONE,
                    palette.text_muted,
                )
            };

            let frame = Frame::none()
                .fill(bg_fill)
                .stroke(border_stroke)
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::symmetric(10.0, 9.0));

            let resp = frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    if is_selected {
                        let (bar_rect, _) = ui.allocate_exact_size(Vec2::new(3.0, 14.0), egui::Sense::hover());
                        ui.painter().rect_filled(bar_rect, Rounding::ZERO, palette.accent);
                        ui.add_space(6.0);
                    } else {
                        ui.add_space(9.0);
                    }
                    ui.label(
                        RichText::new(tab.label())
                            .color(if is_selected { palette.text } else { text_color })
                            .strong()
                            .size(12.5),
                    );

                    // Optional badge
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        match tab {
                            Tab::Flasher if !self.scatter_rows.is_empty() => {
                                Self::sidebar_count_badge(ui, self.scatter_rows.len(), palette);
                            }
                            Tab::Partitions if !self.partitions.is_empty() => {
                                Self::sidebar_count_badge(ui, self.partitions.len(), palette);
                            }
                            _ => {}
                        }
                    });
                });
            });

            if resp.response.interact(egui::Sense::click()).clicked() {
                self.persisted.tab = tab;
            }

            ui.add_space(3.0);
        }

        // Bottom Footer in Sidebar: Version info
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.add_space(6.0);
            ui.label(
                RichText::new("Penumbra v2.0")
                    .color(palette.text_muted)
                    .size(10.0),
            );
            ui.separator();
        });
    }

    fn sidebar_count_badge(ui: &mut Ui, count: usize, palette: &Palette) {
        Frame::none()
            .fill(palette.panel_alt)
            .rounding(Rounding::same(3.0))
            .inner_margin(Margin::symmetric(6.0, 1.0))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!("{count}"))
                        .color(palette.accent)
                        .size(10.0),
                );
            });
    }

    fn chip_badge(ui: &mut Ui, label: &str, active: bool, palette: &Palette) {
        let (bg, fg) = if active {
            (palette.success.gamma_multiply(0.2), palette.success)
        } else {
            (palette.panel, palette.text_faint)
        };

        Frame::none()
            .fill(bg)
            .rounding(Rounding::same(3.0))
            .inner_margin(Margin::symmetric(4.0, 2.0))
            .show(ui, |ui| {
                ui.label(RichText::new(label).color(fg).size(9.5));
            });
    }

    fn render_screen_header(&self, ui: &mut Ui, palette: &Palette) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(self.persisted.tab.label())
                    .color(palette.text)
                    .size(18.0)
                    .strong(),
            );
            ui.label(RichText::new("-").color(palette.text_muted));
            ui.label(
                RichText::new(self.persisted.tab.description())
                    .color(palette.text_muted)
                    .size(12.0),
            );

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (status_text, status_color) = match self.status {
                    ConnStatus::Connected(ref port) => (format!("Device Ready ({port})"), palette.success),
                    ConnStatus::Connecting => ("Handshaking...".to_string(), palette.warn),
                    ConnStatus::Disconnected => ("Device Offline".to_string(), palette.text_faint),
                };
                Frame::none()
                    .fill(palette.panel)
                    .stroke(Stroke::new(1.0_f32, palette.border))
                    .rounding(Rounding::same(3.0))
                    .inner_margin(Margin::symmetric(10.0, 4.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new(status_text).color(status_color).size(11.0));
                    });
            });
        });
        ui.separator();
    }
}

// ---------------------------------------------------------------------------
// Flasher Screen Implementation
// ---------------------------------------------------------------------------

impl App {
    fn render_flasher_tab(&mut self, ui: &mut Ui, palette: &Palette) {
        // Top Firmware Configuration Card
        Frame::none()
            .fill(palette.panel_alt)
            .stroke(Stroke::new(1.0_f32, palette.border))
            .rounding(Rounding::same(3.0))
            .inner_margin(Margin::same(12.0))
            .show(ui, |ui| {
                // Scatter File Row
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Scatter File:")
                            .color(palette.text)
                            .strong()
                            .size(12.0),
                    );
                    let scatter_text = self
                        .persisted
                        .scatter_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "No scatter file loaded".to_string());

                    ui.add(
                        egui::Label::new(
                            RichText::new(&scatter_text)
                                .color(if self.persisted.scatter_path.is_some() {
                                    palette.text
                                } else {
                                    palette.text_muted
                                })
                                .monospace()
                                .size(11.5),
                        )
                        .truncate(),
                    );

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .button(
                                RichText::new("Browse Scatter (.txt/.xml)")
                                    .color(palette.accent)
                                    .strong()
                                    .size(11.5),
                            )
                            .clicked()
                        {
                            if let Some(file) = rfd::FileDialog::new()
                                .add_filter("MediaTek Scatter", &["txt", "xml", "yaml"])
                                .pick_file()
                            {
                                self.load_scatter_file(&file);
                            }
                        }
                    });
                });
            });

        ui.add_space(10.0);

        // Sub-toolbar: Search & Quick Selections
        ui.horizontal(|ui| {
            ui.label(RichText::new("Partitions:").color(palette.text_muted).size(12.0));

            let has_partitions = !self.scatter_rows.is_empty();
            if ui.add_enabled(has_partitions, egui::Button::new(RichText::new("Select All").size(11.0))).clicked() {
                for r in &mut self.scatter_rows {
                    if r.file_exists {
                        r.selected = true;
                    }
                }
            }
            if ui.add_enabled(has_partitions, egui::Button::new(RichText::new("Deselect All").size(11.0))).clicked() {
                for r in &mut self.scatter_rows {
                    r.selected = false;
                }
            }
            if ui
                .add_enabled(has_partitions, egui::Button::new(RichText::new("Firmware Only (Skip Userdata)").size(11.0)))
                .clicked()
            {
                for r in &mut self.scatter_rows {
                    r.selected = r.file_exists && !r.name.eq_ignore_ascii_case("userdata");
                }
            }

            ui.add_space(10.0);
            ui.label(RichText::new("Search:").color(palette.text_muted).size(11.5));
            ui.add(
                egui::TextEdit::singleline(&mut self.scatter_filter)
                    .hint_text("Filter partition name...")
                    .desired_width(160.0),
            );

            // Summary metrics and Flash Selected Button
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let selected_files: Vec<(String, PathBuf)> = self
                    .scatter_rows
                    .iter()
                    .filter(|r| r.selected && r.file_path.is_some())
                    .map(|r| (r.name.clone(), r.file_path.clone().unwrap()))
                    .collect();

                let total_bytes: u64 = selected_files
                    .iter()
                    .filter_map(|(_, p)| std::fs::metadata(p).ok().map(|m| m.len()))
                    .sum();

                let count = selected_files.len();
                let is_connected = matches!(self.status, ConnStatus::Connected(_));
                let is_busy = !self.input_enabled || self.progress.active;

                let flash_btn = egui::Button::new(
                    RichText::new(format!("Flash Selected ({count})"))
                        .color(palette.btn_text_dark)
                        .strong()
                        .size(12.5),
                )
                .fill(palette.accent)
                .min_size(Vec2::new(150.0, 30.0));

                if ui
                    .add_enabled(count > 0 && is_connected && !is_busy, flash_btn)
                    .on_hover_text(if !is_connected {
                        "Connect your device first to begin flashing."
                    } else if count == 0 {
                        "Select at least one valid partition image to flash."
                    } else {
                        "Flash selected partition images to connected device."
                    })
                    .clicked()
                {
                    self.confirm_modal = Some(ConfirmModal::FlashScatter(selected_files));
                }

                ui.label(
                    RichText::new(format!(
                        "{} selected ({})",
                        count,
                        human_bytes(total_bytes as f64)
                    ))
                    .color(palette.text_muted)
                    .size(11.5),
                );
            });
        });

        ui.add_space(6.0);

        // Partition Table & Fixed Bottom Console
        let console_h = 160.0_f32;
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            self.render_bottom_console(ui, palette, console_h);
            ui.add_space(8.0);
            ui.with_layout(Layout::top_down(Align::Min), |ui| {
                ui.push_id("flasher_table_scope", |ui| {
                    let table_h = ui.available_height().max(120.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(ui.available_width(), table_h),
                        Layout::top_down(Align::Min),
                        |ui| {
                            Frame::none()
                                .fill(palette.panel)
                                .stroke(Stroke::new(1.0_f32, palette.border))
                                .rounding(Rounding::same(3.0))
                                .inner_margin(Margin::same(6.0))
                                .show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .resizable(true)
                                        .min_scrolled_height((table_h - 20.0).max(0.0))
                                        .cell_layout(Layout::left_to_right(Align::Center))
                            .column(Column::exact(36.0))                    // Checkbox
                            .column(Column::initial(130.0).at_least(100.0)) // Partition Name
                            .column(Column::initial(150.0).at_least(110.0)) // Target Image
                            .column(Column::initial(115.0))                 // Start Addr
                            .column(Column::initial(115.0))                 // End Addr
                            .column(Column::initial(85.0))                  // File Size
                            .column(Column::initial(95.0))                  // Flash Status
                            .column(Column::remainder())                    // File Location & Browse
                            .header(24.0, |mut header| {
                                header.col(|ui| {
                                    let mut all_sel = !self.scatter_rows.is_empty() && self.scatter_rows.iter().all(|r| r.selected);
                                    if theme::hardware_checkbox(ui, &mut all_sel, &palette).changed() {
                                        for r in &mut self.scatter_rows {
                                            r.selected = all_sel;
                                        }
                                    }
                                });
                                header.col(|ui| {
                                    ui.label(RichText::new("Partition").strong().color(palette.text_muted));
                                });
                                header.col(|ui| {
                                    ui.label(RichText::new("Target Image").strong().color(palette.text_muted));
                                });
                                header.col(|ui| {
                                    ui.label(RichText::new("Start Addr").strong().color(palette.text_muted));
                                });
                                header.col(|ui| {
                                    ui.label(RichText::new("End Addr").strong().color(palette.text_muted));
                                });
                                header.col(|ui| {
                                    ui.label(RichText::new("Size").strong().color(palette.text_muted));
                                });
                                header.col(|ui| {
                                    ui.label(RichText::new("Status").strong().color(palette.text_muted));
                                });
                                header.col(|ui| {
                                    ui.label(RichText::new("Location / Action").strong().color(palette.text_muted));
                                });
                            })
                            .body(|body| {
                                if self.scatter_rows.is_empty() {
                                    body.rows(28.0, 1, |mut row| {
                                        row.col(|_| {});
                                        row.col(|ui| {
                                            ui.label(RichText::new("No scatter file loaded").color(palette.text_muted).italics());
                                        });
                                        row.col(|ui| {
                                            ui.label(RichText::new("Click 'Browse Scatter' above to load firmware package").color(palette.text_muted));
                                        });
                                        row.col(|_| {});
                                        row.col(|_| {});
                                        row.col(|_| {});
                                        row.col(|_| {});
                                        row.col(|_| {});
                                    });
                                    return;
                                }

                                let filter = self.scatter_filter.to_lowercase();
                                let rows_len = self.scatter_rows.len();

                                body.rows(26.0, rows_len, |mut row| {
                                    let idx = row.index();
                                    let r = &self.scatter_rows[idx];

                                    if !filter.is_empty()
                                        && !r.name.to_lowercase().contains(&filter)
                                        && !r.file_name.to_lowercase().contains(&filter)
                                    {
                                        return;
                                    }

                                    let mut selected = r.selected;
                                    let file_exists = r.file_exists;
                                    let name = r.name.clone();
                                    let file_name = r.file_name.clone();
                                    let file_path = r.file_path.clone();
                                    let address = r.address;
                                    let size = r.size;

                                    row.col(|ui| {
                                        if theme::hardware_checkbox(ui, &mut selected, &palette).changed() {
                                            self.scatter_rows[idx].selected = selected;
                                        }
                                    });

                                    row.col(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(&name).color(palette.text).monospace().strong().size(12.0));
                                            if name.eq_ignore_ascii_case("preloader") {
                                                Frame::none()
                                                    .fill(palette.warn.gamma_multiply(0.25))
                                                    .rounding(Rounding::same(3.0))
                                                    .inner_margin(Margin::symmetric(3.0, 1.0))
                                                    .show(ui, |ui| {
                                                        ui.label(RichText::new("BL").color(palette.warn).size(9.0).strong());
                                                    });
                                            }
                                        });
                                    });

                                    row.col(|ui| {
                                        if file_name.is_empty() {
                                            ui.label(RichText::new("-").color(palette.text_muted));
                                        } else {
                                            ui.label(RichText::new(&file_name).color(palette.text_muted).monospace().size(11.5));
                                        }
                                    });

                                    row.col(|ui| {
                                        ui.label(RichText::new(format!("0x{address:08X}")).color(palette.text_muted).monospace().size(11.0));
                                    });

                                    row.col(|ui| {
                                        let end_addr = address.saturating_add(size as u64);
                                        ui.label(RichText::new(format!("0x{end_addr:08X}")).color(palette.text_muted).monospace().size(11.0));
                                    });

                                    row.col(|ui| {
                                        if size > 0 {
                                            ui.label(RichText::new(human_bytes(size as f64)).color(palette.text).size(11.5));
                                        } else {
                                            ui.label(RichText::new("-").color(palette.text_muted));
                                        }
                                    });

                                    row.col(|ui| {
                                        if file_exists {
                                            ui.label(RichText::new("Ready").color(palette.success).size(11.5));
                                        } else if file_name.is_empty() {
                                            ui.label(RichText::new("Erase Only").color(palette.error).size(11.0));
                                        } else {
                                            ui.label(RichText::new("Unassigned").color(palette.text_faint).size(11.0));
                                        }
                                    });

                                    row.col(|ui| {
                                        ui.horizontal(|ui| {
                                            let btn_label = if file_path.is_some() { "Re-select" } else { "Browse..." };
                                            if ui.button(RichText::new(btn_label).size(10.5)).clicked() {
                                                if let Some(custom_file) = rfd::FileDialog::new().pick_file() {
                                                    self.scatter_rows[idx].file_path = Some(custom_file);
                                                    self.scatter_rows[idx].file_exists = true;
                                                    self.scatter_rows[idx].selected = true;
                                                }
                                            }
                                            if let Some(ref p) = file_path {
                                                ui.add(egui::Label::new(RichText::new(p.display().to_string()).color(palette.text_muted).size(10.5)).truncate());
                                            }
                                        });
                                    });
                                });
                            });
                    });
                });
            });
            });
        });
    }
}

// ---------------------------------------------------------------------------
// Partitions Tab Implementation (PGPT Manager)
// ---------------------------------------------------------------------------

impl App {
    fn render_partitions_tab(&mut self, ui: &mut Ui, palette: &Palette) {
        let is_connected = matches!(self.status, ConnStatus::Connected(_));
        let is_busy = !self.input_enabled || self.progress.active;

        // Auto-load partition table when entering tab if connected and not yet loaded
        if is_connected && self.partitions.is_empty() && !is_busy {
            self.send_cmd(Command::LoadPartitions);
        }

        // Toolbar: Output Folder & Primary Actions
        Frame::none()
            .fill(palette.panel_alt)
            .stroke(Stroke::new(1.0_f32, palette.border))
            .rounding(Rounding::same(3.0))
            .inner_margin(Margin::same(10.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Output Folder:").color(palette.text_muted).size(12.0));

                    let dir_text = self
                        .persisted
                        .output_dir
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "/home/ydnar/Downloads/penumbra_backup".to_string());

                    ui.add(
                        egui::Label::new(
                            RichText::new(&dir_text)
                                .color(if self.persisted.output_dir.is_some() {
                                    palette.text
                                } else {
                                    palette.text_muted
                                })
                                .monospace()
                                .size(11.5),
                        )
                        .truncate(),
                    );

                    if ui.button(RichText::new("Browse...").size(11.0)).clicked() {
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.persisted.output_dir = Some(folder);
                        }
                    }

                    ui.add_space(12.0);

                    let read_btn = egui::Button::new(
                        RichText::new("Read Partition Table")
                            .color(if is_connected { palette.accent } else { palette.text_muted })
                            .strong()
                            .size(11.5),
                    )
                    .fill(palette.panel);

                    if ui.add_enabled(is_connected && !is_busy, read_btn).clicked() {
                        self.send_cmd(Command::LoadPartitions);
                    }

                    let selected_count = self.partitions.iter().filter(|p| p.selected).count();
                    let read_sel_btn = egui::Button::new(
                        RichText::new(format!("Read Selected ({selected_count})"))
                            .color(if is_connected && selected_count > 0 { palette.text } else { palette.text_muted })
                            .size(11.5),
                    );
                    if ui
                        .add_enabled(is_connected && !is_busy && selected_count > 0, read_sel_btn)
                        .clicked()
                    {
                        let dir = self.persisted.output_dir.clone().unwrap_or_else(|| {
                            dirs_next::download_dir()
                                .unwrap_or_else(|| dirs_next::home_dir().unwrap_or_else(|| PathBuf::from(".")))
                                .join("penumbra_backup")
                        });
                        let names = self.partitions.iter().filter(|p| p.selected).map(|p| p.partition.name.clone()).collect();
                        self.send_cmd(Command::BatchBackup { names, output_dir: dir });
                    }

                    let backup_btn = egui::Button::new(
                        RichText::new("Backup All")
                            .color(if is_connected && !self.partitions.is_empty() { palette.text } else { palette.text_muted })
                            .size(11.5),
                    );
                    if ui
                        .add_enabled(is_connected && !is_busy && !self.partitions.is_empty(), backup_btn)
                        .clicked()
                    {
                        let dir = self.persisted.output_dir.clone().unwrap_or_else(|| {
                            dirs_next::download_dir()
                                .unwrap_or_else(|| dirs_next::home_dir().unwrap_or_else(|| PathBuf::from(".")))
                                .join("penumbra_backup")
                        });
                        let names = self.partitions.iter().map(|p| p.partition.name.clone()).collect();
                        self.send_cmd(Command::BatchBackup { names, output_dir: dir });
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{} partitions", self.partitions.len()))
                                .color(palette.text_muted)
                                .size(11.5),
                        );
                        ui.add_space(8.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.partition_filter)
                                .hint_text("Search partition...")
                                .desired_width(140.0),
                        );
                        ui.label(RichText::new("Filter:").color(palette.text_muted).size(11.5));
                    });
                });
            });

        ui.add_space(6.0);

        // Sub-toolbar: Selection actions
        ui.horizontal(|ui| {
            let has_parts = !self.partitions.is_empty();
            if ui.add_enabled(has_parts, egui::Button::new(RichText::new("Select All").size(11.0))).clicked() {
                for p in &mut self.partitions {
                    p.selected = true;
                }
            }
            if ui.add_enabled(has_parts, egui::Button::new(RichText::new("Deselect All").size(11.0))).clicked() {
                for p in &mut self.partitions {
                    p.selected = false;
                }
            }
        });

        ui.add_space(4.0);

        // Partitions Table & Fixed Bottom Console
        let console_h = 160.0_f32;
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            self.render_bottom_console(ui, palette, console_h);
            ui.add_space(8.0);
            ui.with_layout(Layout::top_down(Align::Min), |ui| {
                ui.push_id("partitions_table_scope", |ui| {
                    let table_h = ui.available_height().max(120.0);
                    ui.allocate_ui_with_layout(
                        Vec2::new(ui.available_width(), table_h),
                        Layout::top_down(Align::Min),
                        |ui| {
                            Frame::none()
                                .fill(palette.panel)
                                .stroke(Stroke::new(1.0_f32, palette.border))
                                .rounding(Rounding::same(3.0))
                                .inner_margin(Margin::same(6.0))
                                .show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .resizable(true)
                                        .min_scrolled_height((table_h - 20.0).max(0.0))
                                        .cell_layout(Layout::left_to_right(Align::Center))
                                        .column(Column::exact(36.0))                    // Checkbox
                                        .column(Column::exact(45.0))                    // Index
                                        .column(Column::initial(150.0).at_least(100.0)) // Partition Name
                                        .column(Column::initial(115.0))                 // Start Addr
                                        .column(Column::initial(115.0))                 // End Addr
                                        .column(Column::initial(95.0))                  // Size
                                        .column(Column::remainder())                    // Operations
                                        .header(24.0, |mut header| {
                                            header.col(|ui| {
                                                let mut all_sel = !self.partitions.is_empty() && self.partitions.iter().all(|p| p.selected);
                                                if theme::hardware_checkbox(ui, &mut all_sel, &palette).changed() {
                                                    for p in &mut self.partitions {
                                                        p.selected = all_sel;
                                                    }
                                                }
                                            });
                                            header.col(|ui| { ui.label(RichText::new("#").strong().color(palette.text_muted)); });
                                            header.col(|ui| { ui.label(RichText::new("Partition").strong().color(palette.text_muted)); });
                                            header.col(|ui| { ui.label(RichText::new("Start Addr").strong().color(palette.text_muted)); });
                                            header.col(|ui| { ui.label(RichText::new("End Addr").strong().color(palette.text_muted)); });
                                            header.col(|ui| { ui.label(RichText::new("Size").strong().color(palette.text_muted)); });
                                            header.col(|ui| { ui.label(RichText::new("Operations").strong().color(palette.text_muted)); });
                                        })
                                        .body(|body| {
                                            if self.partitions.is_empty() {
                                                body.rows(28.0, 1, |mut row| {
                                                    row.col(|_| {});
                                                    row.col(|_| {});
                                                    row.col(|ui| {
                                                        ui.label(RichText::new("No partition table loaded").color(palette.text_muted).italics());
                                                    });
                                                    row.col(|ui| {
                                                        ui.label(RichText::new("Connect device and click 'Read Partition Table'").color(palette.text_muted));
                                                    });
                                                    row.col(|_| {});
                                                    row.col(|_| {});
                                                    row.col(|_| {});
                                                });
                                                return;
                                            }

                                            let filter = self.partition_filter.to_lowercase();
                                            let len = self.partitions.len();

                                            body.rows(24.0, len, |mut row| {
                                                let idx = row.index();
                                                let p = &self.partitions[idx].partition;

                                                if !filter.is_empty() && !p.name.to_lowercase().contains(&filter) {
                                                    return;
                                                }

                                                let mut selected = self.partitions[idx].selected;
                                                let name = p.name.clone();
                                                let size = p.size;
                                                let start_addr = p.address;
                                                let end_addr = p.address.saturating_add(p.size as u64);
                                                let is_critical = is_critical_partition(&name);

                                                row.col(|ui| {
                                                    if theme::hardware_checkbox(ui, &mut selected, &palette).changed() {
                                                        self.partitions[idx].selected = selected;
                                                    }
                                                });
                                                row.col(|ui| { ui.label(RichText::new(format!("{idx}")).color(palette.text_muted).size(11.0)); });
                                                row.col(|ui| {
                                                    ui.horizontal(|ui| {
                                                        ui.label(RichText::new(&name).color(palette.text).monospace().strong().size(12.0));
                                                        if is_critical {
                                                            Frame::none()
                                                                .fill(palette.warn.gamma_multiply(0.25))
                                                                .rounding(Rounding::same(3.0))
                                                                .inner_margin(Margin::symmetric(3.0, 1.0))
                                                                .show(ui, |ui| {
                                                                    ui.label(RichText::new("CRIT").color(palette.warn).size(9.0).strong());
                                                                });
                                                        }
                                                    });
                                                });
                                                row.col(|ui| { ui.label(RichText::new(format!("0x{start_addr:08X}")).color(palette.text_muted).monospace().size(11.0)); });
                                                row.col(|ui| { ui.label(RichText::new(format!("0x{end_addr:08X}")).color(palette.text_muted).monospace().size(11.0)); });
                                                row.col(|ui| { ui.label(RichText::new(human_bytes(size as f64)).color(palette.text).size(11.5)); });
                                                row.col(|ui| {
                                                    ui.horizontal(|ui| {
                                                        if ui.button(RichText::new("Dump").size(10.5)).clicked() {
                                                            let dest = if let Some(ref dir) = self.persisted.output_dir {
                                                                let _ = std::fs::create_dir_all(dir);
                                                                dir.join(format!("{name}.img"))
                                                            } else if let Some(dest) = rfd::FileDialog::new().set_file_name(&format!("{name}.img")).save_file() {
                                                                dest
                                                            } else {
                                                                return;
                                                            };
                                                            self.send_cmd(Command::ReadPartition {
                                                                name: name.clone(),
                                                                output_path: dest,
                                                            });
                                                        }
                                                        if ui.button(RichText::new("Write").size(10.5)).clicked() {
                                                            if let Some(src) = rfd::FileDialog::new().pick_file() {
                                                                self.confirm_modal = Some(ConfirmModal::FlashPartition {
                                                                    name: name.clone(),
                                                                    path: src,
                                                                });
                                                            }
                                                        }
                                                        if is_critical {
                                                            ui.add_enabled(
                                                                false,
                                                                egui::Button::new(
                                                                    RichText::new("Protected").color(palette.warn).size(10.5),
                                                                ),
                                                            )
                                                            .on_disabled_hover_text("Critical bootloader partition (LK / Preloader): Erasing is prohibited to prevent device brick.");
                                                        } else if ui.button(RichText::new("Erase").color(palette.error).size(10.5)).clicked() {
                                                            self.confirm_modal = Some(ConfirmModal::ErasePartition(name.clone()));
                                                        }
                                                    });
                                                });
                                            });
                                        });
                                });
                        });
                });
            });
        });
    }
}

// ---------------------------------------------------------------------------
// Tools & Power Tab Implementation
// ---------------------------------------------------------------------------

impl App {
    fn render_tools_tab(&mut self, ui: &mut Ui, palette: &Palette) {
        let is_connected = matches!(self.status, ConnStatus::Connected(_));
        let is_busy = !self.input_enabled || self.progress.active;

        ScrollArea::vertical().id_salt("tools_scroll").show(ui, |ui| {
            // Full Width Device Power & Reboot Card
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(16.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("Device Reboot & Power Targets").strong().color(palette.text).size(15.0));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Command the device to exit Download Agent mode and transition to the target operating system.")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                    ui.add_space(16.0);

                    ui.columns(4, |cols| {
                        Self::reboot_tile(
                            &mut cols[0],
                            "Normal Boot",
                            "Reboot device into standard Android OS",
                            is_connected && !is_busy,
                            palette.accent,
                            palette,
                            || Some(ConfirmModal::Reboot(BootMode::Normal)),
                            &mut self.confirm_modal,
                        );
                        Self::reboot_tile(
                            &mut cols[1],
                            "Fastboot",
                            "Reboot into MediaTek Fastboot bootloader",
                            is_connected && !is_busy,
                            palette.text,
                            palette,
                            || Some(ConfirmModal::Reboot(BootMode::Fastboot)),
                            &mut self.confirm_modal,
                        );
                        Self::reboot_tile(
                            &mut cols[2],
                            "Meta Mode",
                            "Reboot into Factory Meta mode for calibration",
                            is_connected && !is_busy,
                            palette.text,
                            palette,
                            || Some(ConfirmModal::Reboot(BootMode::Meta)),
                            &mut self.confirm_modal,
                        );
                        Self::reboot_tile(
                            &mut cols[3],
                            "Power Off",
                            "Shut down device and release hardware bus",
                            is_connected && !is_busy,
                            palette.error,
                            palette,
                            || Some(ConfirmModal::Shutdown),
                            &mut self.confirm_modal,
                        );
                    });
                });

            ui.add_space(12.0);

            // Bootloader (seccfg) bypass card
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(16.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("Bootloader & Security (seccfg)").strong().color(palette.text).size(15.0));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Unlock or relock the bootloader by patching the seccfg partition. Requires an exploitable or unfused device in DA mode.")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                    ui.add_space(16.0);

                    ui.columns(2, |cols| {
                        Self::reboot_tile(
                            &mut cols[0],
                            "Unlock Bootloader",
                            "Set seccfg to unlocked (allows booting unverified images)",
                            is_connected && !is_busy,
                            palette.error,
                            palette,
                            || Some(ConfirmModal::UnlockBootloader),
                            &mut self.confirm_modal,
                        );
                        Self::reboot_tile(
                            &mut cols[1],
                            "Relock Bootloader",
                            "Set seccfg back to the locked state",
                            is_connected && !is_busy,
                            palette.text,
                            palette,
                            || Some(ConfirmModal::LockBootloader),
                            &mut self.confirm_modal,
                        );
                    });
                });

            ui.add_space(12.0);

            // RPMB security card
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(16.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("RPMB Security").strong().color(palette.text).size(15.0));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Authenticate, unlock or relock the RPMB region. Unlocking requires an exploitable DA and works on UFS devices with the default MediaTek lock state.")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                    ui.add_space(12.0);

                    ui.horizontal(|ui| {
                        ui.label(RichText::new("RPMB Key (hex):").color(palette.text).size(12.0));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.rpmb_key)
                                .desired_width(200.0)
                                .hint_text("e.g. 0011223344556677...")
                                .interactive(!is_busy),
                        );
                    });
                    ui.add_space(8.0);

                    let key_valid = !self.rpmb_key.trim().is_empty();
                    let auth_btn = egui::Button::new(RichText::new("Authenticate RPMB").size(11.5))
                        .min_size(Vec2::new(ui.available_width().max(0.0), 26.0));
                    if ui
                        .add_enabled(is_connected && !is_busy && key_valid, auth_btn)
                        .on_disabled_hover_text("Connect a device and provide a hex encoded RPMB key")
                        .clicked()
                    {
                        let key = self.rpmb_key.trim().to_string();
                        let _ = self.handle.cmd_tx.send(Command::RpmbAuth { key });
                    }
                    ui.add_space(8.0);

                    ui.columns(2, |cols| {
                        Self::reboot_tile(
                            &mut cols[0],
                            "Unlock RPMB",
                            "Bypass the default MediaTek RPMB lock (UFS only)",
                            is_connected && !is_busy,
                            palette.error,
                            palette,
                            || Some(ConfirmModal::UnlockRpmb),
                            &mut self.confirm_modal,
                        );
                        Self::reboot_tile(
                            &mut cols[1],
                            "Relock RPMB",
                            "Restore the default RPMB lock state",
                            is_connected && !is_busy,
                            palette.text,
                            palette,
                            || Some(ConfirmModal::LockRpmb),
                            &mut self.confirm_modal,
                        );
                    });
                });
        });
    }

    fn reboot_tile<F>(
        ui: &mut Ui,
        title: &str,
        desc: &str,
        enabled: bool,
        accent: Color32,
        palette: &Palette,
        modal_factory: F,
        modal_out: &mut Option<ConfirmModal>,
    ) where
        F: FnOnce() -> Option<ConfirmModal>,
    {
        Frame::none()
            .fill(palette.panel)
            .stroke(Stroke::new(1.0_f32, palette.border))
            .rounding(Rounding::same(3.0))
            .inner_margin(Margin::same(12.0))
            .show(ui, |ui| {
                ui.label(RichText::new(title).strong().color(accent).size(13.0));
                ui.add_space(4.0);
                ui.label(RichText::new(desc).color(palette.text_muted).size(11.0));
                ui.add_space(10.0);

                let btn = egui::Button::new(RichText::new("Execute").size(11.5))
                    .min_size(Vec2::new(ui.available_width().max(0.0), 26.0));

                if ui.add_enabled(enabled, btn).clicked() {
                    *modal_out = modal_factory();
                }
            });
    }
}

// ---------------------------------------------------------------------------
// Reusable Bottom Console Log Component
// ---------------------------------------------------------------------------

impl App {
    fn render_bottom_console(&mut self, ui: &mut Ui, palette: &Palette, height: f32) {
        ui.push_id("bottom_console_scope", |ui| {
            ui.allocate_ui_with_layout(
                Vec2::new(ui.available_width(), height),
                Layout::top_down(Align::Min),
                |ui| {
                Frame::none()
                    .fill(palette.panel)
                    .stroke(Stroke::new(1.0_f32, palette.border))
                    .rounding(Rounding::same(3.0))
                    .inner_margin(Margin::same(8.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Console Logs").strong().color(palette.text).size(12.0));
                            ui.add_space(8.0);
                            ui.label(RichText::new("Filter:").color(palette.text_muted).size(11.0));
                            let filters = [
                                (LogFilter::All, "All"),
                                (LogFilter::Error, "Errors"),
                                (LogFilter::Warn, "Warnings"),
                                (LogFilter::Info, "Info"),
                            ];
                            for (f, label) in filters {
                                let active = self.log_filter == f;
                                let btn = egui::Button::new(
                                    RichText::new(label)
                                        .color(if active { palette.accent } else { palette.text_muted })
                                        .size(10.5),
                                );
                                if ui.add(btn).clicked() {
                                    self.log_filter = f;
                                }
                            }

                            ui.add_space(8.0);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.log_search)
                                    .hint_text("Search logs...")
                                    .desired_width(140.0),
                            );

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.button(RichText::new("Clear").size(10.5)).clicked() {
                                    self.logs.clear();
                                }
                                if ui.button(RichText::new("Copy").size(10.5)).clicked() {
                                    let full_text: String = self
                                        .logs
                                        .iter()
                                        .map(|l| format!("[{}] {}\n", l.level, l.message))
                                        .collect();
                                    ui.output_mut(|o| o.copied_text = full_text);
                                    self.toast("Copied console log to clipboard");
                                }
                                theme::hardware_checkbox_labeled(
                                    ui,
                                    &mut self.log_autoscroll,
                                    RichText::new("Auto-scroll").size(10.5),
                                    &palette,
                                );
                            });
                        });

                        ui.separator();

                        ScrollArea::vertical()
                            .id_salt("bottom_console_scroll")
                            .stick_to_bottom(self.log_autoscroll)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let search = self.log_search.to_lowercase();
                                if self.logs.is_empty() {
                                    ui.label(RichText::new("No log output yet.").color(palette.text_muted).italics().size(11.0));
                                    return;
                                }
                                for line in &self.logs {
                                    let matches_level = match self.log_filter {
                                        LogFilter::All => true,
                                        LogFilter::Error => line.level == log::Level::Error,
                                        LogFilter::Warn => line.level <= log::Level::Warn,
                                        LogFilter::Info => line.level <= log::Level::Info,
                                    };

                                    if !matches_level {
                                        continue;
                                    }
                                    if !search.is_empty() && !line.message.to_lowercase().contains(&search) {
                                        continue;
                                    }

                                    let level_color = match line.level {
                                        log::Level::Error => palette.error,
                                        log::Level::Warn => palette.warn,
                                        log::Level::Info => palette.accent,
                                        log::Level::Debug | log::Level::Trace => palette.text_muted,
                                    };

                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(format!("[{:5}]", line.level))
                                                .color(level_color)
                                                .monospace()
                                                .size(10.5),
                                        );
                                        ui.label(
                                            RichText::new(&line.message)
                                                .color(palette.text)
                                                .monospace()
                                                .size(10.5),
                                        );
                                    });
                                }
                            });
                    });
            });
        });
    }
}

// ---------------------------------------------------------------------------
// Settings Tab Implementation
// ---------------------------------------------------------------------------

impl App {
    fn render_settings_tab(&mut self, ui: &mut Ui, palette: &Palette) {
        // Computed up front: the panel closure below holds mutable borrows of
        // several fields (path rows, text inputs) for its whole duration, so
        // anything the cards must read is captured into locals here instead.
        let is_busy = !self.input_enabled || self.progress.active;
        let has_da = self.persisted.da_path.is_some();
        let patch_out = self
            .persisted
            .da_path
            .as_ref()
            .map(patched_output_path)
            .unwrap_or_default();

        ScrollArea::vertical().id_salt("settings_scroll").show(ui, |ui| {
            // Hardware Port Backend Setting
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(14.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("Hardware Port Driver Backend").strong().color(palette.text).size(13.5));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Choose which USB or serial driver Penumbra uses to communicate with device BROM.")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                    ui.add_space(10.0);

                    let backends = [
                        BackendChoice::Auto,
                        BackendChoice::Libusb,
                        BackendChoice::Usb,
                        BackendChoice::Serial,
                    ];

                    for b in backends {
                        let is_sel = self.persisted.backend == b;
                        ui.horizontal(|ui| {
                            ui.radio_value(
                                &mut self.persisted.backend,
                                b,
                                RichText::new(b.label())
                                    .strong()
                                    .color(if is_sel { palette.text } else { palette.text_muted })
                                    .size(12.5),
                            );
                            ui.label(
                                RichText::new(format!("- {}", b.detail()))
                                    .color(if is_sel { palette.text } else { palette.text_faint })
                                    .size(11.5),
                            );
                        });
                        ui.add_space(4.0);
                    }
                });

            ui.add_space(12.0);

            // Custom Binary Overrides
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(14.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("Binary & Authentication Overrides").strong().color(palette.text).size(13.5));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Optional overrides for custom signed Download Agent (DA) and preloader binaries.")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                    ui.add_space(12.0);

                    egui::Grid::new("settings_paths_grid")
                        .num_columns(3)
                        .spacing([12.0, 8.0])
                        .show(ui, |ui| {
                            Self::grid_path_row(
                                ui,
                                "Custom DA File:",
                                &mut self.persisted.da_path,
                                "Embedded default (da.bin)",
                                &["bin"],
                                palette,
                            );
                            Self::grid_path_row(
                                ui,
                                "Preloader File:",
                                &mut self.persisted.preloader_path,
                                "Auto-detected from scatter",
                                &["bin", "img"],
                                palette,
                            );
                            Self::grid_path_row(
                                ui,
                                "SLA Auth File:",
                                &mut self.persisted.auth_path,
                                "None (bypass enabled)",
                                &["bin", "auth"],
                                palette,
                            );
                            Self::grid_folder_row(
                                ui,
                                "ROM Backup Directory:",
                                &mut self.persisted.output_dir,
                                "~/penumbra_backup",
                                palette,
                            );
                        });
                });

            ui.add_space(12.0);

            // Interface & Theme
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(14.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("Appearance").strong().color(palette.text).size(13.5));
                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Color Theme:").color(palette.text).size(12.0));
                        let prev_theme = self.persisted.theme;
                        egui::ComboBox::from_id_salt("settings_theme_picker")
                            .selected_text(RichText::new(self.persisted.theme.label()).size(12.0))
                            .width(240.0)
                            .show_ui(ui, |ui| {
                                for t in ThemeId::ALL {
                                    ui.selectable_value(&mut self.persisted.theme, *t, t.label());
                                }
                            });
                        if self.persisted.theme != prev_theme {
                            theme::apply(self.persisted.theme.palette(), ui.ctx());
                        }
                    });
                });

            ui.add_space(12.0);

            // Patch Download Agent (offline)
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(14.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("Patch Download Agent (Offline)").strong().color(palette.text).size(13.5));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Apply the exploitation patches to a DA file and write a patched copy. Equivalent to the `antumbra patchda` command. No device connection required.")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                    ui.add_space(10.0);

                    ui.label(
                        RichText::new(if has_da {
                            format!("Output: {patch_out}")
                        } else {
                            "Set a Custom DA File above to enable patching.".to_string()
                        })
                        .color(if has_da { palette.text_muted } else { palette.warn })
                        .monospace()
                        .size(10.5),
                    );
                    ui.add_space(8.0);

                    let btn = egui::Button::new(RichText::new("Patch DA").size(11.5))
                        .min_size(Vec2::new(ui.available_width().max(0.0), 26.0));
                    if ui
                        .add_enabled(!is_busy && has_da, btn)
                        .on_disabled_hover_text("Set a Custom DA File in 'Binary & Authentication Overrides' first")
                        .clicked()
                    {
                        self.patch_da_requested = true;
                    }
                });

            ui.add_space(12.0);

            // Online SLA / DAA signing server
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(14.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("SLA / DAA Online Signing").strong().color(palette.text).size(13.5));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Sign SLA protected devices through a remote Penumbra signing server. Credentials are stored in the OS config directory. Restart the GUI after saving to apply.")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.auth_online, RichText::new("Enable online auth").color(palette.text).size(12.0));
                    });
                    ui.add_space(6.0);

                    egui::Grid::new("sla_settings_grid")
                        .num_columns(2)
                        .spacing([12.0, 8.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("Server endpoint:").color(palette.text).size(12.0));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.auth_endpoint)
                                    .desired_width(220.0)
                                    .hint_text("https://sign.example.com")
                                    .interactive(!is_busy),
                            );
                            ui.end_row();

                            ui.label(RichText::new("Username:").color(palette.text).size(12.0));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.auth_username)
                                    .desired_width(220.0)
                                    .hint_text("(optional)")
                                    .interactive(!is_busy),
                            );
                            ui.end_row();

                            ui.label(RichText::new("Password:").color(palette.text).size(12.0));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.auth_password)
                                    .desired_width(220.0)
                                    .hint_text("(optional)")
                                    .interactive(!is_busy),
                            );
                            ui.end_row();
                        });

                    ui.add_space(8.0);
                    if ui.button(RichText::new("Save settings").size(11.5)).clicked() {
                        self.auth_save_requested = true;
                    }
                });

            ui.add_space(12.0);

            // About Penumbra
            Frame::none()
                .fill(palette.panel_alt)
                .stroke(Stroke::new(1.0_f32, palette.border))
                .rounding(Rounding::same(3.0))
                .inner_margin(Margin::same(14.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("About Penumbra Flasher").strong().color(palette.text).size(13.5));
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Version: 2.0.0 | Protocol: MediaTek V5 (XFlash) & V6 (XML)")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                    ui.label(
                        RichText::new("Core engine: penumbra-mtk 2.0.0 | GUI: egui / eframe")
                            .color(palette.text_muted)
                            .size(11.5),
                    );
                });
        });

        // Act on the Settings tab requests now that the panel closure has
        // released its mutable borrows of the edited fields.
        if self.patch_da_requested {
            self.patch_da_requested = false;
            if let Some(input) = self.persisted.da_path.clone() {
                let output = PathBuf::from(patched_output_path(&input));
                self.send_cmd(Command::PatchDa { input_path: input, output_path: output });
            }
        }

        if self.auth_save_requested {
            self.auth_save_requested = false;

            let cfg = crate::config::PenumbraGuiConfig {
                auth: crate::config::AuthConfig {
                    online_auth: self.auth_online,
                    endpoint: trimmed_opt(&self.auth_endpoint),
                    username: trimmed_opt(&self.auth_username),
                    password: trimmed_opt(&self.auth_password),
                },
            };

            match cfg.save() {
                Ok(()) => {
                    self.toast("SLA signing settings saved. Restart the GUI to apply them.");
                }
                Err(e) => {
                    log::error!("Failed to save SLA settings: {e}");
                    self.error_modal = Some(format!("Failed to save settings: {e}"));
                }
            }
        }
    }

    fn grid_path_row(
        ui: &mut Ui,
        label: &str,
        path: &mut Option<PathBuf>,
        placeholder: &str,
        filters: &[&str],
        palette: &Palette,
    ) {
        ui.label(RichText::new(label).color(palette.text).strong().size(12.0));

        let is_custom = path.is_some();
        let text = path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| placeholder.to_string());

        ui.horizontal(|ui| {
            if is_custom {
                Frame::none()
                    .fill(palette.accent_dim)
                    .rounding(Rounding::same(3.0))
                    .inner_margin(Margin::symmetric(4.0, 1.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("OVERRIDE").color(palette.accent).size(9.0).strong());
                    });
            } else {
                Frame::none()
                    .fill(palette.panel)
                    .rounding(Rounding::same(3.0))
                    .inner_margin(Margin::symmetric(4.0, 1.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("DEFAULT").color(palette.text_faint).size(9.0));
                    });
            }

            ui.add(
                egui::Label::new(
                    RichText::new(&text)
                        .color(if is_custom { palette.text } else { palette.text_muted })
                        .monospace()
                        .size(11.0),
                )
                .truncate(),
            );
        });

        ui.horizontal(|ui| {
            if ui.button(RichText::new("Browse...").size(11.0)).clicked() {
                let mut dialog = rfd::FileDialog::new();
                if !filters.is_empty() {
                    dialog = dialog.add_filter("Supported Files", filters);
                }
                if let Some(file) = dialog.pick_file() {
                    *path = Some(file);
                }
            }

            let reset_btn = egui::Button::new(
                RichText::new("Reset to Default")
                    .color(if is_custom { palette.accent } else { palette.text_faint })
                    .size(11.0),
            );
            if ui
                .add_enabled(is_custom, reset_btn)
                .on_hover_text(if is_custom {
                    "Clear custom file override and revert back to default"
                } else {
                    "Already using default"
                })
                .clicked()
            {
                *path = None;
            }
        });
        ui.end_row();
    }

    fn grid_folder_row(
        ui: &mut Ui,
        label: &str,
        path: &mut Option<PathBuf>,
        placeholder: &str,
        palette: &Palette,
    ) {
        ui.label(RichText::new(label).color(palette.text).strong().size(12.0));

        let default_dir = dirs_next::download_dir()
            .or_else(dirs_next::home_dir)
            .map(|p| p.join("penumbra_backup"));

        let is_custom = path.as_ref() != default_dir.as_ref();
        let text = path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| placeholder.to_string());

        ui.horizontal(|ui| {
            if is_custom {
                Frame::none()
                    .fill(palette.accent_dim)
                    .rounding(Rounding::same(3.0))
                    .inner_margin(Margin::symmetric(4.0, 1.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("CUSTOM").color(palette.accent).size(9.0).strong());
                    });
            } else {
                Frame::none()
                    .fill(palette.panel)
                    .rounding(Rounding::same(3.0))
                    .inner_margin(Margin::symmetric(4.0, 1.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("DEFAULT").color(palette.text_faint).size(9.0));
                    });
            }

            ui.add(
                egui::Label::new(
                    RichText::new(&text)
                        .color(if is_custom { palette.text } else { palette.text_muted })
                        .monospace()
                        .size(11.0),
                )
                .truncate(),
            );
        });

        ui.horizontal(|ui| {
            if ui.button(RichText::new("Browse...").size(11.0)).clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    *path = Some(folder);
                }
            }

            let reset_btn = egui::Button::new(
                RichText::new("Reset to Default")
                    .color(if is_custom { palette.accent } else { palette.text_faint })
                    .size(11.0),
            );
            if ui
                .add_enabled(is_custom, reset_btn)
                .on_hover_text(if is_custom {
                    "Reset backup directory back to ~/penumbra_backup"
                } else {
                    "Already using default"
                })
                .clicked()
            {
                *path = default_dir;
            }
        });
        ui.end_row();
    }
}

// ---------------------------------------------------------------------------
// Bottom Activity & Progress Dock
// ---------------------------------------------------------------------------

impl App {
    fn render_dock(&mut self, ui: &mut Ui, palette: &Palette) {
        if self.progress.active {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&self.progress.message)
                        .color(palette.text)
                        .strong()
                        .size(12.0),
                );

                let fraction = match self.progress.total {
                    Some(total) if total > 0 => {
                        (self.progress.written as f32 / total as f32).clamp(0.0, 1.0)
                    }
                    _ => 0.0,
                };

                let pbar = egui::ProgressBar::new(fraction)
                    .show_percentage()
                    .fill(palette.accent);
                ui.add_sized(Vec2::new(260.0, 16.0), pbar);

                if let Some(total) = self.progress.total {
                    ui.label(
                        RichText::new(format!(
                            "{}/{}",
                            human_bytes(self.progress.written as f64),
                            human_bytes(total as f64)
                        ))
                        .color(palette.text_muted)
                        .size(11.0),
                    );
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .button(RichText::new("Abort Operation").color(palette.error).size(11.0))
                        .clicked()
                    {
                        self.handle.cancel.store(true, Ordering::SeqCst);
                    }
                });
            });
        } else if let Some(finished_at) = self.progress.finished_at {
            if finished_at.elapsed() < std::time::Duration::from_millis(3000) {
                let is_cancelled = self
                    .progress
                    .finished_msg
                    .as_deref()
                    .map(|m| m.to_lowercase().contains("cancel"))
                    .unwrap_or(false);
                let is_failed = self
                    .progress
                    .finished_msg
                    .as_deref()
                    .map(|m| m.to_lowercase().contains("fail"))
                    .unwrap_or(false);

                let (status_color, badge_text) = if is_failed {
                    (palette.error, "✖ Failed")
                } else if is_cancelled {
                    (palette.warn, "⚠ Cancelled")
                } else {
                    (palette.success, "✔ Complete")
                };

                ui.horizontal(|ui| {
                    theme::status_led(ui, status_color, 8.0);
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(
                            self.progress
                                .finished_msg
                                .as_deref()
                                .unwrap_or("Operation Complete"),
                        )
                        .color(status_color)
                        .strong()
                        .size(12.0),
                    );

                    let fraction = if is_failed || is_cancelled {
                        match self.progress.total {
                            Some(total) if total > 0 => {
                                (self.progress.written as f32 / total as f32).clamp(0.0, 1.0)
                            }
                            _ => 0.0,
                        }
                    } else {
                        1.0
                    };

                    let pbar = egui::ProgressBar::new(fraction)
                        .show_percentage()
                        .fill(status_color);
                    ui.add_sized(Vec2::new(260.0, 16.0), pbar);

                    if let Some(total) = self.progress.total {
                        let written = if is_failed || is_cancelled {
                            self.progress.written
                        } else {
                            total
                        };
                        ui.label(
                            RichText::new(format!(
                                "{}/{}",
                                human_bytes(written as f64),
                                human_bytes(total as f64)
                            ))
                            .color(palette.text_muted)
                            .size(11.0),
                        );
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        Frame::none()
                            .fill(status_color.gamma_multiply(0.18))
                            .stroke(Stroke::new(1.0_f32, status_color.gamma_multiply(0.4)))
                            .rounding(Rounding::same(3.0))
                            .inner_margin(Margin::symmetric(6.0, 2.0))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(badge_text)
                                        .color(status_color)
                                        .size(11.0)
                                        .strong(),
                                );
                            });
                    });
                });
            } else {
                self.progress.finished_at = None;
                self.progress.finished_msg = None;
                self.render_ready_dock(ui, palette);
            }
        } else {
            self.render_ready_dock(ui, palette);
        }
    }

    fn render_ready_dock(&mut self, ui: &mut Ui, palette: &Palette) {
        ui.horizontal(|ui| {
            theme::status_led(ui, palette.success, 8.0);
            ui.add_space(2.0);
            ui.label(RichText::new("Ready").color(palette.text_muted).size(11.0));

            ui.add_space(14.0);
            ui.label(
                RichText::new(format!("Backend: {}", self.persisted.backend.label()))
                    .color(palette.text_muted)
                    .size(11.0),
            );

            if let Some(ref path) = self.persisted.scatter_path {
                ui.add_space(14.0);
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("scatter");
                ui.label(
                    RichText::new(format!("Scatter: {name} ({} partitions)", self.scatter_rows.len()))
                        .color(palette.text_muted)
                        .size(11.0),
                );
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Confirmation Dialogs
// ---------------------------------------------------------------------------

impl App {
    fn render_confirm_modal(&mut self, ctx: &egui::Context, palette: &Palette) {
        let Some(modal) = self.confirm_modal.clone() else {
            return;
        };

        egui::Window::new(RichText::new("Confirm Action").strong().color(palette.text))
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .frame(
                Frame::none()
                    .fill(palette.panel)
                    .stroke(Stroke::new(1.0_f32, palette.border))
                    .rounding(Rounding::same(3.0))
                    .inner_margin(Margin::same(18.0)),
            )
            .show(ctx, |ui| {
                ui.set_width(380.0);

                let (message, warning, is_danger) = match &modal {
                    ConfirmModal::FlashScatter(files) => (
                        format!("Flash {} partition images to the connected device?", files.len()),
                        "Ensure USB cable remains securely connected during flashing.",
                        true,
                    ),
                    ConfirmModal::FlashPartition { name, path } => (
                        format!("Flash raw image '{}' to partition '{}'?", path.display(), name),
                        "Writing an incorrect image may prevent the device from booting.",
                        true,
                    ),
                    ConfirmModal::ErasePartition(name) => (
                        format!("Permanently wipe partition '{}'?", name),
                        "Erasing boot or security partitions can brick the device.",
                        true,
                    ),
                    ConfirmModal::UnlockBootloader => (
                        "Unlock device bootloader via DA?".to_string(),
                        "Device will permit booting unverified images. Userdata will be wiped.",
                        true,
                    ),
                    ConfirmModal::LockBootloader => (
                        "Relock device bootloader?".to_string(),
                        "Ensure all partitions are running verified stock firmware.",
                        false,
                    ),
                    ConfirmModal::UnlockRpmb => (
                        "Unlock the RPMB partition?".to_string(),
                        "Bypasses RPMB protection. Works on UFS devices with the default \
                         MediaTek lock state and requires an exploitable DA. This does not \
                         guarantee a full unlock.",
                        true,
                    ),
                    ConfirmModal::LockRpmb => (
                        "Relock the RPMB partition?".to_string(),
                        "Restores the default MediaTek RPMB lock state.",
                        false,
                    ),
                    ConfirmModal::Reboot(mode) => (
                        format!("Reboot device into {:?} mode?", mode),
                        "Device will disconnect and exit Download Agent mode.",
                        false,
                    ),
                    ConfirmModal::Shutdown => (
                        "Power off device?".to_string(),
                        "Device will safely power down.",
                        false,
                    ),
                };

                ui.label(RichText::new(message).color(palette.text).strong().size(13.0));
                ui.add_space(8.0);
                ui.label(RichText::new(warning).color(if is_danger { palette.warn } else { palette.text_muted }).size(11.5));
                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Cancel").color(palette.text_muted).size(12.0)).clicked() {
                        self.confirm_modal = None;
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let confirm_btn = egui::Button::new(
                            RichText::new("Confirm & Execute")
                                .color(if is_danger { Color32::WHITE } else { palette.btn_text_dark })
                                .strong()
                                .size(12.0),
                        )
                        .fill(if is_danger { palette.error } else { palette.accent });

                        if ui.add(confirm_btn).clicked() {
                            match modal {
                                ConfirmModal::FlashScatter(files) => {
                                    self.send_cmd(Command::FlashScatter { files });
                                }
                                ConfirmModal::FlashPartition { name, path } => {
                                    self.send_cmd(Command::WritePartition {
                                        name,
                                        input_path: path,
                                    });
                                }
                                ConfirmModal::ErasePartition(name) => {
                                    if is_critical_partition(&name) {
                                        self.toast(&format!("Cannot erase critical partition '{name}'"));
                                    } else {
                                        self.send_cmd(Command::ErasePartition { name });
                                    }
                                }
                                ConfirmModal::UnlockBootloader => {
                                    self.send_cmd(Command::Seccfg(LockAction::Unlock));
                                }
                                ConfirmModal::LockBootloader => {
                                    self.send_cmd(Command::Seccfg(LockAction::Lock));
                                }
                                ConfirmModal::UnlockRpmb => {
                                    self.send_cmd(Command::RpmbLock(LockAction::Unlock));
                                }
                                ConfirmModal::LockRpmb => {
                                    self.send_cmd(Command::RpmbLock(LockAction::Lock));
                                }
                                ConfirmModal::Reboot(mode) => {
                                    self.send_cmd(Command::Reboot(mode));
                                }
                                ConfirmModal::Shutdown => {
                                    self.send_cmd(Command::Shutdown);
                                }
                            }
                            self.confirm_modal = None;
                        }
                    });
                });
            });
    }
}

/// Default output path for a patched DA file: same directory, `<stem>_patched.bin`.
fn patched_output_path(input: &Path) -> String {
    match input.file_stem().and_then(|s| s.to_str()) {
        Some(stem) => {
            let name = format!("{stem}_patched.bin");
            match input.parent() {
                Some(parent) => parent.join(name).display().to_string(),
                None => name,
            }
        }
        None => input.display().to_string(),
    }
}

/// Returns the trimmed string as `Some` when non-empty, otherwise `None`.
fn trimmed_opt(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}
