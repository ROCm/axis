// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// AXIS Desktop — Linux native app with GTK4 + libadwaita + WebKitGTK
// Provides desktop integration, system tray, and hosts the shared frontend.

use adw::prelude::*;
use gtk4::Application;
use gtk4::prelude::*;
use libadwaita as adw;
use webkit6::prelude::*;

const APP_ID: &str = "org.axis.Desktop";
const GATEWAY_URL: &str = "http://127.0.0.1:18519";

fn main() {
    // Initialize libadwaita.
    adw::init().expect("failed to initialize libadwaita");

    let app = Application::builder().application_id(APP_ID).build();

    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    // Ensure daemon is running.
    ensure_daemon_running();

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("AXIS — Agent Sandbox")
        .default_width(1200)
        .default_height(800)
        .build();

    // Create WebKitGTK WebView.
    let webview = create_webview();

    // Use AdwToolbarView for header bar.
    let header = adw::HeaderBar::builder()
        .title_widget(&gtk4::Label::new(Some("AXIS")))
        .build();

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&webview));

    window.set_content(Some(&toolbar_view));
    window.present();
}

fn create_webview() -> webkit6::WebView {
    let settings = webkit6::Settings::new();
    settings.set_enable_developer_extras(cfg!(debug_assertions));
    settings.set_javascript_can_access_clipboard(true);

    let webview = webkit6::WebView::builder().settings(&settings).build();

    // Inject AXIS configuration via user script.
    let user_content_manager = webview.user_content_manager().unwrap();
    let script = webkit6::UserScript::new(
        &format!(
            r#"
            window.AXIS_CONFIG = {{
                gateway_url: '{}',
                token: '{}',
                platform: 'linux'
            }};
            window.AXIS_NATIVE = {{
                showNotification: (title, body) => {{
                    window.webkit.messageHandlers.axis.postMessage(
                        JSON.stringify({{ type: 'notification', title, body }})
                    );
                }},
                minimizeToTray: () => {{
                    window.webkit.messageHandlers.axis.postMessage(
                        JSON.stringify({{ type: 'minimize_to_tray' }})
                    );
                }}
            }};
            "#,
            GATEWAY_URL,
            read_daemon_token()
        ),
        webkit6::UserContentInjectedFrames::TopFrame,
        webkit6::UserScriptInjectionTime::Start,
        // Only the bundled frontend or dev server may see the daemon token.
        &["file:///*", "http://localhost:3000/*"],
        &[],
    );
    user_content_manager.add_script(&script);

    // Load the frontend.
    let adjacent_web = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("web/index.html")));
    let system_web = std::path::PathBuf::from("/usr/share/axis/web/index.html");
    let dev_url = "http://localhost:3000";

    if let Some(web_dir) = adjacent_web.filter(|path| path.exists()) {
        // Portable release archive: load resources beside the executable.
        let uri = format!("file://{}", web_dir.display());
        webview.load_uri(&uri);
    } else if system_web.exists() {
        // System package: load from the shared data directory.
        let uri = format!("file://{}", system_web.display());
        webview.load_uri(&uri);
    } else {
        // Try local build.
        let local_dist = dirs_home().join(".axis/gui/web/index.html");
        if local_dist.exists() {
            let uri = format!("file://{}", local_dist.display());
            webview.load_uri(&uri);
        } else {
            // Development: connect to Vite dev server.
            webview.load_uri(dev_url);
        }
    }

    webview
}

fn ensure_daemon_running() {
    let daemon_path = dirs_home().join(".axis/bin/axisd");
    if !daemon_path.exists() {
        return;
    }

    // Check if already running.
    let status = std::process::Command::new("pgrep")
        .args(["-x", "axisd"])
        .status();

    if let Ok(s) = status {
        if s.success() {
            return; // Already running.
        }
    }

    // Start daemon in background.
    let _ = std::process::Command::new(&daemon_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// The per-user token axisd requires on every gateway request. Waits briefly
/// for a daemon that was just started to write it.
fn read_daemon_token() -> String {
    let path = dirs_home().join(".axis/run/axisd.token");
    for _ in 0..30 {
        if let Ok(token) = std::fs::read_to_string(&path) {
            let token = token.trim();
            if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
                return token.to_string();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    String::new()
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"))
}
