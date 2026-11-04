// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// AXIS Desktop — macOS native app with WKWebView
// Provides menu bar integration, window management, and hosts the shared frontend.

import Cocoa
import WebKit

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    var mainWindow: NSWindow!
    var webView: WKWebView!
    var statusItem: NSStatusItem!

    private let gatewayURL = "http://127.0.0.1:18519"

    func applicationDidFinishLaunching(_ notification: Notification) {
        ensureDaemonRunning()
        setupMenuBar()
        setupMainWindow()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false // Keep running in menu bar
    }

    // MARK: - Menu Bar

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.checkered", accessibilityDescription: "AXIS")
            button.action = #selector(toggleWindow)
        }

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Show AXIS", action: #selector(showWindow), keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Agents", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit AXIS", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        statusItem.menu = menu
    }

    @objc private func toggleWindow() {
        if mainWindow.isVisible {
            mainWindow.orderOut(nil)
        } else {
            showWindow()
        }
    }

    @objc private func showWindow() {
        mainWindow.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - Main Window

    private func setupMainWindow() {
        let windowRect = NSRect(x: 0, y: 0, width: 1200, height: 800)
        mainWindow = NSWindow(
            contentRect: windowRect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        mainWindow.title = "AXIS — Agent Sandbox"
        mainWindow.center()
        mainWindow.titlebarAppearsTransparent = true
        mainWindow.titleVisibility = .hidden
        mainWindow.backgroundColor = NSColor(red: 0.051, green: 0.067, blue: 0.09, alpha: 1.0)

        // Configure WKWebView with native bridge.
        let config = WKWebViewConfiguration()
        let userContentController = WKUserContentController()

        // Inject AXIS configuration.
        let configScript = WKUserScript(
            source: """
            window.AXIS_CONFIG = {
                gateway_url: '\(gatewayURL)',
                token: '\(readDaemonToken())',
                platform: 'macos'
            };
            window.AXIS_NATIVE = {
                showNotification: (title, body) => {
                    window.webkit.messageHandlers.axis.postMessage({
                        type: 'notification', title: title, body: body
                    });
                },
                openFileDialog: (opts) => {
                    window.webkit.messageHandlers.axis.postMessage({
                        type: 'file_dialog', ...opts
                    });
                },
                minimizeToTray: () => {
                    window.webkit.messageHandlers.axis.postMessage({
                        type: 'minimize_to_tray'
                    });
                }
            };
            """,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: true
        )
        userContentController.addUserScript(configScript)
        userContentController.add(self, name: "axis")
        config.userContentController = userContentController

        // Allow local file access for production builds.
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")

        webView = WKWebView(frame: windowRect, configuration: config)
        webView.autoresizingMask = [.width, .height]
        mainWindow.contentView = webView

        loadFrontend()
        mainWindow.makeKeyAndOrderFront(nil)
    }

    private func loadFrontend() {
        // Production: load from the SwiftPM resource bundle.
        if let indexURL = Bundle.module.url(forResource: "index", withExtension: "html", subdirectory: "web") {
            webView.loadFileURL(indexURL, allowingReadAccessTo: indexURL.deletingLastPathComponent())
        } else {
            // Development: connect to Vite dev server.
            let devURL = URL(string: "http://localhost:3000")!
            webView.load(URLRequest(url: devURL))
        }
    }

    // MARK: - Daemon Lifecycle

    private func ensureDaemonRunning() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let daemonPath = home.appendingPathComponent(".axis/bin/axisd")

        guard FileManager.default.fileExists(atPath: daemonPath.path) else { return }

        // Check if already running.
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        task.arguments = ["-x", "axisd"]
        try? task.run()
        task.waitUntilExit()
        if task.terminationStatus == 0 { return } // Already running.

        // Start daemon.
        let daemon = Process()
        daemon.executableURL = daemonPath
        daemon.standardOutput = FileHandle.nullDevice
        daemon.standardError = FileHandle.nullDevice
        try? daemon.run()
    }

    /// The per-user token axisd requires on every gateway request. Waits
    /// briefly for a daemon that was just started to write it.
    private func readDaemonToken() -> String {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".axis/run/axisd.token")
        for _ in 0..<30 {
            if let raw = try? String(contentsOf: path, encoding: .utf8) {
                let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                if token.count == 64 && token.allSatisfy({ $0.isHexDigit }) {
                    return token
                }
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        return ""
    }
}

// MARK: - WKScriptMessageHandler (Native Bridge)

extension AppDelegate: WKScriptMessageHandler {
    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any],
              let type = body["type"] as? String else { return }

        switch type {
        case "notification":
            let title = body["title"] as? String ?? "AXIS"
            let body = body["body"] as? String ?? ""
            showNativeNotification(title: title, body: body)

        case "minimize_to_tray":
            mainWindow.orderOut(nil)

        case "file_dialog":
            showFileDialog()

        default:
            break
        }
    }

    private func showNativeNotification(title: String, body: String) {
        let notification = NSUserNotification()
        notification.title = title
        notification.informativeText = body
        NSUserNotificationCenter.default.deliver(notification)
    }

    private func showFileDialog() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.yaml]
        panel.begin { response in
            if response == .OK, let url = panel.url {
                let js = "window.dispatchEvent(new CustomEvent('axis:file-selected', { detail: '\(url.path)' }))"
                self.webView.evaluateJavaScript(js, completionHandler: nil)
            }
        }
    }
}
