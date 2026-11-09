// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

using Microsoft.Web.WebView2.Core;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;

namespace AXIS;

public partial class MainWindow : Window
{
    private const string GATEWAY_URL = "http://127.0.0.1:18520";

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        var userDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "axis", "webview2");
        Directory.CreateDirectory(userDataFolder);

        var env = await CoreWebView2Environment.CreateAsync(
            browserExecutableFolder: null,
            userDataFolder: userDataFolder);

        await WebView.EnsureCoreWebView2Async(env);

        var settings = WebView.CoreWebView2.Settings;
        settings.AreDevToolsEnabled = true;
        settings.IsStatusBarEnabled = false;

        // Native bridge.
        WebView.CoreWebView2.WebMessageReceived += OnWebMessage;

        // Inject AXIS config. The script runs in every document and frame, so
        // only the top-level frontend gets the daemon token.
        await WebView.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync($@"
            window.AXIS_CONFIG = {{
                gateway_url: '{GATEWAY_URL}',
                token: (window === window.top &&
                        (location.origin === 'https://axis.local' || location.origin === 'http://localhost:3000'))
                    ? '{ReadDaemonToken()}' : '',
                platform: 'windows'
            }};
        ");

        // Load frontend.
        var webDir = Path.Combine(AppContext.BaseDirectory, "web");
        if (Directory.Exists(webDir))
        {
            WebView.CoreWebView2.SetVirtualHostNameToFolderMapping(
                "axis.local", webDir,
                CoreWebView2HostResourceAccessKind.Allow);
            WebView.CoreWebView2.Navigate("https://axis.local/index.html");
        }
        else
        {
            WebView.CoreWebView2.Navigate("http://localhost:3000");
        }
    }

    // The per-user token axisd requires on every gateway request.
    private static string ReadDaemonToken()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "axis", "axisd.token");
        try
        {
            var token = File.ReadAllText(path).Trim();
            if (token.Length == 64 && token.All(Uri.IsHexDigit))
            {
                return token;
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return "";
    }

    private void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        var json = args.WebMessageAsJson;
        using var doc = JsonDocument.Parse(json);
        var type = doc.RootElement.GetProperty("type").GetString();

        switch (type)
        {
            case "notification":
                var title = doc.RootElement.GetProperty("title").GetString() ?? "AXIS";
                var body = doc.RootElement.GetProperty("body").GetString() ?? "";
                MessageBox.Show(body, title, MessageBoxButton.OK, MessageBoxImage.Information);
                break;
        }
    }
}
