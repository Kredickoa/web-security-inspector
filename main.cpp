#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commdlg.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#include "inspector.h"

#ifdef _MSC_VER
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
constexpr int Inspect = 101, Cancel = 102, Save = 103;
constexpr UINT Finished = WM_APP + 1;
struct Application {
    HWND window{}, url{}, inspect{}, cancel{}, save{}, output{}, status{};
    HFONT font{}, mono{};
    std::thread worker;
    std::atomic<bool> stopped{false};
    bool busy = false, closing = false;
    std::wstring report;
} app;
std::wstring wide(const std::string& value) {
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), size);
    return result;
}
HWND widget(const wchar_t* type, const wchar_t* label, DWORD style,
    int x, int y, int width, int height, int id = 0) {
    HWND item = CreateWindowW(type, label, WS_CHILD | WS_VISIBLE | style, x, y, width, height,
        app.window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(item, WM_SETFONT, reinterpret_cast<WPARAM>(app.font), TRUE);
    return item;
}
void busy(bool value) {
    app.busy = value;
    EnableWindow(app.url, !value); EnableWindow(app.inspect, !value);
    EnableWindow(app.cancel, value); EnableWindow(app.save, !value && !app.report.empty());
}
void start_inspection() {
    std::wstring url(GetWindowTextLengthW(app.url) + 1, L'\0');
    GetWindowTextW(app.url, url.data(), static_cast<int>(url.size()));
    url.resize(wcslen(url.c_str()));
    if (url.empty()) throw std::runtime_error("Enter a URL first.");
    app.report.clear(); app.stopped = false;
    SetWindowTextW(app.output, L"Requesting response headers...\r\nRedirects and TLS certificates are being checked.\r\nThis can take a few seconds.");
    SetWindowTextW(app.status, L"Inspecting... The window stays responsive.");
    busy(true);
    try {
        app.worker = std::thread([url] {
            try { app.report = inspect_url(url, app.stopped); }
            catch (const std::exception& error) { app.report = L"Inspection failed:\r\n" + wide(error.what()); }
            PostMessageW(app.window, Finished, 0, 0);
        });
    } catch (...) { busy(false); throw; }
}
void save_report() {
    wchar_t filename[32768] = L"report.txt";
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog); dialog.hwndOwner = app.window;
    dialog.lpstrFilter = L"Text report\0*.txt\0"; dialog.lpstrFile = filename;
    dialog.nMaxFile = 32768; dialog.lpstrDefExt = L"txt";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&dialog)) return;
    const int length = WideCharToMultiByte(CP_UTF8, 0, app.report.data(), static_cast<int>(app.report.size()), nullptr, 0, nullptr, nullptr);
    std::string bytes(length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, app.report.data(), static_cast<int>(app.report.size()), bytes.data(), length, nullptr, nullptr);
    std::ofstream file(std::filesystem::path(filename), std::ios::binary);
    file << bytes; file.close();
    if (!file) throw std::runtime_error("Could not save the report.");
    SetWindowTextW(app.status, L"Report saved as UTF-8 text.");
}
LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        app.window = window;
        app.font = CreateFontW(-17, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        app.mono = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH, L"Consolas");
        widget(L"STATIC", L"WEB SECURITY INSPECTOR", 0, 20, 16, 400, 26);
        widget(L"STATIC", L"URL", 0, 20, 60, 40, 24);
        app.url = widget(L"EDIT", L"https://example.com", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
            65, 55, 780, 30);
        SendMessageW(app.url, EM_SETLIMITTEXT, 4096, 0);
        app.inspect = widget(L"BUTTON", L"Inspect", WS_TABSTOP, 20, 103, 110, 32, Inspect);
        app.cancel = widget(L"BUTTON", L"Cancel", WS_TABSTOP, 145, 103, 110, 32, Cancel);
        app.save = widget(L"BUTTON", L"Save report...", WS_TABSTOP, 270, 103, 150, 32, Save);
        app.status = widget(L"STATIC", L"HTTPS, redirect chain, certificate details, security headers and cookie attributes.",
            0, 20, 151, 830, 24);
        app.output = widget(L"EDIT", L"Enter a URL and click Inspect.\r\n\r\nThe report describes the responses received by this tool.\r\nHeader presence alone does not establish that a website is secure.",
            WS_BORDER | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            20, 190, 830, 450);
        SendMessageW(app.output, WM_SETFONT, reinterpret_cast<WPARAM>(app.mono), TRUE);
        SendMessageW(app.output, EM_SETLIMITTEXT, 2000000, 0);
        busy(false); return 0;
    case WM_SIZE: {
        const int width = LOWORD(lparam), height = HIWORD(lparam);
        MoveWindow(app.url, 65, 55, std::max(1, width - 85), 30, TRUE);
        MoveWindow(app.status, 20, 151, std::max(1, width - 40), 24, TRUE);
        MoveWindow(app.output, 20, 190, std::max(1, width - 40), std::max(1, height - 210), TRUE);
        return 0;
    }
    case WM_GETMINMAXINFO:
        reinterpret_cast<MINMAXINFO*>(lparam)->ptMinTrackSize = {680, 480}; return 0;
    case WM_CTLCOLORSTATIC:
        SetBkColor(reinterpret_cast<HDC>(wparam), RGB(255, 255, 255));
        SetTextColor(reinterpret_cast<HDC>(wparam), RGB(30, 30, 30));
        return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
    case Finished:
        if (app.worker.joinable()) app.worker.join();
        busy(false);
        if (app.closing) { DestroyWindow(window); return 0; }
        SetWindowTextW(app.output, app.report.c_str());
        SetWindowTextW(app.status, app.stopped ? L"Stopped. Collected observations are shown below." : L"Finished. Review the response observations below.");
        return 0;
    case WM_COMMAND:
        if (HIWORD(wparam) != BN_CLICKED) break;
        try {
            switch (LOWORD(wparam)) {
            case Inspect: if (!app.busy) start_inspection(); break;
            case Cancel: app.stopped = true; SetWindowTextW(app.status, L"Stopping after the current request (bounded by network timeouts)..."); break;
            case Save: if (!app.busy && !app.report.empty()) save_report(); break;
            }
        } catch (const std::exception& error) {
            MessageBoxW(window, wide(error.what()).c_str(), L"Web Security Inspector", MB_OK | MB_ICONERROR);
        }
        return 0;
    case WM_CLOSE:
        if (app.busy) { app.closing = true; app.stopped = true; SetWindowTextW(app.status, L"Finishing the current request before closing..."); }
        else DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        DeleteObject(app.font); DeleteObject(app.mono); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    SetProcessDPIAware();
    WNDCLASSW window{};
    window.lpfnWndProc = window_proc; window.hInstance = instance; window.lpszClassName = L"JuniorWebInspector";
    window.hCursor = LoadCursorW(nullptr, IDC_ARROW); window.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassW(&window)) return 1;
    HWND handle = CreateWindowW(window.lpszClassName, L"Web Security Inspector", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1060, 800, nullptr, nullptr, instance, nullptr);
    if (!handle) return 1;
    ShowWindow(handle, show);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(handle, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
    }
    return static_cast<int>(message.wParam);
}
