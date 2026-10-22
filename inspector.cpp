#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include "inspector.h"
#include <algorithm>
#include <cwctype>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {
using Headers = std::vector<std::pair<std::wstring, std::wstring>>;
std::wstring trim(std::wstring value) {
    const auto start = value.find_first_not_of(L" \t\r\n");
    return start == std::wstring::npos ? L"" : value.substr(start, value.find_last_not_of(L" \t\r\n") - start + 1);
}
std::wstring lower(std::wstring value) {
    for (auto& c : value) c = static_cast<wchar_t>(towlower(c));
    return value;
}
std::wstring wide(const std::string& value) {
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), size);
    result.resize(wcslen(result.c_str()));
    return result;
}
[[noreturn]] void network_error() {
    const DWORD error = GetLastError();
    if (error == ERROR_WINHTTP_SECURE_FAILURE || error == ERROR_WINHTTP_SECURE_CERT_DATE_INVALID
        || error == ERROR_WINHTTP_SECURE_INVALID_CA || error == ERROR_WINHTTP_SECURE_CERT_CN_INVALID)
        throw std::runtime_error("TLS certificate or handshake validation failed. Certificate validation was not bypassed.");
    if (error == ERROR_WINHTTP_TIMEOUT) throw std::runtime_error("Request timed out.");
    if (error == ERROR_WINHTTP_NAME_NOT_RESOLVED) throw std::runtime_error("Cannot resolve the hostname.");
    if (error == ERROR_WINHTTP_CANNOT_CONNECT) throw std::runtime_error("Cannot connect to the server.");
    throw std::runtime_error("HTTP request failed (Windows error " + std::to_string(error) + ").");
}
struct Internet {
    HINTERNET value;
    explicit Internet(HINTERNET handle) : value(handle) { if (!value) network_error(); }
    ~Internet() { WinHttpCloseHandle(value); }
    Internet(const Internet&) = delete;
    Internet& operator=(const Internet&) = delete;
};
struct Url {
    std::wstring host, path;
    INTERNET_PORT port;
    bool secure;
};
Url parse_url(const std::wstring& value) {
    if (value.size() > 4096 || std::any_of(value.begin(), value.end(), [](wchar_t c) { return c <= 32 || c == 127; }))
        throw std::runtime_error("URL is too long or contains whitespace/control characters. Encode spaces as %20.");
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = static_cast<DWORD>(-1);
    parts.dwUserNameLength = parts.dwPasswordLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(value.c_str(), static_cast<DWORD>(value.size()), 0, &parts)
        || (parts.nScheme != INTERNET_SCHEME_HTTP && parts.nScheme != INTERNET_SCHEME_HTTPS)
        || !parts.dwHostNameLength)
        throw std::runtime_error("Enter an HTTP or HTTPS URL.");
    if (parts.dwUserNameLength || parts.dwPasswordLength)
        throw std::runtime_error("URLs containing a username or password are not accepted.");
    const auto authority_start = value.find(L"://") + 3;
    const auto authority_end = value.find_first_of(L"/?#", authority_start);
    if (value.substr(authority_start, authority_end - authority_start).find(L'@') != std::wstring::npos)
        throw std::runtime_error("URLs containing user information are not accepted.");
    Url url;
    url.host.assign(parts.lpszHostName, parts.dwHostNameLength);
    if (std::any_of(url.host.begin(), url.host.end(), [](wchar_t c) { return c > 127; }))
        throw std::runtime_error("For international hostnames, use the ASCII / punycode domain.");
    if (parts.dwUrlPathLength) url.path.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (url.path.empty()) url.path = L"/";
    if (parts.dwExtraInfoLength) url.path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    const auto fragment = url.path.find(L'#');
    if (fragment != std::wstring::npos) url.path.erase(fragment);
    url.port = parts.nPort; url.secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
    return url;
}
Headers parse_headers(const std::wstring& raw) {
    Headers headers;
    std::wistringstream stream(raw);
    std::wstring line;
    while (std::getline(stream, line)) {
        const auto colon = line.find(L':');
        if (colon != std::wstring::npos)
            headers.emplace_back(lower(trim(line.substr(0, colon))), trim(line.substr(colon + 1)));
    }
    return headers;
}
std::vector<std::wstring> values(const Headers& headers, const std::wstring& name) {
    std::vector<std::wstring> found;
    for (const auto& header : headers) if (header.first == name) found.push_back(header.second);
    return found;
}
std::wstring first(const Headers& headers, const std::wstring& name) {
    const auto found = values(headers, name);
    return found.empty() ? L"" : found.front();
}
std::wstring date(const FILETIME& filetime) {
    SYSTEMTIME time{};
    if (!FileTimeToSystemTime(&filetime, &time)) return L"unavailable";
    wchar_t buffer[48]{};
    swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u UTC", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute);
    return buffer;
}
std::wstring certificate_info(HINTERNET request) {
    PCCERT_CONTEXT raw = nullptr;
    DWORD size = sizeof(raw);
    if (!WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &raw, &size))
        return L"Certificate details unavailable.\r\n";
    std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)> certificate(raw, CertFreeCertificateContext);
    auto name = [&](DWORD flags) {
        const DWORD length = CertGetNameStringW(raw, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, nullptr, 0);
        if (!length) return std::wstring(L"unavailable");
        std::wstring value(length, L'\0');
        CertGetNameStringW(raw, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, value.data(), length);
        value.resize(length - 1); return value;
    };
    return L"Certificate accepted by Windows TLS validation.\r\nSubject: " + name(0)
        + L"\r\nIssuer: " + name(CERT_NAME_ISSUER_FLAG) + L"\r\nValid from: "
        + date(raw->pCertInfo->NotBefore) + L"\r\nValid until: " + date(raw->pCertInfo->NotAfter) + L"\r\n";
}
struct Response {
    DWORD status;
    Headers headers;
    std::wstring certificate;
};
Response request(const Url& url, HINTERNET session) {
    Internet connection(WinHttpConnect(session, url.host.c_str(), url.port, 0));
    Internet query(WinHttpOpenRequest(connection.value, L"GET", url.path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, url.secure ? WINHTTP_FLAG_SECURE : 0));
    DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES;
    if (!WinHttpSetOption(query.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled))) network_error();
    if (!WinHttpSendRequest(query.value, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        || !WinHttpReceiveResponse(query.value, nullptr)) network_error();
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(query.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) network_error();
    size = 0;
    WinHttpQueryHeaders(query.value, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
        nullptr, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size > 131072) throw std::runtime_error("Cannot read response headers or response headers are too large.");
    std::vector<wchar_t> raw(size / sizeof(wchar_t) + 1, L'\0');
    if (!WinHttpQueryHeaders(query.value, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
        raw.data(), &size, WINHTTP_NO_HEADER_INDEX)) network_error();
    return {status, parse_headers(raw.data()), url.secure ? certificate_info(query.value) : L"No TLS: this response uses HTTP.\r\n"};
}
std::wstring combine_url(const std::wstring& base, const std::wstring& location) {
    std::vector<wchar_t> buffer(8192);
    DWORD length = static_cast<DWORD>(buffer.size());
    if (FAILED(UrlCombineW(base.c_str(), location.c_str(), buffer.data(), &length, 0)))
        throw std::runtime_error("Cannot resolve the redirect URL.");
    return buffer.data();
}
std::wstring cookie_report(const Headers& headers, bool https) {
    std::wostringstream report;
    const auto cookies = values(headers, L"set-cookie");
    report << L"COOKIES: " << cookies.size() << L" Set-Cookie header(s). Values are omitted.\r\n";
    if (cookies.empty()) report << L"No cookies observed in this response; this does not describe later browser activity.\r\n";
    for (const auto& cookie : cookies) {
        std::wistringstream parts(cookie);
        std::wstring pair; std::getline(parts, pair, L';');
        const auto equals = pair.find(L'=');
        if (equals == std::wstring::npos) { report << L"[REVIEW] Malformed Set-Cookie header.\r\n"; continue; }
        const std::wstring name = trim(pair.substr(0, equals)).substr(0, 120);
        bool secure = false, http_only = false, domain = false;
        std::wstring same_site, path, attribute;
        while (std::getline(parts, attribute, L';')) {
            const auto separator = attribute.find(L'=');
            const auto key = lower(trim(attribute.substr(0, separator)));
            const auto value = separator == std::wstring::npos ? L"" : trim(attribute.substr(separator + 1));
            if (key == L"secure" && separator == std::wstring::npos) secure = true;
            if (key == L"httponly" && separator == std::wstring::npos) http_only = true;
            if (key == L"samesite") same_site = lower(value);
            if (key == L"domain") domain = true;
            if (key == L"path") path = value;
        }
        report << L"  " << name << L" | Secure=" << (secure ? L"yes" : L"no")
            << L" | HttpOnly=" << (http_only ? L"yes" : L"no") << L" | SameSite="
            << (same_site.empty() ? L"not explicit" : same_site) << L"\r\n";
        if (!secure) report << L"    [REVIEW] Secure flag missing; review whether this cookie must be HTTPS-only.\r\n";
        if (!http_only) report << L"    [INFO] JavaScript access is permitted; some application cookies need it.\r\n";
        if (same_site == L"none" && !secure) report << L"    [REVIEW] SameSite=None requires Secure in modern browsers.\r\n";
        if (!same_site.empty() && same_site != L"none" && same_site != L"lax" && same_site != L"strict")
            report << L"    [REVIEW] Unrecognised SameSite value.\r\n";
        if (name.rfind(L"__Host-", 0) == 0 && (!secure || domain || path != L"/"))
            report << L"    [REVIEW] __Host- requires Secure, Path=/ and no Domain.\r\n";
        if (name.rfind(L"__Secure-", 0) == 0 && !secure)
            report << L"    [REVIEW] __Secure- requires Secure.\r\n";
        if (!https) report << L"    [REVIEW] Set-Cookie received over HTTP; transport is not encrypted.\r\n";
    }
    return report.str();
}
std::wstring header_report(const Headers& headers, bool https) {
    std::wostringstream report;
    report << L"RESPONSE HEADER OBSERVATIONS\r\n";
    for (const auto* name : {L"content-security-policy", L"x-frame-options", L"x-content-type-options",
        L"strict-transport-security", L"referrer-policy", L"permissions-policy"}) {
        const auto found = values(headers, name);
        report << (found.empty() ? L"[NOT OBSERVED] " : L"[PRESENT] ") << name << L"\r\n";
        for (const auto& value : found) report << L"  " << value << L"\r\n";
        if (found.size() > 1) report << L"  [REVIEW] Multiple header instances; browser handling depends on the header.\r\n";
    }
    const auto content_type = lower(first(headers, L"x-content-type-options"));
    if (!content_type.empty() && content_type != L"nosniff") report << L"[REVIEW] X-Content-Type-Options value is not nosniff.\r\n";
    const auto frame = lower(first(headers, L"x-frame-options"));
    if (!frame.empty() && frame != L"deny" && frame != L"sameorigin")
        report << L"[REVIEW] X-Frame-Options value is not DENY or SAMEORIGIN.\r\n";
    const auto hsts = lower(first(headers, L"strict-transport-security"));
    if (!hsts.empty()) {
        if (!https) report << L"[REVIEW] HSTS on an HTTP response is not an HTTPS policy.\r\n";
        bool positive = false;
        std::wistringstream directives(hsts); std::wstring directive;
        while (std::getline(directives, directive, L';')) {
            const auto equal = directive.find(L'=');
            if (equal != std::wstring::npos && trim(directive.substr(0, equal)) == L"max-age") {
                auto age = trim(directive.substr(equal + 1));
                if (age.size() >= 2 && age.front() == L'"' && age.back() == L'"') age = age.substr(1, age.size() - 2);
                positive = !age.empty() && std::all_of(age.begin(), age.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; })
                    && age.find_first_not_of(L'0') != std::wstring::npos;
            }
        }
        if (!positive) report << L"[REVIEW] HSTS has no positive numeric max-age; policy may be disabled or invalid.\r\n";
    }
    report << L"\r\nPresence is not proof of an effective policy. CSP directives and application behaviour require manual review.\r\n"
        << L"Missing headers are observations, not confirmed vulnerabilities; relevance depends on the endpoint.\r\n\r\n";
    return report.str();
}
}

std::wstring inspect_url(std::wstring url, const std::atomic<bool>& cancel) {
    url = trim(url);
    if (url.empty()) throw std::runtime_error("Enter a URL.");
    if (url.find(L"://") == std::wstring::npos) url = L"https://" + url;
    const auto fragment = url.find(L'#');
    if (fragment != std::wstring::npos) url.erase(fragment);
    parse_url(url);
    Internet session(WinHttpOpen(L"WebSecurityInspector/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!WinHttpSetTimeouts(session.value, 3000, 5000, 5000, 5000)) network_error();
    std::wostringstream report;
    report << L"WEB SECURITY INSPECTOR\r\nRequested URL: " << url
        << L"\r\nMethod: GET (response body is not downloaded or executed)\r\n"
        << L"Anonymous request; automatic cookies and authentication disabled.\r\n\r\n";
    std::set<std::wstring> visited;
    for (int hop = 0; hop <= 5; ++hop) {
        if (cancel.load()) { report << L"Inspection cancelled.\r\n"; break; }
        if (!visited.insert(url).second) { report << L"[REVIEW] Redirect loop detected.\r\n"; break; }
        try {
            const Url parsed = parse_url(url);
            const auto response = request(parsed, session.value);
            report << L"HOP " << hop + 1 << L": " << url << L"\r\nHTTP status: " << response.status
                << L"\r\n" << response.certificate << cookie_report(response.headers, parsed.secure) << L"\r\n";
            const bool redirect = response.status == 301 || response.status == 302 || response.status == 303
                || response.status == 307 || response.status == 308;
            if (!redirect) {
                report << L"Final URL: " << url << L"\r\n\r\n" << header_report(response.headers, parsed.secure);
                if (!parsed.secure) report << L"[REVIEW] Final response is HTTP: traffic is not encrypted.\r\n";
                report << L"RAW RESPONSE HEADERS (cookie values omitted)\r\n";
                for (const auto& header : response.headers) {
                    if (header.first == L"set-cookie") report << L"set-cookie: [value omitted; attributes analysed above]\r\n";
                    else report << header.first << L": " << header.second << L"\r\n";
                }
                break;
            }
            const auto location = first(response.headers, L"location");
            if (location.empty()) { report << L"[REVIEW] Redirect without a Location header.\r\n"; break; }
            const auto destination = combine_url(url, location);
            const auto next = parse_url(destination);
            report << L"Redirect to: " << destination << L"\r\n\r\n";
            if (parsed.secure && !next.secure) { report << L"[REVIEW] HTTPS-to-HTTP downgrade; stopped before following it.\r\n"; break; }
            if (hop == 5) { report << L"Stopped after five redirects.\r\n"; break; }
            url = destination;
        } catch (const std::exception& error) {
            report << L"REQUEST FAILED: " << wide(error.what()) << L"\r\n"; break;
        }
    }
    report << L"\r\nScope: response metadata only. No JavaScript, browser cookie jar, crawling or exploitation.\r\n"
        << L"Certificate validation uses Windows defaults; this is not a complete TLS or vulnerability audit.\r\n";
    return report.str();
}
