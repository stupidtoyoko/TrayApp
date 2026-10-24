
#include <windows.h>
#include <winsvc.h>
#include <WtsApi32.h>
#include <UserEnv.h>
#include <rpc.h>
#include <rpcndr.h>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <vector>
#include <string>
#include <regex>
#include <algorithm>
#include <cstring>
#include <winhttp.h>

#include "TrayRpc_h.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Winhttp.lib")

// ============================================================
// MIDL memory allocation
// ============================================================

void* __RPC_USER MIDL_user_allocate(size_t size)
{
    return std::malloc(size);
}

void __RPC_USER MIDL_user_free(void* pointer)
{
    std::free(pointer);
}

// ============================================================
// Service configuration
// ============================================================

static const wchar_t* SERVICE_NAME = L"TrayService";
static const wchar_t* RPC_ENDPOINT = L"TrayServiceEndpoint";

static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS g_status{};

static HANDLE g_stopEvent = nullptr;
static HANDLE g_rpcReadyEvent = nullptr;

static CRITICAL_SECTION g_lock;
static bool g_lockInitialized = false;
static bool g_stopping = false;

static DWORD g_rpcStatus = RPC_S_OK;

struct ChildProcess
{
    DWORD sessionId;
    HANDLE process;
};

static std::vector<ChildProcess> g_children;
static std::vector<HANDLE> g_workerThreads;

// ============================================================
// Diagnostic log
// ============================================================

static void LogDiagnostic(const char* message, DWORD error)
{
    HANDLE file = CreateFileW(
        L"C:\\Windows\\Temp\\TrayService.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
        return;

    char buffer[512]{};

    int length = sprintf_s(
        buffer,
        sizeof(buffer),
        "TrayService: %s; error=%lu\r\n",
        message,
        error);

    if (length > 0)
    {
        DWORD written = 0;
        WriteFile(
            file,
            buffer,
            static_cast<DWORD>(length),
            &written,
            nullptr);
    }

    CloseHandle(file);
}

// ============================================================
// Find TrayApp.exe next to TrayService.exe
// ============================================================

static bool GetTrayAppPath(wchar_t* path, DWORD capacity)
{
    DWORD length = GetModuleFileNameW(
        nullptr, path, capacity);

    if (length == 0 || length >= capacity)
        return false;

    wchar_t* slash = wcsrchr(path, L'\\');

    if (!slash)
        return false;

    *(slash + 1) = L'\0';

    const wchar_t* appName = L"TrayApp.exe";
    size_t used = wcslen(path);

    if (used >= capacity ||
        wcslen(appName) + 1 > capacity - used)
        return false;

    return wcscat_s(path, capacity, appName) == 0;
}

// ============================================================
// Update service status
// ============================================================

static void SetServiceState(
    DWORD state,
    DWORD win32ExitCode = NO_ERROR)
{
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32ExitCode;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwCheckPoint = 0;

    g_status.dwWaitHint =
        (state == SERVICE_START_PENDING ||
            state == SERVICE_STOP_PENDING)
        ? 5000
        : 0;

    // Stop and Shutdown controls are intentionally not accepted.
    g_status.dwControlsAccepted =
        state == SERVICE_RUNNING
        ? SERVICE_ACCEPT_SESSIONCHANGE
        : 0;

    if (g_statusHandle)
        SetServiceStatus(g_statusHandle, &g_status);
}

// ============================================================
// Launch TrayApp.exe in a user session
// ============================================================

static bool LaunchTrayAppInSession(DWORD sessionId)
{
    if (!g_lockInitialized)
        return false;

    EnterCriticalSection(&g_lock);

    if (g_stopping)
    {
        LeaveCriticalSection(&g_lock);
        return false;
    }

    // Remove finished processes and avoid duplicate instances.
    for (auto it = g_children.begin(); it != g_children.end();)
    {
        DWORD result = WaitForSingleObject(it->process, 0);

        if (result == WAIT_OBJECT_0 || result == WAIT_FAILED)
        {
            CloseHandle(it->process);
            it = g_children.erase(it);
            continue;
        }

        if (it->sessionId == sessionId)
        {
            LeaveCriticalSection(&g_lock);
            return true;
        }

        ++it;
    }

    HANDLE userToken = nullptr;
    LPVOID environment = nullptr;

    PROCESS_INFORMATION processInfo{};
    STARTUPINFOW startupInfo{};

    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop =
        const_cast<LPWSTR>(L"winsta0\\default");
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    bool success = false;

    if (!WTSQueryUserToken(sessionId, &userToken))
    {
        LogDiagnostic(
            "WTSQueryUserToken failed", GetLastError());
    }
    else
    {
        if (!CreateEnvironmentBlock(
            &environment, userToken, FALSE))
        {
            LogDiagnostic(
                "CreateEnvironmentBlock failed", GetLastError());
        }
        else
        {
            wchar_t appPath[MAX_PATH]{};

            if (!GetTrayAppPath(appPath, ARRAYSIZE(appPath)))
            {
                LogDiagnostic(
                    "GetTrayAppPath failed",
                    ERROR_INSUFFICIENT_BUFFER);
            }
            else
            {
                // TrayApp recognizes this argument as a service launch.
                wchar_t commandLine[MAX_PATH + 32]{};

                int commandLength = swprintf_s(
                    commandLine,
                    ARRAYSIZE(commandLine),
                    L"\"%s\" --service-launch",
                    appPath);

                if (commandLength < 0)
                {
                    LogDiagnostic(
                        "Failed to build TrayApp command line",
                        ERROR_INSUFFICIENT_BUFFER);
                }
                else
                {
                    BOOL created = CreateProcessAsUserW(
                        userToken,
                        appPath,
                        commandLine,
                        nullptr,
                        nullptr,
                        FALSE,
                        CREATE_UNICODE_ENVIRONMENT,
                        environment,
                        nullptr,
                        &startupInfo,
                        &processInfo);

                    if (!created)
                    {
                        LogDiagnostic(
                            "CreateProcessAsUserW failed",
                            GetLastError());
                    }
                    else
                    {
                        try
                        {
                            g_children.push_back(
                                { sessionId, processInfo.hProcess });

                            success = true;
                            LogDiagnostic(
                                "TrayApp process created", sessionId);
                        }
                        catch (...)
                        {
                            TerminateProcess(processInfo.hProcess, 1);
                            WaitForSingleObject(
                                processInfo.hProcess, 5000);
                            CloseHandle(processInfo.hProcess);
                        }

                        CloseHandle(processInfo.hThread);
                    }
                }
            }

            DestroyEnvironmentBlock(environment);
        }

        CloseHandle(userToken);
    }

    LeaveCriticalSection(&g_lock);
    return success;
}

// ============================================================
// Launch in all existing active user sessions
// ============================================================

static void LaunchTrayAppForExistingSessions()
{
    LogDiagnostic(
        "LaunchTrayAppForExistingSessions entered", 0);

    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD sessionCount = 0;

    if (!WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &sessions,
        &sessionCount))
    {
        LogDiagnostic(
            "WTSEnumerateSessionsW failed", GetLastError());
        return;
    }

    LogDiagnostic(
        "WTSEnumerateSessionsW succeeded", sessionCount);

    for (DWORD i = 0; i < sessionCount; ++i)
    {
        DWORD sessionId = sessions[i].SessionId;

        if (sessionId == 0 || sessions[i].State != WTSActive)
            continue;

        bool launched = LaunchTrayAppInSession(sessionId);

        LogDiagnostic(
            launched
            ? "LaunchTrayAppInSession succeeded"
            : "LaunchTrayAppInSession failed",
            sessionId);
    }

    WTSFreeMemory(sessions);
}

// ============================================================
// Worker thread for a newly logged-on user
// ============================================================

static DWORD WINAPI LaunchSessionThread(LPVOID parameter)
{
    DWORD sessionId = *static_cast<DWORD*>(parameter);
    HeapFree(GetProcessHeap(), 0, parameter);

    LaunchTrayAppInSession(sessionId);
    return 0;
}

// ============================================================
// Authentication and licensing state (memory only)
// ============================================================

static SRWLOCK g_authLock = SRWLOCK_INIT;
static std::wstring g_accessToken;
static std::wstring g_refreshToken;
static std::wstring g_username;
static std::wstring g_licenseTicket; // never sent to the GUI client
static std::wstring g_licenseExpiry;
static ULONGLONG g_accessRefreshAt = 0;
static ULONGLONG g_licenseRefreshAt = 0;
static HANDLE g_backgroundStopEvent = nullptr;
static HANDLE g_backgroundThread = nullptr;

struct ApiConfig
{
    std::wstring baseUrl;
    std::wstring loginPath = L"/api/auth/login";
    std::wstring refreshPath = L"/api/auth/refresh";
    std::wstring licensePath = L"/api/license/status";
    std::wstring activatePath = L"/api/license/activate";
    std::wstring loginMethod = L"POST";
    std::wstring refreshMethod = L"POST";
    std::wstring licenseMethod = L"POST";
    std::wstring activateMethod = L"POST";
    bool allowLoopbackHttp = false;
};

static std::wstring ServiceDirectory()
{
    wchar_t path[MAX_PATH]{};
    DWORD n = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    if (!n || n >= ARRAYSIZE(path)) return L".";
    wchar_t* slash = wcsrchr(path, L'\\');
    if (slash) *slash = L'\0';
    return path;
}

static ApiConfig LoadApiConfig()
{
    ApiConfig c;
    std::wstring file = ServiceDirectory() + L"\\TrayService.ini";
    wchar_t value[2048]{};
    GetPrivateProfileStringW(L"server", L"base_url", L"", value, ARRAYSIZE(value), file.c_str()); c.baseUrl = value;
    GetPrivateProfileStringW(L"endpoints", L"login", c.loginPath.c_str(), value, ARRAYSIZE(value), file.c_str()); c.loginPath = value;
    GetPrivateProfileStringW(L"endpoints", L"refresh", c.refreshPath.c_str(), value, ARRAYSIZE(value), file.c_str()); c.refreshPath = value;
    GetPrivateProfileStringW(L"endpoints", L"license_status", c.licensePath.c_str(), value, ARRAYSIZE(value), file.c_str()); c.licensePath = value;
    GetPrivateProfileStringW(L"endpoints", L"activate", c.activatePath.c_str(), value, ARRAYSIZE(value), file.c_str()); c.activatePath = value;
    GetPrivateProfileStringW(L"methods", L"login", c.loginMethod.c_str(), value, ARRAYSIZE(value), file.c_str()); c.loginMethod = value;
    GetPrivateProfileStringW(L"methods", L"refresh", c.refreshMethod.c_str(), value, ARRAYSIZE(value), file.c_str()); c.refreshMethod = value;
    GetPrivateProfileStringW(L"methods", L"license_status", c.licenseMethod.c_str(), value, ARRAYSIZE(value), file.c_str()); c.licenseMethod = value;
    GetPrivateProfileStringW(L"methods", L"activate", c.activateMethod.c_str(), value, ARRAYSIZE(value), file.c_str()); c.activateMethod = value;
    c.allowLoopbackHttp = GetPrivateProfileIntW(L"server", L"allow_insecure_loopback_http", 0, file.c_str()) == 1;
    return c;
}

static std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), n, nullptr, nullptr);
    out.resize(static_cast<size_t>(n - 1));
    return out;
}

static std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (n <= 1) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, out.data(), n);
    out.resize(static_cast<size_t>(n - 1));
    return out;
}

static std::string JsonEscape(const std::wstring& input)
{
    std::string src = WideToUtf8(input), out;
    for (unsigned char c : src)
    {
        switch (c)
        {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: if (c < 0x20) { char b[7]; sprintf_s(b, "\\u%04x", c); out += b; } else out += static_cast<char>(c);
        }
    }
    return out;
}

static std::string JsonString(const std::string& json, const char* key)
{
    try
    {
        std::regex re(std::string("\\\"") + key + "\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"");
        std::smatch m;
        if (!std::regex_search(json, m, re)) return {};
        std::string v = m[1].str(), out;
        for (size_t i = 0; i < v.size(); ++i)
        {
            if (v[i] == '\\' && i + 1 < v.size())
            {
                char n = v[++i];
                if (n == 'n') out += '\n'; else if (n == 'r') out += '\r'; else if (n == 't') out += '\t'; else out += n;
            }
            else out += v[i];
        }
        return out;
    }
    catch (...) { return {}; }
}

static long long JsonInteger(const std::string& json, const char* key, long long fallback)
{
    try
    {
        std::regex re(std::string("\\\"") + key + "\\\"\\s*:\\s*(-?[0-9]+)");
        std::smatch m;
        if (std::regex_search(json, m, re)) return std::stoll(m[1].str());
    }
    catch (...) {}
    return fallback;
}

static bool JsonBoolean(const std::string& json, const char* key, bool fallback = false)
{
    try
    {
        std::regex re(std::string("\\\"") + key + "\\\"\\s*:\\s*(true|false|1|0)", std::regex_constants::icase);
        std::smatch m;
        if (std::regex_search(json, m, re)) return _stricmp(m[1].str().c_str(), "true") == 0 || m[1].str() == "1";
    }
    catch (...) {}
    return fallback;
}

static bool IsAllowedBaseUrl(const ApiConfig& cfg)
{
    if (cfg.baseUrl.rfind(L"https://", 0) == 0) return true;
    // Explicit development-only exception: plain HTTP is allowed only to loopback.
    if (!cfg.allowLoopbackHttp || cfg.baseUrl.rfind(L"http://127.0.0.1:", 0) != 0) return false;
    return true;
}

static bool HttpRequestJson(const std::wstring& method, const std::wstring& endpoint, const std::string& body,
    const std::wstring& bearer, std::string& response, DWORD& httpStatus)
{
    ApiConfig cfg = LoadApiConfig();
    if (!IsAllowedBaseUrl(cfg)) return false; // HTTPS, or explicitly enabled 127.0.0.1 test mode only
    std::wstring full = cfg.baseUrl;
    while (!full.empty() && full.back() == L'/') full.pop_back();
    full += endpoint.empty() || endpoint.front() != L'/' ? L"/" + endpoint : endpoint;

    URL_COMPONENTSW parts{}; parts.dwStructSize = sizeof(parts);
    wchar_t host[512]{}; wchar_t path[2048]{}; wchar_t extra[1024]{};
    parts.lpszHostName = host; parts.dwHostNameLength = ARRAYSIZE(host);
    parts.lpszUrlPath = path; parts.dwUrlPathLength = ARRAYSIZE(path);
    parts.lpszExtraInfo = extra; parts.dwExtraInfoLength = ARRAYSIZE(extra);
    if (!WinHttpCrackUrl(full.c_str(), 0, 0, &parts)) return false;
    bool secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
    if (!secure && !(cfg.allowLoopbackHttp && parts.nScheme == INTERNET_SCHEME_HTTP && wcscmp(host, L"127.0.0.1") == 0)) return false;

    HINTERNET session = WinHttpOpen(L"TrayService/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;
    WinHttpSetTimeouts(session, 5000, 5000, 10000, 10000);
    HINTERNET connection = WinHttpConnect(session, host, parts.nPort, 0);
    if (!connection) { WinHttpCloseHandle(session); return false; }
    std::wstring resource(path, parts.dwUrlPathLength);
    if (parts.dwExtraInfoLength) resource.append(extra, parts.dwExtraInfoLength);
    HINTERNET request = WinHttpOpenRequest(connection, method.c_str(), resource.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
    if (!request) { WinHttpCloseHandle(connection); WinHttpCloseHandle(session); return false; }
    std::wstring headers = L"Content-Type: application/json; charset=utf-8\r\nAccept: application/json\r\n";
    if (!bearer.empty()) headers += L"Authorization: Bearer " + bearer + L"\r\n";
    BOOL sent = WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(headers.size()),
        (body.empty() || method == L"GET" || method == L"HEAD") ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        (body.empty() || method == L"GET" || method == L"HEAD") ? 0 : static_cast<DWORD>(body.size()),
        (body.empty() || method == L"GET" || method == L"HEAD") ? 0 : static_cast<DWORD>(body.size()), 0);
    BOOL received = sent && WinHttpReceiveResponse(request, nullptr);
    DWORD statusSize = sizeof(httpStatus);
    if (received) WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &httpStatus, &statusSize, WINHTTP_NO_HEADER_INDEX);
    if (received)
    {
        DWORD available = 0;
        do
        {
            available = 0;
            if (!WinHttpQueryDataAvailable(request, &available) || !available) break;
            std::string chunk(available, '\0'); DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read)) break;
            chunk.resize(read); response += chunk;
        } while (available > 0 && response.size() < 1024 * 1024);
    }
    WinHttpCloseHandle(request); WinHttpCloseHandle(connection); WinHttpCloseHandle(session);
    return received != FALSE;
}

static void ClearAuthAndLicense()
{
    AcquireSRWLockExclusive(&g_authLock);
    g_accessToken.clear(); g_refreshToken.clear(); g_username.clear();
    g_licenseTicket.clear(); g_licenseExpiry.clear();
    g_accessRefreshAt = 0; g_licenseRefreshAt = 0;
    ReleaseSRWLockExclusive(&g_authLock);
}

static bool RefreshTokens()
{
    std::wstring refresh;
    AcquireSRWLockShared(&g_authLock); refresh = g_refreshToken; ReleaseSRWLockShared(&g_authLock);
    if (refresh.empty()) return false;
    ApiConfig cfg = LoadApiConfig(); std::string response; DWORD status = 0;
    std::string body = "{\"refresh_token\":\"" + JsonEscape(refresh) + "\"}";
    if (!HttpRequestJson(cfg.refreshMethod, cfg.refreshPath, body, L"", response, status) || status < 200 || status >= 300) return false;
    std::wstring access = Utf8ToWide(JsonString(response, "access_token"));
    std::wstring newRefresh = Utf8ToWide(JsonString(response, "refresh_token"));
    long long expires = JsonInteger(response, "expires_in", 900);
    if (access.empty()) return false;
    AcquireSRWLockExclusive(&g_authLock);
    g_accessToken = access; if (!newRefresh.empty()) g_refreshToken = newRefresh;
    g_accessRefreshAt = GetTickCount64() + static_cast<ULONGLONG>((std::max)(30LL, expires - 60) * 1000);
    ReleaseSRWLockExclusive(&g_authLock);
    return true;
}

static bool FetchLicenseStatus(std::wstring& error)
{
    std::wstring access; AcquireSRWLockShared(&g_authLock); access = g_accessToken; ReleaseSRWLockShared(&g_authLock);
    if (access.empty()) { error = L"Сначала войдите в учётную запись."; return false; }
    ApiConfig cfg = LoadApiConfig(); std::string response; DWORD status = 0;
    if (!HttpRequestJson(cfg.licenseMethod, cfg.licensePath, "{}", access, response, status)) { error = L"Не удалось подключиться к HTTPS-серверу. Проверьте TrayService.ini."; return false; }
    if (status < 200 || status >= 300) { error = L"Сервер отклонил запрос статуса лицензии (HTTP " + std::to_wstring(status) + L")."; return false; }
    std::string ticket = JsonString(response, "ticket");
    if (ticket.empty()) ticket = JsonString(response, "license_ticket");
    std::string expiry = JsonString(response, "expires_at");
    if (expiry.empty()) expiry = JsonString(response, "license_expires_at");
    long long ttl = JsonInteger(response, "ticket_ttl_seconds", 300);
    bool hasLicense = JsonBoolean(response, "has_license", false) || JsonInteger(response, "has_license", 0) == 1 || !ticket.empty();
    AcquireSRWLockExclusive(&g_authLock);
    if (hasLicense) { g_licenseTicket = Utf8ToWide(ticket.empty() ? response : ticket); g_licenseExpiry = Utf8ToWide(expiry); g_licenseRefreshAt = GetTickCount64() + static_cast<ULONGLONG>((std::max)(30LL, ttl / 2) * 1000); }
    else { g_licenseTicket.clear(); g_licenseExpiry.clear(); g_licenseRefreshAt = 0; }
    ReleaseSRWLockExclusive(&g_authLock);
    return hasLicense;
}

static DWORD WINAPI BackgroundRefreshThread(LPVOID)
{
    while (g_backgroundStopEvent && WaitForSingleObject(g_backgroundStopEvent, 5000) == WAIT_TIMEOUT)
    {
        ULONGLONG now = GetTickCount64(); bool auth = false, refreshToken = false, refreshLicense = false;
        AcquireSRWLockShared(&g_authLock);
        auth = !g_accessToken.empty();
        refreshToken = auth && g_accessRefreshAt && now >= g_accessRefreshAt;
        refreshLicense = auth && !g_licenseTicket.empty() && g_licenseRefreshAt && now >= g_licenseRefreshAt;
        ReleaseSRWLockShared(&g_authLock);
        if (refreshToken && !RefreshTokens()) { LogDiagnostic("JWT refresh failed; clearing in-memory session", 0); ClearAuthAndLicense(); continue; }
        if (refreshLicense) { std::wstring ignored; FetchLicenseStatus(ignored); }
    }
    return 0;
}

static wchar_t* RpcCopyString(const std::wstring& value)
{
    size_t bytes = (value.size() + 1) * sizeof(wchar_t);
    wchar_t* result = static_cast<wchar_t*>(MIDL_user_allocate(bytes));
    if (result) memcpy(result, value.c_str(), bytes);
    return result;
}

// ============================================================
// RPC method: request service shutdown
// ============================================================

error_status_t RequestServiceStop(handle_t IDL_handle)
{
    (void)IDL_handle;

    if (!g_stopEvent)
        return ERROR_SERVICE_NOT_ACTIVE;

    if (!SetEvent(g_stopEvent))
        return GetLastError();

    return NO_ERROR;
}

error_status_t GetAuthState(handle_t, long* authenticated, wchar_t** username)
{
    if (!authenticated || !username) return ERROR_INVALID_PARAMETER;
    AcquireSRWLockShared(&g_authLock);
    *authenticated = g_accessToken.empty() ? 0 : 1;
    *username = RpcCopyString(g_username);
    ReleaseSRWLockShared(&g_authLock);
    return *username ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
}

error_status_t Login(handle_t, wchar_t* username, wchar_t* password, long* success,
    wchar_t** message, wchar_t** authenticatedUsername)
{
    if (!username || !password || !success || !message || !authenticatedUsername) return ERROR_INVALID_PARAMETER;
    *success = 0; *message = nullptr; *authenticatedUsername = nullptr;
    ApiConfig cfg = LoadApiConfig();
    if (!IsAllowedBaseUrl(cfg))
    {
        *message = RpcCopyString(L"Не настроен сервер. Для production используйте HTTPS; HTTP разрешён только для 127.0.0.1 в тестовом режиме.");
        *authenticatedUsername = RpcCopyString(L""); return *message && *authenticatedUsername ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
    }
    std::string body = "{\"username\":\"" + JsonEscape(username) + "\",\"password\":\"" + JsonEscape(password) + "\"}";
    std::string response; DWORD status = 0;
    if (!HttpRequestJson(cfg.loginMethod, cfg.loginPath, body, L"", response, status) || status < 200 || status >= 300)
    {
        std::wstring msg = L"Не удалось выполнить вход. Проверьте данные и доступность сервера";
        if (status) msg += L" (HTTP " + std::to_wstring(status) + L")";
        *message = RpcCopyString(msg); *authenticatedUsername = RpcCopyString(L"");
        return *message && *authenticatedUsername ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
    }
    std::wstring access = Utf8ToWide(JsonString(response, "access_token"));
    std::wstring refresh = Utf8ToWide(JsonString(response, "refresh_token"));
    std::wstring actualUser = Utf8ToWide(JsonString(response, "username"));
    if (actualUser.empty()) actualUser = username;
    if (access.empty() || refresh.empty())
    {
        *message = RpcCopyString(L"Ответ сервера не содержит access_token и refresh_token. Проверьте контракт API.");
        *authenticatedUsername = RpcCopyString(L""); return *message && *authenticatedUsername ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
    }
    long long expires = JsonInteger(response, "expires_in", 900);
    AcquireSRWLockExclusive(&g_authLock);
    g_accessToken = access; g_refreshToken = refresh; g_username = actualUser;
    g_licenseTicket.clear(); g_licenseExpiry.clear(); g_licenseRefreshAt = 0;
    g_accessRefreshAt = GetTickCount64() + static_cast<ULONGLONG>((std::max)(30LL, expires - 60) * 1000);
    ReleaseSRWLockExclusive(&g_authLock);
    *success = 1; *message = RpcCopyString(L"Вход выполнен."); *authenticatedUsername = RpcCopyString(actualUser);
    return *message && *authenticatedUsername ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
}

error_status_t Logout(handle_t)
{
    ClearAuthAndLicense();
    return NO_ERROR;
}

error_status_t GetLicenseState(handle_t, long* hasLicense, wchar_t** expiryDate, wchar_t** message)
{
    if (!hasLicense || !expiryDate || !message) return ERROR_INVALID_PARAMETER;
    *hasLicense = 0; *expiryDate = nullptr; *message = nullptr;
    std::wstring access; bool cached = false;
    AcquireSRWLockShared(&g_authLock);
    access = g_accessToken; cached = !g_licenseTicket.empty() && (!g_licenseRefreshAt || GetTickCount64() < g_licenseRefreshAt);
    *expiryDate = RpcCopyString(g_licenseExpiry);
    ReleaseSRWLockShared(&g_authLock);
    if (!*expiryDate) return ERROR_NOT_ENOUGH_MEMORY;
    if (access.empty()) { *message = RpcCopyString(L"Не выполнен вход."); return *message ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY; }
    std::wstring err;
    if (cached) *hasLicense = 1;
    else if (FetchLicenseStatus(err)) *hasLicense = 1;
    else err = err.empty() ? L"Лицензия отсутствует или не активирована." : err;
    AcquireSRWLockShared(&g_authLock);
    std::wstring expiry = g_licenseExpiry;
    ReleaseSRWLockShared(&g_authLock);
    MIDL_user_free(*expiryDate); *expiryDate = RpcCopyString(expiry);
    *message = RpcCopyString(*hasLicense ? L"Лицензия активна." : err);
    return *expiryDate && *message ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
}

error_status_t ActivateProduct(handle_t, wchar_t* activationCode, long* success,
    wchar_t** expiryDate, wchar_t** message)
{
    if (!activationCode || !success || !expiryDate || !message) return ERROR_INVALID_PARAMETER;
    *success = 0; *expiryDate = nullptr; *message = nullptr;
    std::wstring access; AcquireSRWLockShared(&g_authLock); access = g_accessToken; ReleaseSRWLockShared(&g_authLock);
    if (access.empty()) { *expiryDate = RpcCopyString(L""); *message = RpcCopyString(L"Сначала войдите в учётную запись."); return *expiryDate && *message ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY; }
    ApiConfig cfg = LoadApiConfig();
    std::string body = "{\"activation_code\":\"" + JsonEscape(activationCode) + "\"}";
    std::string response; DWORD status = 0;
    if (!HttpRequestJson(cfg.activateMethod, cfg.activatePath, body, access, response, status) || status < 200 || status >= 300)
    {
        *expiryDate = RpcCopyString(L""); std::wstring msg = L"Активация не выполнена";
        if (status) msg += L" (HTTP " + std::to_wstring(status) + L")";
        *message = RpcCopyString(msg); return *expiryDate && *message ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
    }
    std::string ticket = JsonString(response, "ticket");
    if (ticket.empty()) ticket = JsonString(response, "license_ticket");
    std::string expiry = JsonString(response, "expires_at");
    if (expiry.empty()) expiry = JsonString(response, "license_expires_at");
    if (ticket.empty())
    {
        std::wstring ignored;
        if (!FetchLicenseStatus(ignored))
        {
            *expiryDate = RpcCopyString(L""); *message = RpcCopyString(ignored.empty() ? L"Активация прошла, но сервер не подтвердил активную лицензию." : ignored);
            return *expiryDate && *message ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
        }
        AcquireSRWLockShared(&g_authLock); expiry = WideToUtf8(g_licenseExpiry); ReleaseSRWLockShared(&g_authLock);
    }
    else
    {
        long long ttl = JsonInteger(response, "ticket_ttl_seconds", 300);
        AcquireSRWLockExclusive(&g_authLock);
        g_licenseTicket = Utf8ToWide(ticket); g_licenseExpiry = Utf8ToWide(expiry);
        g_licenseRefreshAt = GetTickCount64() + static_cast<ULONGLONG>((std::max)(30LL, ttl / 2) * 1000);
        ReleaseSRWLockExclusive(&g_authLock);
    }
    *success = 1; *expiryDate = RpcCopyString(Utf8ToWide(expiry)); *message = RpcCopyString(L"Продукт активирован.");
    return *expiryDate && *message ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
}

// ============================================================
// RPC server thread
// ============================================================

static DWORD WINAPI RpcServerThread(LPVOID)
{
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(
            const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(
            const_cast<wchar_t*>(RPC_ENDPOINT)),
        nullptr);

    if (status == RPC_S_OK)
    {
        status = RpcServerRegisterIf2(
            TrayRpc_v1_0_s_ifspec,
            nullptr,
            nullptr,
            0,
            RPC_C_LISTEN_MAX_CALLS_DEFAULT,
            0,
            nullptr);
    }

    g_rpcStatus = status;

    if (g_rpcReadyEvent)
        SetEvent(g_rpcReadyEvent);

    if (status != RPC_S_OK)
        return status;

    status = RpcServerListen(
        1,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        FALSE);

    RpcServerUnregisterIf(
        TrayRpc_v1_0_s_ifspec,
        nullptr,
        TRUE);

    return status;
}

// ============================================================
// Service control handler and session notifications
// ============================================================

static DWORD WINAPI ServiceControlHandler(
    DWORD control,
    DWORD eventType,
    LPVOID eventData,
    LPVOID)
{
    if (control != SERVICE_CONTROL_SESSIONCHANGE)
        return ERROR_CALL_NOT_IMPLEMENTED;

    if (eventType != WTS_SESSION_LOGON || eventData == nullptr)
        return NO_ERROR;

    auto* notification =
        static_cast<WTSSESSION_NOTIFICATION*>(eventData);

    DWORD* sessionId = static_cast<DWORD*>(
        HeapAlloc(GetProcessHeap(), 0, sizeof(DWORD)));

    if (!sessionId)
        return ERROR_NOT_ENOUGH_MEMORY;

    *sessionId = notification->dwSessionId;

    EnterCriticalSection(&g_lock);

    if (g_stopping)
    {
        LeaveCriticalSection(&g_lock);
        HeapFree(GetProcessHeap(), 0, sessionId);
        return NO_ERROR;
    }

    HANDLE thread = CreateThread(
        nullptr,
        0,
        LaunchSessionThread,
        sessionId,
        0,
        nullptr);

    if (!thread)
    {
        DWORD error = GetLastError();
        LeaveCriticalSection(&g_lock);
        HeapFree(GetProcessHeap(), 0, sessionId);
        return error;
    }

    try
    {
        g_workerThreads.push_back(thread);
    }
    catch (...)
    {
        LeaveCriticalSection(&g_lock);
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    LeaveCriticalSection(&g_lock);
    return NO_ERROR;
}

// ============================================================
// Stop all GUI processes launched by this service
// ============================================================

static void StopChildProcesses()
{
    EnterCriticalSection(&g_lock);

    for (const auto& child : g_children)
    {
        DWORD result = WaitForSingleObject(child.process, 0);

        if (result == WAIT_TIMEOUT)
        {
            if (!TerminateProcess(child.process, 0))
            {
                LogDiagnostic(
                    "TerminateProcess failed", GetLastError());
            }
        }

        WaitForSingleObject(child.process, 5000);
        CloseHandle(child.process);
    }

    g_children.clear();
    LeaveCriticalSection(&g_lock);
}

// ============================================================
// Main service function
// ============================================================

static void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_statusHandle = RegisterServiceCtrlHandlerExW(
        SERVICE_NAME,
        ServiceControlHandler,
        nullptr);

    if (!g_statusHandle)
        return;

    SetServiceState(SERVICE_START_PENDING);

    InitializeCriticalSection(&g_lock);
    g_lockInitialized = true;
    g_stopping = false;

    g_children.clear();
    g_workerThreads.clear();

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_rpcReadyEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    if (!g_stopEvent || !g_rpcReadyEvent)
    {
        DWORD error = GetLastError();

        if (g_stopEvent)
            CloseHandle(g_stopEvent);
        if (g_rpcReadyEvent)
            CloseHandle(g_rpcReadyEvent);

        g_stopEvent = nullptr;
        g_rpcReadyEvent = nullptr;

        DeleteCriticalSection(&g_lock);
        g_lockInitialized = false;

        SetServiceState(SERVICE_STOPPED, error);
        return;
    }

    HANDLE rpcThread = CreateThread(
        nullptr, 0, RpcServerThread, nullptr, 0, nullptr);

    if (!rpcThread)
    {
        DWORD error = GetLastError();

        CloseHandle(g_rpcReadyEvent);
        CloseHandle(g_stopEvent);

        g_rpcReadyEvent = nullptr;
        g_stopEvent = nullptr;

        DeleteCriticalSection(&g_lock);
        g_lockInitialized = false;

        SetServiceState(SERVICE_STOPPED, error);
        return;
    }

    WaitForSingleObject(g_rpcReadyEvent, INFINITE);

    if (g_rpcStatus != RPC_S_OK)
    {
        WaitForSingleObject(rpcThread, INFINITE);
        CloseHandle(rpcThread);
        CloseHandle(g_rpcReadyEvent);
        CloseHandle(g_stopEvent);

        g_rpcReadyEvent = nullptr;
        g_stopEvent = nullptr;

        DeleteCriticalSection(&g_lock);
        g_lockInitialized = false;

        SetServiceState(SERVICE_STOPPED, g_rpcStatus);
        return;
    }

    g_backgroundStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_backgroundStopEvent)
    {
        DWORD error = GetLastError();
        RpcMgmtStopServerListening(nullptr); WaitForSingleObject(rpcThread, INFINITE); CloseHandle(rpcThread);
        CloseHandle(g_rpcReadyEvent); CloseHandle(g_stopEvent);
        g_rpcReadyEvent = nullptr; g_stopEvent = nullptr;
        DeleteCriticalSection(&g_lock); g_lockInitialized = false;
        SetServiceState(SERVICE_STOPPED, error); return;
    }
    g_backgroundThread = CreateThread(nullptr, 0, BackgroundRefreshThread, nullptr, 0, nullptr);
    if (!g_backgroundThread)
    {
        DWORD error = GetLastError(); CloseHandle(g_backgroundStopEvent); g_backgroundStopEvent = nullptr;
        RpcMgmtStopServerListening(nullptr); WaitForSingleObject(rpcThread, INFINITE); CloseHandle(rpcThread);
        CloseHandle(g_rpcReadyEvent); CloseHandle(g_stopEvent); g_rpcReadyEvent = nullptr; g_stopEvent = nullptr;
        DeleteCriticalSection(&g_lock); g_lockInitialized = false; SetServiceState(SERVICE_STOPPED, error); return;
    }

    SetServiceState(SERVICE_RUNNING);

    LaunchTrayAppForExistingSessions();

    HANDLE waitHandles[] = { g_stopEvent, rpcThread };

    WaitForMultipleObjects(
        2, waitHandles, FALSE, INFINITE);

    SetServiceState(SERVICE_STOP_PENDING);

    if (g_backgroundStopEvent) SetEvent(g_backgroundStopEvent);
    if (g_backgroundThread) { WaitForSingleObject(g_backgroundThread, INFINITE); CloseHandle(g_backgroundThread); g_backgroundThread = nullptr; }
    if (g_backgroundStopEvent) { CloseHandle(g_backgroundStopEvent); g_backgroundStopEvent = nullptr; }
    ClearAuthAndLicense();

    EnterCriticalSection(&g_lock);
    g_stopping = true;
    LeaveCriticalSection(&g_lock);

    RpcMgmtStopServerListening(nullptr);

    WaitForSingleObject(rpcThread, INFINITE);
    CloseHandle(rpcThread);

    EnterCriticalSection(&g_lock);
    std::vector<HANDLE> workers;
    workers.swap(g_workerThreads);
    LeaveCriticalSection(&g_lock);

    for (HANDLE worker : workers)
    {
        WaitForSingleObject(worker, INFINITE);
        CloseHandle(worker);
    }

    StopChildProcesses();

    CloseHandle(g_rpcReadyEvent);
    CloseHandle(g_stopEvent);

    g_rpcReadyEvent = nullptr;
    g_stopEvent = nullptr;

    DeleteCriticalSection(&g_lock);
    g_lockInitialized = false;

    SetServiceState(SERVICE_STOPPED);
}

// ============================================================
// Windows service entry point
// ============================================================

int WINAPI wWinMain(
    HINSTANCE,
    HINSTANCE,
    PWSTR,
    int)
{
    SERVICE_TABLE_ENTRYW serviceTable[] =
    {
        {
            const_cast<LPWSTR>(L"TrayService"),
            ServiceMain
        },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable))
        return static_cast<int>(GetLastError());

    return 0;
}
