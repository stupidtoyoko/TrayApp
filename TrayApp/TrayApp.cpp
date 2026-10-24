
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <rpc.h>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <string>

#include "..\\SharedRpc\\TrayRpc_h.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Advapi32.lib")

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
// Diagnostic log: %TEMP%\TrayApp.log
// ============================================================

static void LogAppDiagnostic(const char* message, DWORD error)
{
    wchar_t path[MAX_PATH]{};

    DWORD length = GetTempPathW(ARRAYSIZE(path), path);

    if (length == 0 || length >= ARRAYSIZE(path))
        return;

    if (wcscat_s(path, ARRAYSIZE(path), L"TrayApp.log") != 0)
        return;

    HANDLE file = CreateFileW(
        path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
        return;

    char buffer[512]{};

    int count = sprintf_s(
        buffer,
        sizeof(buffer),
        "TrayApp: %s; error=%lu\r\n",
        message,
        error);

    if (count > 0)
    {
        DWORD written = 0;

        WriteFile(
            file,
            buffer,
            static_cast<DWORD>(count),
            &written,
            nullptr);
    }

    CloseHandle(file);
}

// ============================================================
// Request service shutdown over local RPC
// ============================================================

static bool RequestTrayServiceStop()
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;

    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(
            const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(
            const_cast<wchar_t*>(L"TrayServiceEndpoint")),
        nullptr,
        &stringBinding);

    if (status != RPC_S_OK)
    {
        LogAppDiagnostic(
            "RpcStringBindingComposeW failed", status);
        return false;
    }

    status = RpcBindingFromStringBindingW(
        stringBinding, &binding);

    RpcStringFreeW(&stringBinding);

    if (status != RPC_S_OK)
    {
        LogAppDiagnostic(
            "RpcBindingFromStringBindingW failed", status);
        return false;
    }

    error_status_t result = RPC_S_OK;

    RpcTryExcept
    {
        result = RequestServiceStop(binding);
    }
        RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        result = RpcExceptionCode();
    }
    RpcEndExcept

        RpcBindingFree(&binding);

    if (result != RPC_S_OK)
    {
        LogAppDiagnostic("RequestServiceStop failed", result);
        return false;
    }

    LogAppDiagnostic("Service stop request sent", 0);
    return true;
}

// ============================================================
// Start service if needed and wait for RUNNING
// ============================================================

static bool EnsureTrayServiceRunning()
{
    SC_HANDLE scm = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT);

    if (!scm)
    {
        LogAppDiagnostic("OpenSCManagerW failed", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        scm,
        L"TrayService",
        SERVICE_QUERY_STATUS | SERVICE_START);

    if (!service)
    {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);
        LogAppDiagnostic("OpenServiceW failed", error);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    bool success = false;

    if (!QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytesNeeded))
    {
        LogAppDiagnostic(
            "QueryServiceStatusEx failed", GetLastError());
    }
    else
    {
        if (status.dwCurrentState == SERVICE_STOPPED)
        {
            if (!StartServiceW(service, 0, nullptr))
            {
                DWORD error = GetLastError();

                if (error != ERROR_SERVICE_ALREADY_RUNNING)
                {
                    LogAppDiagnostic(
                        "StartServiceW failed", error);
                }
            }
        }

        for (int i = 0; i < 300; ++i)
        {
            if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status),
                sizeof(status),
                &bytesNeeded))
            {
                LogAppDiagnostic(
                    "QueryServiceStatusEx failed", GetLastError());
                break;
            }

            if (status.dwCurrentState == SERVICE_RUNNING)
            {
                success = true;
                break;
            }

            if (status.dwCurrentState == SERVICE_STOPPED)
            {
                LogAppDiagnostic(
                    "Service stopped during startup",
                    status.dwWin32ExitCode);
                break;
            }

            Sleep(100);
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    LogAppDiagnostic(
        success ? "Service is running" : "Service startup failed",
        success ? 0 : status.dwCurrentState);

    return success;
}

// ============================================================
// Verify that the parent process is TrayService
// ============================================================

static bool IsLaunchedByTrayService()
{
    DWORD parentPid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        LogAppDiagnostic(
            "CreateToolhelp32Snapshot failed", GetLastError());
        return false;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (entry.th32ProcessID == GetCurrentProcessId())
            {
                parentPid = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    else
    {
        LogAppDiagnostic(
            "Process32FirstW failed", GetLastError());
    }

    CloseHandle(snapshot);

    if (parentPid == 0)
    {
        LogAppDiagnostic("Parent process not found", 0);
        return false;
    }

    SC_HANDLE scm = OpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_CONNECT);

    if (!scm)
    {
        LogAppDiagnostic("OpenSCManagerW failed", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        scm, L"TrayService", SERVICE_QUERY_STATUS);

    if (!service)
    {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);

        LogAppDiagnostic(
            "OpenServiceW for parent verification failed", error);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;

    bool queried = QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytesNeeded) != FALSE;

    DWORD queryError = queried ? ERROR_SUCCESS : GetLastError();

    bool valid = queried &&
        status.dwCurrentState == SERVICE_RUNNING &&
        status.dwProcessId == parentPid;

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (!queried)
    {
        LogAppDiagnostic(
            "Parent verification query failed", queryError);
    }
    else
    {
        LogAppDiagnostic(
            valid
            ? "Parent process verified"
            : "Invalid parent process",
            parentPid);
    }

    return valid;
}

// ============================================================
// RPC client helpers for authentication and licensing
// ============================================================

static RPC_BINDING_HANDLE OpenServiceRpc()
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")), nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"TrayServiceEndpoint")), nullptr, &stringBinding);
    if (status != RPC_S_OK) return nullptr;
    status = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);
    return status == RPC_S_OK ? binding : nullptr;
}

static void FreeRpcString(wchar_t* value)
{
    if (value) MIDL_user_free(value);
}

// Keep Windows SEH (RpcTryExcept) in functions that contain only POD values.
// MSVC error C2712 occurs when RpcTryExcept is mixed with std::wstring/string
// objects whose destructors must run during C++ stack unwinding.
static error_status_t SafeGetAuthState(handle_t binding, long* authenticated, wchar_t** username)
{
    error_status_t result = RPC_S_OK;
    RpcTryExcept
    {
        result = GetAuthState(binding, authenticated, username);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        result = RpcExceptionCode();
    }
    RpcEndExcept
    return result;
}

static error_status_t SafeLogin(handle_t binding, wchar_t* username, wchar_t* password,
    long* success, wchar_t** message, wchar_t** authenticatedUsername)
{
    error_status_t result = RPC_S_OK;
    RpcTryExcept
    {
        result = Login(binding, username, password, success, message, authenticatedUsername);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        result = RpcExceptionCode();
    }
    RpcEndExcept
    return result;
}

static error_status_t SafeLogout(handle_t binding)
{
    error_status_t result = RPC_S_OK;
    RpcTryExcept
    {
        result = Logout(binding);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        result = RpcExceptionCode();
    }
    RpcEndExcept
    return result;
}

static error_status_t SafeGetLicenseState(handle_t binding, long* hasLicense,
    wchar_t** expiryDate, wchar_t** message)
{
    error_status_t result = RPC_S_OK;
    RpcTryExcept
    {
        result = GetLicenseState(binding, hasLicense, expiryDate, message);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        result = RpcExceptionCode();
    }
    RpcEndExcept
    return result;
}

static error_status_t SafeActivateProduct(handle_t binding, wchar_t* activationCode,
    long* success, wchar_t** expiryDate, wchar_t** message)
{
    error_status_t result = RPC_S_OK;
    RpcTryExcept
    {
        result = ActivateProduct(binding, activationCode, success, expiryDate, message);
    }
    RpcExcept(EXCEPTION_EXECUTE_HANDLER)
    {
        result = RpcExceptionCode();
    }
    RpcEndExcept
    return result;
}

static bool RpcGetAuth(long& authenticated, std::wstring& username)
{
    auto binding = OpenServiceRpc(); if (!binding) return false;
    wchar_t* user = nullptr; error_status_t result = RPC_S_OK;
    result = SafeGetAuthState(binding, &authenticated, &user);
    if (result == RPC_S_OK && user) username = user;
    FreeRpcString(user); RpcBindingFree(&binding);
    return result == RPC_S_OK;
}

static bool RpcLogin(const std::wstring& username, const std::wstring& password,
    bool& success, std::wstring& message)
{
    auto binding = OpenServiceRpc(); if (!binding) { message = L"Не удалось подключиться к службе."; return false; }
    long ok = 0; wchar_t* msg = nullptr; wchar_t* user = nullptr; error_status_t result = RPC_S_OK;
    result = SafeLogin(binding, const_cast<wchar_t*>(username.c_str()),
        const_cast<wchar_t*>(password.c_str()), &ok, &msg, &user);
    success = ok != 0; if (msg) message = msg;
    FreeRpcString(msg); FreeRpcString(user); RpcBindingFree(&binding);
    if (result != RPC_S_OK) { message = L"Ошибка RPC при входе (" + std::to_wstring(result) + L")."; return false; }
    return true;
}

static bool RpcLogout()
{
    auto binding = OpenServiceRpc(); if (!binding) return false;
    error_status_t result = RPC_S_OK;
    result = SafeLogout(binding);
    RpcBindingFree(&binding); return result == RPC_S_OK;
}

static bool RpcGetLicense(long& hasLicense, std::wstring& expiry, std::wstring& message)
{
    auto binding = OpenServiceRpc(); if (!binding) { message = L"Не удалось подключиться к службе."; return false; }
    wchar_t* date = nullptr; wchar_t* msg = nullptr; error_status_t result = RPC_S_OK;
    result = SafeGetLicenseState(binding, &hasLicense, &date, &msg);
    if (date) expiry = date; if (msg) message = msg;
    FreeRpcString(date); FreeRpcString(msg); RpcBindingFree(&binding);
    if (result != RPC_S_OK) { message = L"Ошибка RPC при проверке лицензии (" + std::to_wstring(result) + L")."; return false; }
    return true;
}

static bool RpcActivate(const std::wstring& code, bool& success, std::wstring& expiry, std::wstring& message)
{
    auto binding = OpenServiceRpc(); if (!binding) { message = L"Не удалось подключиться к службе."; return false; }
    long ok = 0; wchar_t* date = nullptr; wchar_t* msg = nullptr; error_status_t result = RPC_S_OK;
    result = SafeActivateProduct(binding, const_cast<wchar_t*>(code.c_str()),
        &ok, &date, &msg);
    success = ok != 0; if (date) expiry = date; if (msg) message = msg;
    FreeRpcString(date); FreeRpcString(msg); RpcBindingFree(&binding);
    if (result != RPC_S_OK) { message = L"Ошибка RPC при активации (" + std::to_wstring(result) + L")."; return false; }
    return true;
}

#define ID_USERNAME_EDIT 1101
#define ID_PASSWORD_EDIT 1102
#define ID_LOGIN_BUTTON 1103
#define ID_LOGOUT_BUTTON 1104
#define ID_ACTIVATION_EDIT 1105
#define ID_ACTIVATE_BUTTON 1106
#define ID_REFRESH_BUTTON 1107
static HWND g_userEdit = nullptr, g_passwordEdit = nullptr, g_loginButton = nullptr;
static HWND g_logoutButton = nullptr, g_activationEdit = nullptr, g_activateButton = nullptr;
static HWND g_userLabel = nullptr, g_statusLabel = nullptr, g_licenseLabel = nullptr, g_activationLabel = nullptr;

static void SetControlVisible(HWND control, bool visible)
{
    if (control) ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
}

static void RefreshUiState(HWND hwnd)
{
    // Keep the activation row visible even before login or when the service is
    // temporarily unreachable, so the UI never silently hides the feature.
    SetControlVisible(g_activationLabel, true);
    SetControlVisible(g_activationEdit, true);
    SetControlVisible(g_activateButton, true);
    long authenticated = 0; std::wstring username;
    if (!RpcGetAuth(authenticated, username))
    {
        SetWindowTextW(g_statusLabel, L"Нет связи со службой TrayService.");
        return;
    }
    bool auth = authenticated != 0;
    SetControlVisible(g_userEdit, !auth); SetControlVisible(g_passwordEdit, !auth); SetControlVisible(g_loginButton, !auth);
    SetControlVisible(g_logoutButton, auth);
    if (!auth)
    {
        SetWindowTextW(g_userLabel, L"Пользователь: не выполнен вход");
        SetWindowTextW(g_licenseLabel, L"Лицензия: недоступна без входа");
        SetWindowTextW(g_statusLabel, L"Войдите в учётную запись, чтобы продолжить.");
        return;
    }
    std::wstring userText = L"Пользователь: " + username;
    SetWindowTextW(g_userLabel, userText.c_str());
    // Keep activation controls visible for every authenticated account. This also
    // makes the activation flow available if the license-status endpoint is unavailable.
    SetControlVisible(g_activationLabel, true);
    SetControlVisible(g_activationEdit, true);
    SetControlVisible(g_activateButton, true);
    long hasLicense = 0; std::wstring expiry, message;
    if (!RpcGetLicense(hasLicense, expiry, message))
    {
        SetWindowTextW(g_statusLabel, message.c_str());
        SetControlVisible(g_activationLabel, true); SetControlVisible(g_activationEdit, true); SetControlVisible(g_activateButton, true);
        return;
    }
    if (hasLicense)
    {
        std::wstring licenseText = L"Лицензия активна. Действует до: " + (expiry.empty() ? L"дата не указана сервером" : expiry);
        SetWindowTextW(g_licenseLabel, licenseText.c_str());
        SetWindowTextW(g_statusLabel, L"Защита разрешена: лицензия активна.");
        SetControlVisible(g_activationLabel, true); SetControlVisible(g_activationEdit, true); SetControlVisible(g_activateButton, true);
    }
    else
    {
        SetWindowTextW(g_licenseLabel, L"Лицензия отсутствует или не активирована.");
        SetWindowTextW(g_statusLabel, message.empty() ? L"Введите код активации продукта." : message.c_str());
        SetControlVisible(g_activationLabel, true); SetControlVisible(g_activationEdit, true); SetControlVisible(g_activateButton, true);
    }
}

// ============================================================
// Tray icon and window
// ============================================================

#define WM_TRAYICON (WM_USER + 1)

#define ID_TRAY_OPEN 1001
#define ID_TRAY_EXIT 1002
#define ID_MAIN_EXIT 1003
#define ID_TRAYICON  1

static NOTIFYICONDATAW nid{};
static HWND g_hwnd = nullptr;

// ============================================================
// Show main window
// ============================================================

static void ShowMainWindow()
{
    if (!g_hwnd)
        return;

    ShowWindow(g_hwnd, SW_SHOW);
    ShowWindow(g_hwnd, SW_RESTORE);
    SetForegroundWindow(g_hwnd);
}

// ============================================================
// Tray context menu
// ============================================================

static void ShowTrayMenu()
{
    POINT pt{};

    if (!GetCursorPos(&pt))
        return;

    HMENU menu = CreatePopupMenu();

    if (!menu)
        return;

    if (!AppendMenuW(menu, MF_STRING, ID_TRAY_OPEN, L"Открыть") ||
        !AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"Выход"))
    {
        DestroyMenu(menu);
        return;
    }

    SetForegroundWindow(g_hwnd);

    TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
        pt.x,
        pt.y,
        0,
        g_hwnd,
        nullptr);

    DestroyMenu(menu);
}

// ============================================================
// Window procedure
// ============================================================

static LRESULT CALLBACK WndProc(
    HWND hwnd,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        // Main window menu: File -> Exit.
        HMENU menuBar = CreateMenu();
        HMENU fileMenu = CreatePopupMenu();

        if (!menuBar || !fileMenu)
        {
            if (menuBar)
                DestroyMenu(menuBar);

            if (fileMenu)
                DestroyMenu(fileMenu);

            return -1;
        }

        if (!AppendMenuW(
            fileMenu,
            MF_STRING,
            ID_MAIN_EXIT,
            L"Выход"))
        {
            DestroyMenu(fileMenu);
            DestroyMenu(menuBar);
            return -1;
        }

        if (!AppendMenuW(
            menuBar,
            MF_POPUP,
            reinterpret_cast<UINT_PTR>(fileMenu),
            L"Файл"))
        {
            DestroyMenu(fileMenu);
            DestroyMenu(menuBar);
            return -1;
        }

        if (!SetMenu(hwnd, menuBar))
        {
            DestroyMenu(fileMenu);
            DestroyMenu(menuBar);
            return -1;
        }

        nid = {};
        nid.cbSize = sizeof(nid);
        nid.hWnd = hwnd;
        nid.uID = ID_TRAYICON;
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAYICON;
        nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);

        lstrcpynW(
            nid.szTip, L"TrayApp", ARRAYSIZE(nid.szTip));

        if (!Shell_NotifyIconW(NIM_ADD, &nid))
        {
            LogAppDiagnostic(
                "Shell_NotifyIconW NIM_ADD failed", GetLastError());
            return -1;
        }

        // Create explicit controls and keep their handles for state transitions.
        g_userLabel = CreateWindowW(L"STATIC", L"Пользователь: проверка...", WS_CHILD | WS_VISIBLE, 24, 24, 600, 26, hwnd, nullptr, nullptr, nullptr);
        g_statusLabel = CreateWindowW(L"STATIC", L"Подключение к службе...", WS_CHILD | WS_VISIBLE, 24, 62, 620, 42, hwnd, nullptr, nullptr, nullptr);
        g_licenseLabel = CreateWindowW(L"STATIC", L"Лицензия: проверка...", WS_CHILD | WS_VISIBLE, 24, 108, 620, 42, hwnd, nullptr, nullptr, nullptr);
        CreateWindowW(L"STATIC", L"Логин", WS_CHILD | WS_VISIBLE, 24, 174, 100, 24, hwnd, nullptr, nullptr, nullptr);
        g_userEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 130, 170, 260, 28, hwnd, reinterpret_cast<HMENU>(ID_USERNAME_EDIT), nullptr, nullptr);
        CreateWindowW(L"STATIC", L"Пароль", WS_CHILD | WS_VISIBLE, 24, 210, 100, 24, hwnd, nullptr, nullptr, nullptr);
        g_passwordEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 130, 206, 260, 28, hwnd, reinterpret_cast<HMENU>(ID_PASSWORD_EDIT), nullptr, nullptr);
        g_loginButton = CreateWindowW(L"BUTTON", L"Войти", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 410, 188, 120, 34, hwnd, reinterpret_cast<HMENU>(ID_LOGIN_BUTTON), nullptr, nullptr);
        g_logoutButton = CreateWindowW(L"BUTTON", L"Выйти из аккаунта", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 410, 188, 170, 34, hwnd, reinterpret_cast<HMENU>(ID_LOGOUT_BUTTON), nullptr, nullptr);
        g_activationLabel = CreateWindowW(L"STATIC", L"Код активации:", WS_CHILD | WS_VISIBLE, 24, 264, 112, 24, hwnd, nullptr, nullptr, nullptr);
        g_activationEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 145, 260, 245, 28, hwnd, reinterpret_cast<HMENU>(ID_ACTIVATION_EDIT), nullptr, nullptr);
        g_activateButton = CreateWindowW(L"BUTTON", L"Активировать", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 410, 256, 140, 34, hwnd, reinterpret_cast<HMENU>(ID_ACTIVATE_BUTTON), nullptr, nullptr);
        SetControlVisible(g_logoutButton, false);
        SetTimer(hwnd, 1, 30000, nullptr);
        RefreshUiState(hwnd);
        LogAppDiagnostic("Tray icon created", 0);
        return 0;
    }

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONUP)
        {
            ShowMainWindow();
        }
        else if (lParam == WM_RBUTTONUP)
        {
            ShowTrayMenu();
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_TRAY_OPEN:
            ShowMainWindow();
            return 0;

        case ID_TRAY_EXIT:
        case ID_MAIN_EXIT:
            if (!RequestTrayServiceStop())
            {
                MessageBoxW(
                    hwnd,
                    L"Не удалось отправить запрос на остановку "
                    L"службы TrayService.\n"
                    L"Проверьте журнал приложения.",
                    L"TrayApp",
                    MB_OK | MB_ICONERROR);
            }
            return 0;
        case ID_LOGIN_BUTTON:
        {
            wchar_t username[256]{}, password[256]{};
            GetWindowTextW(g_userEdit, username, ARRAYSIZE(username));
            GetWindowTextW(g_passwordEdit, password, ARRAYSIZE(password));
            bool success = false; std::wstring message;
            if (!RpcLogin(username, password, success, message) || !success)
            {
                MessageBoxW(hwnd, message.c_str(), L"Ошибка входа", MB_OK | MB_ICONERROR);
                SetWindowTextW(g_passwordEdit, L""); RefreshUiState(hwnd); return 0;
            }
            SetWindowTextW(g_passwordEdit, L""); RefreshUiState(hwnd); return 0;
        }
        case ID_LOGOUT_BUTTON:
            if (!RpcLogout()) MessageBoxW(hwnd, L"Не удалось выполнить выход из аккаунта.", L"TrayApp", MB_OK | MB_ICONERROR);
            RefreshUiState(hwnd); return 0;
        case ID_ACTIVATE_BUTTON:
        {
            wchar_t code[512]{}; GetWindowTextW(g_activationEdit, code, ARRAYSIZE(code));
            bool success = false; std::wstring expiry, message;
            if (!RpcActivate(code, success, expiry, message) || !success)
            {
                MessageBoxW(hwnd, message.c_str(), L"Ошибка активации", MB_OK | MB_ICONERROR);
                RefreshUiState(hwnd); return 0;
            }
            SetWindowTextW(g_activationEdit, L""); RefreshUiState(hwnd); return 0;
        }
        }
        break;

    case WM_TIMER:
        if (wParam == 1) RefreshUiState(hwnd);
        return 0;

    case WM_CLOSE:
        // Closing the window hides it; it does not stop the service.
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &nid);
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    return 0;
}

// ============================================================
// Application entry point
// ============================================================

int WINAPI wWinMain(
    HINSTANCE hInstance,
    HINSTANCE,
    PWSTR commandLine,
    int)
{
    LogAppDiagnostic("Application started", 0);

    // A manually launched instance starts the service if needed,
    // waits for RUNNING, and then exits.
    bool serviceLaunch =
        commandLine != nullptr &&
        wcsstr(commandLine, L"--service-launch") != nullptr;

    if (!serviceLaunch)
    {
        LogAppDiagnostic(
            "Manual launch; checking service", 0);

        EnsureTrayServiceRunning();
        return 0;
    }

    // Only accept an instance whose parent is the running service.
    if (!IsLaunchedByTrayService())
    {
        LogAppDiagnostic(
            "Application rejected because parent is invalid", 0);
        return 0;
    }

    const wchar_t CLASS_NAME[] = L"TrayAppWindow";

    WNDCLASSW wc{};

    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);

    if (!RegisterClassW(&wc))
    {
        LogAppDiagnostic("RegisterClassW failed", GetLastError());
        return 1;
    }

    g_hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"TrayApp",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        680,
        380,
        nullptr,
        nullptr,
        hInstance,
        nullptr);

    if (!g_hwnd)
    {
        LogAppDiagnostic(
            "CreateWindowExW failed", GetLastError());
        return 1;
    }

    // Start with the main window hidden.
    ShowWindow(g_hwnd, SW_HIDE);
    UpdateWindow(g_hwnd);

    LogAppDiagnostic("Message loop started", 0);

    MSG msg{};
    int result = 0;

    while ((result = GetMessageW(
        &msg, nullptr, 0, 0)) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (result == -1)
    {
        LogAppDiagnostic("GetMessageW failed", GetLastError());
        return 1;
    }

    LogAppDiagnostic("Application exiting", 0);
    return static_cast<int>(msg.wParam);
}
