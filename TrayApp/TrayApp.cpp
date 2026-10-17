
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <rpc.h>
#include <cstdlib>
#include <cstdio>
#include <cwchar>

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
        }
        break;

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
        600,
        400,
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
