
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

#include "TrayRpc_h.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib")

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

    SetServiceState(SERVICE_RUNNING);

    LaunchTrayAppForExistingSessions();

    HANDLE waitHandles[] = { g_stopEvent, rpcThread };

    WaitForMultipleObjects(
        2, waitHandles, FALSE, INFINITE);

    SetServiceState(SERVICE_STOP_PENDING);

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
