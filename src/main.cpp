#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <shellscalingapi.h>
#include <cwchar>

namespace
{
    constexpr wchar_t kWindowClass[] = L"TrayAppMainWindowClass";
    constexpr wchar_t kWindowTitle[] = L"TrayApp";
    constexpr UINT kTrayIconId = 1;
    constexpr UINT kTrayCallbackMessage = WM_APP + 1;
    constexpr UINT kMenuOpen = 1001;
    constexpr UINT kMenuExit = 1002;

    UINT g_taskbarCreatedMessage = 0;
    NOTIFYICONDATAW g_nid{};
    bool g_trayIconAdded = false;
    HANDLE g_singleInstanceMutex = nullptr;

    bool IsBackgroundLaunch()
    {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (!argv)
            return false;

        bool background = false;
        for (int i = 1; i < argc; ++i)
        {
            if (_wcsicmp(argv[i], L"--background") == 0)
            {
                background = true;
                break;
            }
        }
        LocalFree(argv);
        return background;
    }

    bool AddTrayIcon(HWND hwnd)
    {
        ZeroMemory(&g_nid, sizeof(g_nid));
        g_nid.cbSize = sizeof(g_nid);
        g_nid.hWnd = hwnd;
        g_nid.uID = kTrayIconId;
        g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        g_nid.uCallbackMessage = kTrayCallbackMessage;
        g_nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
        wcscpy_s(g_nid.szTip, L"TrayApp");

        if (!Shell_NotifyIconW(NIM_ADD, &g_nid))
            return false;

        g_nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
        g_trayIconAdded = true;
        return true;
    }

    void RemoveTrayIcon()
    {
        if (g_trayIconAdded)
        {
            Shell_NotifyIconW(NIM_DELETE, &g_nid);
            g_trayIconAdded = false;
        }
    }

    void ShowMainWindow(HWND hwnd)
    {
        if (IsIconic(hwnd))
            ShowWindow(hwnd, SW_RESTORE);
        else
            ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }

    void ShowTrayContextMenu(HWND hwnd)
    {
        HMENU menu = CreatePopupMenu();
        if (!menu)
            return;

        AppendMenuW(menu, MF_STRING, kMenuOpen, L"Открыть");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, kMenuExit, L"Выход");

        POINT cursor{};
        GetCursorPos(&cursor);
        SetForegroundWindow(hwnd);
        TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                       cursor.x, cursor.y, 0, hwnd, nullptr);
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
    }

    HMENU CreateMainMenu()
    {
        HMENU menuBar = CreateMenu();
        HMENU fileMenu = CreatePopupMenu();
        if (!menuBar || !fileMenu)
        {
            if (menuBar) DestroyMenu(menuBar);
            if (fileMenu) DestroyMenu(fileMenu);
            return nullptr;
        }

        AppendMenuW(fileMenu, MF_STRING, kMenuExit, L"Выход");
        AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"Файл");
        return menuBar;
    }

    LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        if (g_taskbarCreatedMessage != 0 && message == g_taskbarCreatedMessage)
        {
            g_trayIconAdded = false;
            AddTrayIcon(hwnd);
            return 0;
        }

        switch (message)
        {
        case WM_CREATE:
            if (!AddTrayIcon(hwnd))
            {
                MessageBoxW(hwnd, L"Не удалось создать иконку в системном трее.",
                            L"TrayApp", MB_OK | MB_ICONERROR);
                return -1;
            }
            return 0;

        case kTrayCallbackMessage:
        {
            const UINT event = LOWORD(lParam);
            if (event == WM_LBUTTONUP || event == NIN_SELECT || event == NIN_KEYSELECT)
                ShowMainWindow(hwnd);
            else if (event == WM_RBUTTONUP || event == WM_CONTEXTMENU)
                ShowTrayContextMenu(hwnd);
            return 0;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
            case kMenuOpen:
                ShowMainWindow(hwnd);
                return 0;
            case kMenuExit:
                DestroyWindow(hwnd);
                return 0;
            default:
                break;
            }
            break;

        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;

        case WM_DESTROY:
            RemoveTrayIcon();
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    bool AcquireSingleInstanceMutex()
    {
        g_singleInstanceMutex = CreateMutexW(nullptr, TRUE,
                                              L"Local\\TrayApp_SingleInstance_Mutex");
        if (!g_singleInstanceMutex)
            return false;

        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            CloseHandle(g_singleInstanceMutex);
            g_singleInstanceMutex = nullptr;
            return false;
        }
        return true;
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand)
{
    if (!AcquireSingleInstanceMutex())
        return 0;

    g_taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.hInstance = instance;
    wc.lpfnWndProc = WindowProc;
    wc.lpszClassName = kWindowClass;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    if (!RegisterClassExW(&wc))
    {
        CloseHandle(g_singleInstanceMutex);
        return 1;
    }

    HMENU menu = CreateMainMenu();
    if (!menu)
    {
        UnregisterClassW(kWindowClass, instance);
        CloseHandle(g_singleInstanceMutex);
        return 1;
    }

    HWND hwnd = CreateWindowExW(
        0, kWindowClass, kWindowTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 400,
        nullptr, menu, instance, nullptr
    );

    if (!hwnd)
    {
        DestroyMenu(menu);
        UnregisterClassW(kWindowClass, instance);
        CloseHandle(g_singleInstanceMutex);
        return 1;
    }

    if (!IsBackgroundLaunch() && showCommand != SW_HIDE)
    {
        ShowWindow(hwnd, showCommand);
        UpdateWindow(hwnd);
    }

    MSG msg{};
    BOOL result = 0;
    while ((result = GetMessageW(&msg, nullptr, 0, 0)) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    DestroyMenu(menu);
    UnregisterClassW(kWindowClass, instance);
    if (g_singleInstanceMutex)
    {
        ReleaseMutex(g_singleInstanceMutex);
        CloseHandle(g_singleInstanceMutex);
    }
    return result == -1 ? 1 : static_cast<int>(msg.wParam);
}
