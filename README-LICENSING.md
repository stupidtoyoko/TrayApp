# TrayApp authentication and licensing integration

This branch extends the existing TrayApp/TrayService Windows RPC sample with an in-memory authentication session, token refresh, license status/activation RPC calls, and a basic GUI for login and activation.

## Important integration limitation

The supplied repository did not contain the assignment 1.2 server, API documentation, OpenAPI schema, endpoint URLs, HTTP methods, or example payloads. Therefore this implementation uses a **configurable example API contract**, not a verified contract for a real server. It cannot successfully authenticate until `TrayService.ini` and the JSON parsing rules below are matched to the actual backend. This is not a claim that a real backend has been tested.

## Configure the HTTPS API

Edit `TrayService.ini` next to `TrayService.exe` (the project copies a default file to the output directory). Set `base_url` to the HTTPS origin of the API, for example `https://api.example.test`. The client rejects plain HTTP. Adjust the endpoint paths and methods to match the backend:

- `login`: default `POST /api/auth/login`, JSON `{ "username": "...", "password": "..." }`
- `refresh`: default `POST /api/auth/refresh`, JSON `{ "refresh_token": "..." }`
- `license_status`: default `POST /api/license/status`, JSON `{}` with `Authorization: Bearer <access_token>`
- `activate`: default `POST /api/license/activate`, JSON `{ "activation_code": "..." }` with `Authorization: Bearer <access_token>`

The current response reader expects:

- Login/refresh: `access_token` and `refresh_token`; optional `expires_in` and `refresh_expires_in` in seconds; optional `username`.
- License status: `has_license` (boolean or 0/1), `ticket` or `license_ticket` (string), `expires_at` or `license_expires_at`, optional `ticket_ttl_seconds`.
- Activation: optional `ticket`/`license_ticket`, `expires_at`/`license_expires_at`, optional `ticket_ttl_seconds`. If no ticket is returned, the service calls the configured license-status endpoint.

If the backend returns a nested ticket object, uses different JSON field names, expects a different payload, or requires another authorization scheme, adapt the parser and request payloads in `TrayService.cpp` to that actual contract.

## Build in Visual Studio 2022

1. Open `TrayApp.slnx`.
2. Select `x64` and `Release` (or `Debug`).
3. Build the solution. `TrayApp` generates the RPC stubs from `TrayApp/TrayRpc.idl`; the service project has a build dependency on that project.
4. Find `TrayApp.exe` and `TrayService.exe` in the corresponding `x64/Release` output folders. Put both executables in the same directory. Put the configured `TrayService.ini` next to `TrayService.exe`.

The CI workflow in this repository is Windows-only. The current development environment used to prepare this archive is Linux and does not have MSVC/MIDL, so a native Windows compile could not be run here. Please perform the first build in Visual Studio or CI and share any diagnostics if a correction is needed.

## Install and run

Install the service from an elevated PowerShell window after placing the executables together:

```powershell
sc.exe create TrayService binPath= "C:\Path\To\TrayService.exe" start= auto
sc.exe start TrayService
```

Launch `TrayApp.exe` as the logged-in desktop user. A manually launched instance asks the service to start if necessary and then exits; the service launches the interactive tray instance in the current session. Open it from the tray icon.

To remove the service later (elevated PowerShell):

```powershell
sc.exe stop TrayService
sc.exe delete TrayService
```

The service is expected to run with permissions sufficient to launch the tray process in user sessions. Service installation and interactive-session behavior depend on Windows configuration and may require administrator privileges.

## Security and scope notes

- Access/refresh tokens and the license ticket are kept in process memory only; they are not written to files or returned through RPC.
- The GUI receives only authentication state/username, license presence, expiry date, and status text.
- Token refresh is scheduled from `expires_in` with a safety margin. License status refresh is scheduled from `ticket_ttl_seconds`.
- Logout clears the in-memory tokens and ticket. Service shutdown also clears them.
- The supplied project did not contain antivirus scanning features or RPC operations for them. This change therefore presents license-gated UI state but cannot gate antivirus operations that do not exist in this codebase yet.
- The existing RPC endpoint's access control should be hardened before production use. Microsoft notes that local `ncalrpc` endpoints are still a security boundary and require explicit client authentication/access checks: https://learn.microsoft.com/en-us/windows/win32/rpc/writing-a-secure-rpc-client-or-server
