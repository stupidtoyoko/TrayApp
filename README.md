# TrayApp / TrayService

Windows C++ tray application and Windows service. This version adds an initial configurable authentication/licensing integration to the existing local RPC architecture.

Start with [README-LICENSING.md](README-LICENSING.md) for API assumptions, configuration, build, and installation instructions.

**Important:** the original archive did not include the assignment 1.2 server or its API contract. The integration therefore uses configurable example endpoints and JSON field names. Match these to the actual backend before expecting real authentication/activation to work. The source was prepared in a Linux environment and still requires a Windows/MSVC/MIDL build verification.
