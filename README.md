# TrayApp

Минимальное графическое приложение Windows на C++ / Win32 API с CMake.

## Реализованные требования

- Иконка в системном трее при запуске.
- Левый клик по иконке показывает главное окно.
- Правый клик открывает меню «Открыть» и «Выход».
- Закрытие окна крестиком скрывает его, приложение остаётся в трее.
- Меню главного окна: «Файл → Выход».
- Запуск с `--background` скрывает окно, оставляя иконку в трее.
- Второй экземпляр блокируется именованным mutex до создания окна и иконки.
- При получении сообщения `TaskbarCreated` приложение повторно добавляет иконку.
- GitHub Actions собирает Release EXE и публикует его как workflow artifact.

## Требования

- Windows 10/11
- Visual Studio 2022 с workload **Desktop development with C++**
- CMake и Windows SDK

## Открыть в Visual Studio

1. Распакуйте архив.
2. В Visual Studio выберите **File → Open → Folder**.
3. Выберите папку `TrayApp-main`, где лежит `CMakeLists.txt`.
4. Выберите конфигурацию `x64-Debug` для разработки или `x64-Release` для итоговой сборки.
5. Соберите и запустите цель `TrayApp`.

## Сборка из Developer PowerShell for VS

В корне проекта:

```powershell
cmake -S . -B out/build -A x64
cmake --build out/build --config Release
```

EXE будет находиться в `out/build/Release/TrayApp.exe`.

## Проверка фонового режима

```powershell
& ".\out\build\Release\TrayApp.exe" --background
```

Ожидается: окно не появляется, но иконка видна в системном трее. Через контекстное меню выберите «Открыть», чтобы показать окно. Без параметра `--background` окно показывается сразу.

## Зависимости

Приложение использует только системные библиотеки Windows (`user32`, `shell32`, `advapi32`). Сторонние DLL не нужны.

## CI

GitHub Actions запускает CMake на `windows-latest`, собирает `Release` и прикрепляет `TrayApp.exe` как artifact.
Updated
