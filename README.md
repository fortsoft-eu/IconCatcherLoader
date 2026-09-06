# IconCatcherLoader - .NET Framework 4 Client Profile

This loader is intended for 32-bit Windows XP SP3.

- Target framework: .NET Framework 4 Client Profile
- Platform: x86
- Application type: WinExe without a console window
- Target application: IconCatcher 4.2.0.37 x86
- Solution format: Visual Studio 2015 (Solution Format 12.00)
- Language version: C# 6

Open IconCatcherLoader.sln in Visual Studio 2015.
The project contains only C# code and uses no third-party libraries. It builds
against the .NET Framework 4 Client Profile supplied with Visual Studio 2015.

The loader does not modify IconCatcher.exe on disk. It starts the target,
installs a 32-bit hook in its memory, and releases TAgSaveDialog whenever the
original save handler returns. A subsequent Save Selected command can therefore
create and display a new dialog instance.
After installing the hook, the loader remains active, closes the intermediate
modal dialog containing the Continue >> button by posting WM_CLOSE, and exits
when IconCatcher exits.
