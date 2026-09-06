# IconCatcherLoader

IconCatcherLoader is an x86 Windows GUI loader for Icon Catcher 4.2.37
(file version 4.2.0.37). The executable contains an outdated product-version
value of 4.1.0.37, while its About box identifies the product as version 4.2.37.
It does not modify IconCatcher.exe on disk and does not open a console window.

The Visual Studio 2015 solution contains these projects:

- `IconCatcherLoader.Net20` targets .NET Framework 2.0.
- `IconCatcherLoader.Net35Client` targets .NET Framework 3.5 Client Profile.
- `IconCatcherLoader.Net40Client` targets .NET Framework 4 Client Profile.
- `IconCatcherLoader.Net48` targets .NET Framework 4.8.

All editable C# 6 source files, shared assembly metadata, and the application
icon physically reside in `IconCatcherLoader.Net48`. The other three projects
compile them through linked project items. No project uses NuGet packages or
third-party libraries. Each project writes its executable to its own
`bin\Debug` or `bin\Release` directory.

Open `IconCatcherLoader.sln` in Visual Studio 2015 and select **Rebuild
Solution** to build all four variants.

After a Release rebuild, run `PackageRelease.bat` from the solution root. The
script collects every Release executable, places a copy of `license.txt` beside
each framework variant, and creates
`IconCatcherLoader-x.x.x.x.zip` in the solution root. The version is read from
the shared `AssemblyFileVersion` attribute. The script uses 7-Zip level 9 when
7-Zip is available and otherwise uses .NET optimal ZIP compression.

## Choosing a package

All four packages contain the same x86 application. Choose the package by the
.NET Framework version already available on the computer, not by whether
Windows itself is 32-bit or 64-bit. The x86 loader runs natively on 32-bit
Windows and under WOW64 on 64-bit Windows.

The following tables give the preferred package for a normal desktop edition
of Windows, or Windows Server with the desktop shell. They assume the original
operating-system components: no .NET Framework download and no optional
Windows component must be installed or enabled first.

| Windows version | Framework supplied by Windows | Preferred package |
| --- | --- | --- |
| Windows 2000 SP4 | None | None without installing .NET Framework |
| Windows XP, including XP SP3 | None | None without installing .NET Framework |
| Windows Vista | 2.0 and 3.0 | `IconCatcherLoader.Net20` |
| Windows 7 | 3.5.1 | `IconCatcherLoader.Net35Client` |
| Windows 8 | 4.5 | `IconCatcherLoader.Net40Client` |
| Windows 8.1 | 4.5.1 | `IconCatcherLoader.Net40Client` |
| Windows 10 versions 1507-1809, including Enterprise 2016 LTSC and 2019 LTSC | 4.6-4.7.2 | `IconCatcherLoader.Net40Client` |
| Windows 10 version 1903 or later, including Enterprise 2021 LTSC | 4.8 | `IconCatcherLoader.Net48` |
| Windows 11, all versions | 4.8 or 4.8.1 | `IconCatcherLoader.Net48` |

| Windows Server version | Framework supplied by Windows | Preferred package |
| --- | --- | --- |
| Windows Server 2003 and 2003 R2 | No installed version can be assumed for every edition and configuration | None without installing or enabling .NET Framework |
| Windows Server 2008 with the desktop shell | 2.0 and 3.0 | `IconCatcherLoader.Net20` |
| Windows Server 2008 R2 with the desktop shell | 3.5.1 | `IconCatcherLoader.Net35Client` |
| Windows Server 2012 | 4.5 | `IconCatcherLoader.Net40Client` |
| Windows Server 2012 R2 | 4.5.1 | `IconCatcherLoader.Net40Client` |
| Windows Server 2016 | 4.6.2 | `IconCatcherLoader.Net40Client` |
| Windows Server 2019 and Windows Server version 1809 | 4.7.2 | `IconCatcherLoader.Net40Client` |
| Windows Server 2022 | 4.8 | `IconCatcherLoader.Net48` |
| Windows Server 2025 or later | 4.8.1 | `IconCatcherLoader.Net48` |

If .NET Framework has been installed separately, use this shorter rule:

| Highest suitable installed framework | Package |
| --- | --- |
| 2.0 or 3.0 | `IconCatcherLoader.Net20` |
| 3.5 or 3.5.1 | `IconCatcherLoader.Net35Client` |
| 4.0 through 4.7.2 | `IconCatcherLoader.Net40Client` |
| 4.8 or 4.8.1 | `IconCatcherLoader.Net48` |

Windows 2000 SP4 has been tested successfully with
`IconCatcherLoader.Net20` after .NET Framework 2.0 SP1 has been installed.
Installing .NET Framework 2.0 SP1 on Windows 2000 requires update KB835732 or
an update rollup that includes it.

In particular, Windows XP SP3 and Windows Server 2003 SP2 can run
`IconCatcherLoader.Net40Client` after .NET Framework 4.0 has been installed.
If only .NET Framework 2.0 or 3.5 is installed on those systems, use the
matching older package instead.

The Client Profile packages also run with the corresponding full framework,
which is a superset of Client Profile. .NET Framework 4.5 and later are
in-place, backward-compatible updates of the .NET Framework 4 runtime. The
`Net40Client` build is therefore the appropriate fallback on systems containing
versions 4.5 through 4.7.2. The `Net48` build specifically requires .NET
Framework 4.8 or 4.8.1.

The release archive deliberately contains no application configuration file.
Consequently, the `Net20` and `Net35Client` executables require the CLR 2
runtime supplied by .NET Framework 2.0 through 3.5. They are not universal
fallbacks for a computer that has only CLR 4 installed.

Server Core and Nano Server are not suitable targets. IconCatcher and this
loader are desktop GUI applications, even though the loader does not display a
console window.

The framework versions above follow Microsoft's
[.NET Framework installation table](https://learn.microsoft.com/en-us/dotnet/framework/install/on-server-2019),
[system requirements](https://learn.microsoft.com/en-us/dotnet/framework/get-started/system-requirements),
and [version compatibility guidance](https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/version-compatibility).
The table describes technical runtime availability, not whether an old Windows
release is still supported or safe to expose to a network.

## Executable search

The loader always performs the original bounded search first. It checks the
loader directory and the conventional IconCatcher installation locations below
the available Program Files and application-data directories. This fast search
does not store a path in the registry.

If the fast search succeeds, the loader removes any path cached by an earlier
deep search. If it fails, the loader checks the cached path and verifies the
exact supported executable hash. Only when both operations fail does it perform
a recursive search below the available Program Files, roaming AppData, local
AppData, and common AppData directories.

The recursive search never starts at a drive or share root, skips filesystem
reparse points, and ignores inaccessible directories. A verified path found by
the recursive search is stored for the current user as:

`HKEY_CURRENT_USER\FortSoft\IconCatcherLoader\ExecutablePath`

Registry access failures do not prevent the loader from starting a target found
by either search method.

## Runtime behavior

The loader starts IconCatcher, waits for its protected image to unpack, and
installs the required x86 hooks in process memory. The intermediate activation
dialog is bypassed in memory before it can be displayed. The loader remains
active until IconCatcher exits so that every successfully saved NE ICL file can
be converted to a same-named PE32 resource-only DLL.
