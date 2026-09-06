@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Resolve every path relative to this script so that it can be started from
rem Visual Studio, Explorer, or an arbitrary command prompt directory.
set "ROOT=%~dp0"
set "ASSEMBLY_INFO=%ROOT%IconCatcherLoader.Net48\Properties\AssemblyInfo.cs"
set "LICENSE_FILE=%ROOT%license.txt"
set "BINARY_NAME=IconCatcherLoader.exe"

rem Derive the archive name from the solution file rather than duplicating it.
set "SOLUTION_FILE="
set "SOLUTION_NAME="
for %%S in ("%ROOT%*.sln") do if not defined SOLUTION_FILE if exist "%%~fS" (
    set "SOLUTION_FILE=%%~fS"
    set "SOLUTION_NAME=%%~nS"
)

if not defined SOLUTION_FILE (
    echo Error: No solution file was found in "%ROOT%". 1>&2
    exit /b 1
)

if not exist "%ASSEMBLY_INFO%" (
    echo Error: AssemblyInfo.cs was not found. 1>&2
    exit /b 1
)

if not exist "%LICENSE_FILE%" (
    echo Error: license.txt was not found. 1>&2
    exit /b 1
)

rem Extract the four-part AssemblyFileVersion shared by all projects.
set "VERSION="
for /f "tokens=2 delims=()" %%V in ('findstr.exe /L /B /C:"[assembly: AssemblyFileVersion(" "%ASSEMBLY_INFO%"') do set "VERSION=%%~V"

if not defined VERSION (
    echo Error: AssemblyFileVersion was not found in "%ASSEMBLY_INFO%". 1>&2
    exit /b 1
)

set "ARCHIVE=%ROOT%%SOLUTION_NAME%-%VERSION%.zip"
set "STAGING=%TEMP%\%SOLUTION_NAME%-package-%RANDOM%-%RANDOM%"

if exist "%STAGING%" (
    echo Error: The temporary directory already exists: "%STAGING%". 1>&2
    exit /b 1
)

mkdir "%STAGING%" || goto Failed

call :StageProject "IconCatcherLoader.Net20" || goto Failed
call :StageProject "IconCatcherLoader.Net35Client" || goto Failed
call :StageProject "IconCatcherLoader.Net40Client" || goto Failed
call :StageProject "IconCatcherLoader.Net48" || goto Failed

if exist "%ARCHIVE%" del /f /q "%ARCHIVE%"
if exist "%ARCHIVE%" (
    echo Error: The existing archive could not be replaced: "%ARCHIVE%". 1>&2
    goto Failed
)

rem Prefer 7-Zip because -mx=9 requests its maximum ZIP compression level.
set "SEVEN_ZIP="
for %%Z in (7z.exe) do if not "%%~$PATH:Z"=="" set "SEVEN_ZIP=%%~$PATH:Z"
if not defined SEVEN_ZIP if exist "%ProgramFiles%\7-Zip\7z.exe" set "SEVEN_ZIP=%ProgramFiles%\7-Zip\7z.exe"
if not defined SEVEN_ZIP if exist "%ProgramFiles(x86)%\7-Zip\7z.exe" set "SEVEN_ZIP=%ProgramFiles(x86)%\7-Zip\7z.exe"

if defined SEVEN_ZIP goto ZipWithSevenZip
goto ZipWithDotNet

:ZipWithSevenZip
pushd "%STAGING%" || goto Failed
"%SEVEN_ZIP%" a -tzip -mx=9 -mmt=on -y "%ARCHIVE%" *
set "ZIP_RESULT=%ERRORLEVEL%"
popd
if not "%ZIP_RESULT%"=="0" goto Failed
echo Created with 7-Zip maximum compression:
echo %ARCHIVE%
goto Succeeded

:ZipWithDotNet
set "PACKAGE_STAGE=%STAGING%"
set "PACKAGE_ARCHIVE=%ARCHIVE%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "try { Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::CreateFromDirectory($env:PACKAGE_STAGE, $env:PACKAGE_ARCHIVE, [IO.Compression.CompressionLevel]::Optimal, $false); exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
if errorlevel 1 (
    echo Error: ZIP creation failed. Install 7-Zip or use a PowerShell version capable of loading .NET Framework 4.5 or later. 1>&2
    goto Failed
)
echo Created with .NET optimal compression:
echo %ARCHIVE%
goto Succeeded

:StageProject
set "PROJECT_NAME=%~1"
set "RELEASE_DIRECTORY=%ROOT%%PROJECT_NAME%\bin\Release"
set "DESTINATION=%STAGING%\%PROJECT_NAME%"

if not exist "%RELEASE_DIRECTORY%\%BINARY_NAME%" (
    echo Error: Missing Release binary for %PROJECT_NAME%. 1>&2
    exit /b 1
)

mkdir "%DESTINATION%" || exit /b 1
copy /y "%RELEASE_DIRECTORY%\%BINARY_NAME%" "%DESTINATION%\%BINARY_NAME%" >nul || exit /b 1
copy /y "%LICENSE_FILE%" "%DESTINATION%\license.txt" >nul || exit /b 1
exit /b 0

:Succeeded
call :Cleanup
exit /b 0

:Failed
set "RESULT=%ERRORLEVEL%"
if "%RESULT%"=="0" set "RESULT=1"
call :Cleanup
exit /b %RESULT%

:Cleanup
if defined STAGING if exist "%STAGING%" rmdir /s /q "%STAGING%"
exit /b 0
