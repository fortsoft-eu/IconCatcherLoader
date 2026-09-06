/**
 * This is open-source software licensed under the terms of the MIT License.
 *
 * Copyright (c) 2026 Petr Červinka - FortSoft <cervinka@fortsoft.eu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 **
 * Last modified for version 2.0.0.0
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.Win32;

namespace IconCatcherLoader {

    /// <summary>
    /// Provides a loader for the 32-bit IconCatcher 4.2.0.37 executable.
    ///
    /// The loader does not modify IconCatcher.exe on disk. It starts the executable,
    /// waits for the protected image to unpack in memory, and redirects the
    /// actSaveIcon OnExecute event and both direct "Save Selected..." OnClick events
    /// to a small hook installed in the target process. The hook invokes the original
    /// actSaveIconExecute method, clears the form field at offset 0x524 after the
    /// method returns, and destroys the TAgSaveDialog instance so that a subsequent
    /// save operation can create and display a new instance.
    ///
    /// The loader also changes one conditional branch in process memory so that the
    /// intermediate activation dialog is bypassed before it can be displayed. It
    /// remains running until IconCatcher exits and converts every successfully saved
    /// NE ICL file to a same-named PE32 resource-only DLL.
    ///
    /// A Delphi event in a 32-bit process is an eight-byte TMethod structure:
    ///
    ///     +0x00  Code  Four-byte address of the event handler
    ///     +0x04  Data  Four-byte Self pointer for the target object
    ///
    /// The events in the located actSaveIcon object have the following layout:
    ///
    ///     actSaveIcon + 0x30  OnExecute.Code
    ///     actSaveIcon + 0x34  OnExecute.Data
    ///     actSaveIcon + 0x38  OnUpdate.Code
    ///     actSaveIcon + 0x3C  OnUpdate.Data
    ///
    /// The main-menu and context-menu items also store direct copies of the same
    /// method at offset 0x80. The loader therefore replaces three four-byte Code
    /// values. It does not modify the Self pointers or the original OnUpdate event.
    /// </summary>
    internal static class Program {
        // The following addresses and offsets were identified by analyzing the
        // unpacked IconCatcher 4.2.0.37 process image.

        // TfmMainIconCatcherWindow.actSaveIconExecute.
        private const uint ExecuteHandler = 0x004C1B4C;

        // TfmMainIconCatcherWindow.actSaveIconUpdate.
        private const uint UpdateHandler = 0x004C1B70;

        // Conditional branch that leads to the intermediate activation dialog.
        private const uint ActivationDialogBranch = 0x004C1001;

        // Conditional branch in actoSaveToLibraryExecute that skips the Save dialog
        // when the preceding check returns true.
        private const uint SaveLibraryEarlyExit = 0x004C096B;

        // Beginning of the instructions that load Output before TICLExport.Execute.
        private const uint SaveLibraryWriterCallSite = 0x004C0C50;

        // Address at which Delphi stores the TICLExport class reference at run time.
        private const uint IclExportClassReference = 0x004B6C1C;

        // Inherited TExport constructor used to create a TICLExport instance.
        private const uint ExportConstructor = 0x0048C52C;

        // Delphi RTL @LStrAsg routine used to assign the destination file name.
        private const uint LongStringAssign = 0x00403D18;

        // Original continuation for an unsuccessful Save Library export.
        private const uint SaveLibraryFailureResume = 0x004C0C64;

        // Original continuation for a successful Save Library export.
        private const uint SaveLibrarySuccessResume = 0x004C0C83;

        // The shared block contains an AnsiString pointer, a sequence number, and
        // the Boolean result of the completed export.
        private const int SaveLibraryStateSize = 12;

        // Expected VMT pointer at the beginning of the TAction object.
        private const uint ActionVmt = 0x0045103C;

        // Expected VMT pointer for both menu items that store a direct OnClick handler.
        private const uint MenuItemVmt = 0x0044AC94;

        // Offset of the main-form field that contains the actSaveIcon pointer.
        private const int ActionFieldOffset = 0x46C;

        // Offset of the main-form field that contains the TAgSaveDialog pointer.
        private const int SaveDialogFieldOffset = 0x524;

        // Offset of the eight-byte OnExecute TMethod structure.
        private const int OnExecuteOffset = 0x30;

        // Offset of the eight-byte OnUpdate TMethod structure.
        private const int OnUpdateOffset = 0x38;

        // Offset of the direct OnClick event in each located menu-item object.
        private const int MenuClickOffset = 0x80;

        // The main menu and context menu create exactly two direct handler copies.
        private const int ExpectedMenuCallbackCount = 2;

        // The standard product directory name used by the installer.
        private const string ProductDirectoryName = "Icon Catcher";

        // The publisher directory name used by the installer.
        private const string PublisherDirectoryName = "Helexis";

        // The name of the executable located and started by the loader.
        private const string ExecutableFileName = "IconCatcher.exe";

        // The per-user registry key used only for a path found by the deep search.
        private const string RegistryKeyPath = @"FortSoft\IconCatcherLoader";

        // The REG_SZ value that stores the verified absolute executable path.
        private const string RegistryValueName = "ExecutablePath";

        // SHA-256 of the analyzed executable. This prevents fixed addresses from
        // being used with another version that may contain unrelated data or code.
        private const string ExpectedSha256 = "B0583B666869A1446B4F656AE74351E8E9245BA5D4333D5481BA2959338CE50E";

        /// <summary>Provides the application entry point.</summary>
        /// <remarks>
        /// STAThread selects a single-threaded apartment. The memory operations do
        /// not require it, but it is the standard apartment model for a Windows GUI
        /// executable that can display dialogs.
        /// </remarks>
        [STAThread]
        private static void Main() {
            // The native handle must remain available to the finally block. A zero
            // value means that OpenProcess has not succeeded.
            IntPtr processHandle = IntPtr.Zero;

            try {
                // Locate the executable and verify the exact supported binary.
                string executable = LocateIconCatcher();
                VerifyExecutable(executable);

                // Use the IconCatcher directory as the working directory so that the
                // target locates its companion files in the normal location.
                string workingDirectory = Path.GetDirectoryName(executable);
                if (workingDirectory == null) {
                    throw new InvalidOperationException("The IconCatcher working directory could not be determined.");
                }

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = executable;
                startInfo.WorkingDirectory = workingDirectory;
                startInfo.UseShellExecute = false;

                Process startedProcess = Process.Start(startInfo);
                if (startedProcess == null) {
                    throw new InvalidOperationException("IconCatcher.exe could not be started.");
                }

                // Disposing the Process object does not terminate IconCatcher. It only
                // releases the managed resources used to monitor the target process.
                Process process = startedProcess;

                // Open a dedicated Win32 handle because Process.Handle may not have
                // the rights required to query, read, and modify the address space.
                uint processAccessRights = NativeMethods.ProcessVmOperation
                    | NativeMethods.ProcessVmRead
                    | NativeMethods.ProcessVmWrite
                    | NativeMethods.ProcessQueryInformation;
                processHandle = NativeMethods.OpenProcess(processAccessRights, false, process.Id);

                if (processHandle == IntPtr.Zero) {
                    // SetLastError preserves the OpenProcess error code.
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // ASProtect unpacks the executable before Delphi creates the main form
                // and actSaveIcon. Poll the address space for up to 20 seconds.
                Stopwatch timeout = Stopwatch.StartNew();
                while (timeout.Elapsed < TimeSpan.FromSeconds(20)) {
                    if (process.HasExited) {
                        throw new InvalidOperationException("IconCatcher exited before the hook was installed.");
                    }

                    // A zero value means that the object is not present yet or that no
                    // sufficiently reliable match was found.
                    IntPtr action = FindAction(processHandle);
                    if (action != IntPtr.Zero) {
                        byte[] formData = Read(processHandle, AddOffset(action, OnExecuteOffset + sizeof(uint)), sizeof(uint));
                        if (formData == null) {
                            Thread.Sleep(10);
                            continue;
                        }

                        uint form = BitConverter.ToUInt32(formData, 0);
                        List<IntPtr> menuCallbacks = FindMenuCallbacks(processHandle, form);
                        if (menuCallbacks.Count != ExpectedMenuCallbackCount) {
                            Thread.Sleep(10);
                            continue;
                        }

                        DisableActivationDialog(processHandle);
                        DisableSaveLibraryEarlyExit(processHandle);
                        IntPtr saveLibraryState = InstallSaveLibraryWriterFallback(processHandle);
                        IntPtr hook = InstallSaveHook(processHandle);
                        RedirectToHook(processHandle, action, menuCallbacks, hook);

                        // Keep the loader alive so it can convert every completed ICL
                        // export. The method returns only after IconCatcher exits.
                        WatchSaveLibraryExports(process, processHandle, saveLibraryState);
                        return;
                    }

                    // A short delay limits CPU usage while polling.
                    Thread.Sleep(10);
                }

                throw new TimeoutException("The actSaveIcon object was not found before the timeout expired.");
            } catch (Exception exception) {
                Debug.WriteLine(exception);
                // The WinExe output type has no console, so display errors in a native
                // message box. The 0x10 flag specifies MB_ICONERROR.
                NativeMethods.MessageBox(IntPtr.Zero, exception.Message, "IconCatcherLoader", 0x10);
            } finally {
                // Always release the handle returned by OpenProcess.
                if (processHandle != IntPtr.Zero) {
                    NativeMethods.CloseHandle(processHandle);
                }
            }
        }

        /// <summary>Locates the IconCatcher executable to start.</summary>
        /// <returns>The absolute path of IconCatcher.exe.</returns>
        private static string LocateIconCatcher() {
            // Always run the original bounded search first. It checks the adjacent
            // portable location and the conventional installation paths without
            // consulting or storing a registry value.
            string executable = LocateIconCatcherQuickly();
            if (executable != null) {
                // A conventional location is preferable to a cached result. Remove
                // the deep-search cache so that it cannot become stale.
                DeleteCachedExecutablePath();
                return executable;
            }

            // When the fast search fails, a previously verified deep-search result
            // avoids another recursive scan. Revalidate both readability and the
            // exact supported executable hash before using the cached path.
            executable = ReadCachedExecutablePath();
            if (IsSupportedExecutable(executable)) {
                return executable;
            }

            // Remove an obsolete or invalid value before performing a new scan.
            DeleteCachedExecutablePath();

            executable = FindIconCatcherDeeply(GetIconCatcherSearchRoots());
            if (executable != null) {
                WriteCachedExecutablePath(executable);
                return executable;
            }

            throw new FileNotFoundException("IconCatcher.exe was not found.");
        }

        /// <summary>Performs the original bounded search without reading the registry.</summary>
        /// <returns>The readable executable path, or <see langword="null"/> if it was not found.</returns>
        private static string LocateIconCatcherQuickly() {
            // Always prefer a portable deployment with IconCatcher next to the loader.
            string adjacent = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ExecutableFileName);
            if (IsSupportedExecutable(adjacent)) {
                return adjacent;
            }

            foreach (string searchRoot in GetIconCatcherSearchRoots()) {
                string executable = FindIconCatcherInRoot(searchRoot);
                if (executable != null) {
                    return executable;
                }
            }

            return null;
        }

        /// <summary>Builds the complete ordered list of permitted search roots.</summary>
        /// <returns>Unique Program Files and application-data directories.</returns>
        private static List<string> GetIconCatcherSearchRoots() {
            List<string> searchRoots = new List<string>();

            // ProgramW6432 exposes the native 64-bit Program Files directory to this
            // 32-bit loader. The remaining variables cover 32-bit and older systems.
            AddEnvironmentSearchRoot(searchRoots, "ProgramFiles(x86)");
            AddEnvironmentSearchRoot(searchRoots, "ProgramW6432");
            AddEnvironmentSearchRoot(searchRoots, "ProgramFiles");
            AddSpecialFolderSearchRoot(searchRoots, Environment.SpecialFolder.ProgramFiles);

            // Include roaming, local, and common application-data locations. Both
            // environment variables and special-folder APIs are used because their
            // availability differs among supported Windows versions.
            AddEnvironmentSearchRoot(searchRoots, "APPDATA");
            AddEnvironmentSearchRoot(searchRoots, "LOCALAPPDATA");
            AddEnvironmentSearchRoot(searchRoots, "ProgramData");
            AddSpecialFolderSearchRoot(searchRoots, Environment.SpecialFolder.ApplicationData);
            AddSpecialFolderSearchRoot(searchRoots, Environment.SpecialFolder.LocalApplicationData);
            AddSpecialFolderSearchRoot(searchRoots, Environment.SpecialFolder.CommonApplicationData);

            return searchRoots;
        }

        /// <summary>Adds a directory obtained from an environment variable.</summary>
        /// <param name="searchRoots">The ordered collection of search roots.</param>
        /// <param name="variableName">The environment-variable name.</param>
        private static void AddEnvironmentSearchRoot(List<string> searchRoots, string variableName) {
            try {
                AddSearchRoot(searchRoots, Environment.GetEnvironmentVariable(variableName));
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                // A denied environment-variable read must not prevent startup.
            }
        }

        /// <summary>Adds a directory obtained from a Windows special-folder value.</summary>
        /// <param name="searchRoots">The ordered collection of search roots.</param>
        /// <param name="specialFolder">The special folder to resolve.</param>
        private static void AddSpecialFolderSearchRoot(List<string> searchRoots, Environment.SpecialFolder specialFolder) {
            try {
                AddSearchRoot(searchRoots, Environment.GetFolderPath(specialFolder));
            } catch (ArgumentException exception) {
                Debug.WriteLine(exception);
                // An unavailable special folder is simply omitted.
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                // A denied special-folder lookup is simply omitted.
            }
        }

        /// <summary>Adds an existing, unique directory to the ordered search list.</summary>
        /// <param name="searchRoots">The ordered collection of directories to search.</param>
        /// <param name="path">The directory to add.</param>
        private static void AddSearchRoot(List<string> searchRoots, string path) {
            if (string.IsNullOrEmpty(path) || path.Trim().Length == 0) {
                return;
            }
            try {
                string fullPath = Path.GetFullPath(path);
                if (!Directory.Exists(fullPath) || IsDriveRoot(fullPath)) {
                    return;
                }
                foreach (string searchRoot in searchRoots) {
                    if (string.Equals(searchRoot, fullPath, StringComparison.OrdinalIgnoreCase)) {
                        return;
                    }
                }
                searchRoots.Add(fullPath);
            } catch (ArgumentException exception) {
                Debug.WriteLine(exception);
                // Ignore malformed values supplied by the environment.
            } catch (NotSupportedException exception) {
                Debug.WriteLine(exception);
                // Ignore values that do not represent filesystem paths.
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                // Ignore paths that cannot be normalized by the filesystem.
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                // Ignore roots that the current account is not allowed to inspect.
            }
        }

        /// <summary>Determines whether a path names the root of a drive or share.</summary>
        /// <param name="path">The absolute directory path to test.</param>
        /// <returns><see langword="true"/> for a filesystem root; otherwise, <see langword="false"/>.</returns>
        private static bool IsDriveRoot(string path) {
            string root = Path.GetPathRoot(path);
            if (string.IsNullOrEmpty(root)) {
                return false;
            }

            char[] separators = new char[] {
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar
            };

            return string.Equals(path.TrimEnd(separators), root.TrimEnd(separators), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Searches one Program Files or application-data directory.</summary>
        /// <param name="searchRoot">The root directory to search.</param>
        /// <returns>The readable executable path, or <see langword="null"/> if it was not found.</returns>
        private static string FindIconCatcherInRoot(string searchRoot) {
            // Check the publisher directory first, followed by installations that
            // omit the publisher name entirely.
            string executable = FindIconCatcherInParent(Path.Combine(searchRoot, PublisherDirectoryName));
            if (executable != null) {
                return executable;
            }

            return FindIconCatcherInParent(searchRoot);
        }

        /// <summary>Searches for product directories below a possible parent directory.</summary>
        /// <param name="parentDirectory">The directory that may contain Icon Catcher.</param>
        /// <returns>The readable executable path, or <see langword="null"/> if it was not found.</returns>
        private static string FindIconCatcherInParent(string parentDirectory) {
            // Test the common unversioned names directly. This can still succeed if
            // directory enumeration is denied but the complete path is accessible.
            string executable = FindIconCatcherInProductDirectory(Path.Combine(parentDirectory, ProductDirectoryName));
            if (executable != null) {
                return executable;
            }

            executable = FindIconCatcherInProductDirectory(Path.Combine(parentDirectory, "IconCatcher"));
            if (executable != null) {
                return executable;
            }

            // Also accept names such as "Icon Catcher 4.2" or
            // "IconCatcher 4.2.0.37".
            foreach (string directory in GetDirectoriesSafely(parentDirectory)) {
                string directoryName = Path.GetFileName(directory);
                if (directoryName.StartsWith(ProductDirectoryName, StringComparison.OrdinalIgnoreCase)
                        || directoryName.StartsWith("IconCatcher", StringComparison.OrdinalIgnoreCase)) {
                    executable = FindIconCatcherInProductDirectory(directory);
                    if (executable != null) {
                        return executable;
                    }
                }
            }

            return null;
        }

        /// <summary>Checks a product directory and its possible version directories.</summary>
        /// <param name="productDirectory">The possible Icon Catcher product directory.</param>
        /// <returns>The readable executable path, or <see langword="null"/> if it was not found.</returns>
        private static string FindIconCatcherInProductDirectory(string productDirectory) {
            string executable = Path.Combine(productDirectory, ExecutableFileName);
            if (IsSupportedExecutable(executable)) {
                return executable;
            }

            // A version may form a separate level, for example
            // Icon Catcher\4.2.0.37\IconCatcher.exe.
            foreach (string versionDirectory in GetDirectoriesSafely(productDirectory)) {
                executable = Path.Combine(versionDirectory, ExecutableFileName);
                if (IsSupportedExecutable(executable)) {
                    return executable;
                }
            }

            return null;
        }

        /// <summary>
        /// Recursively searches only the permitted Program Files and application-data
        /// roots for the exact supported executable.
        /// </summary>
        /// <param name="searchRoots">The non-root directories that may be traversed.</param>
        /// <returns>The verified executable path, or <see langword="null"/>.</returns>
        private static string FindIconCatcherDeeply(List<string> searchRoots) {
            Stack<string> pendingDirectories = new Stack<string>();

            // Push in reverse order so that the depth-first traversal preserves the
            // same preference order as the bounded search.
            for (int index = searchRoots.Count - 1; index >= 0; index--) {
                pendingDirectories.Push(searchRoots[index]);
            }

            while (pendingDirectories.Count != 0) {
                string directory = pendingDirectories.Pop();
                string candidate = CombinePathSafely(directory, ExecutableFileName);
                if (IsSupportedExecutable(candidate)) {
                    return candidate;
                }
                string[] childDirectories = GetDirectoriesSafely(directory);
                for (int index = childDirectories.Length - 1; index >= 0; index--) {
                    if (CanTraverseDirectory(childDirectories[index])) {
                        pendingDirectories.Push(childDirectories[index]);
                    }
                }
            }
            return null;
        }

        /// <summary>Combines two path components without propagating invalid-path errors.</summary>
        /// <param name="directory">The parent directory.</param>
        /// <param name="fileName">The file name to append.</param>
        /// <returns>The combined path, or <see langword="null"/> if it is invalid.</returns>
        private static string CombinePathSafely(string directory, string fileName) {
            try {
                return Path.Combine(directory, fileName);
            } catch (ArgumentException exception) {
                Debug.WriteLine(exception);
                return null;
            } catch (NotSupportedException exception) {
                Debug.WriteLine(exception);
                return null;
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                return null;
            }
        }

        /// <summary>Rejects reparse points and inaccessible directories.</summary>
        /// <param name="directory">The directory proposed for traversal.</param>
        /// <returns><see langword="true"/> when recursive traversal is safe.</returns>
        private static bool CanTraverseDirectory(string directory) {
            try {
                FileAttributes attributes = File.GetAttributes(directory);
                return (attributes & FileAttributes.Directory) != 0 && (attributes & FileAttributes.ReparsePoint) == 0;
            } catch (UnauthorizedAccessException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (ArgumentException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (NotSupportedException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                return false;
            }
        }

        /// <summary>Returns child directories without propagating access failures.</summary>
        /// <param name="directory">The directory whose immediate children are requested.</param>
        /// <returns>The accessible child paths, or an empty array when the directory cannot be enumerated.</returns>
        private static string[] GetDirectoriesSafely(string directory) {
            try {
                return Directory.Exists(directory) ? Directory.GetDirectories(directory) : new string[0];
            } catch (UnauthorizedAccessException exception) {
                Debug.WriteLine(exception);
                return new string[0];
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                return new string[0];
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                return new string[0];
            } catch (ArgumentException exception) {
                Debug.WriteLine(exception);
                return new string[0];
            } catch (NotSupportedException exception) {
                Debug.WriteLine(exception);
                return new string[0];
            }
        }

        /// <summary>Determines whether a file exists and can be opened for reading.</summary>
        /// <param name="path">The file to test.</param>
        /// <returns><see langword="true"/> when the file is readable; otherwise, <see langword="false"/>.</returns>
        private static bool IsReadableFile(string path) {
            try {
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                    return true;
                }
            } catch (UnauthorizedAccessException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (ArgumentException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (NotSupportedException exception) {
                Debug.WriteLine(exception);
                return false;
            }
        }

        /// <summary>Reads the executable path cached after an earlier deep search.</summary>
        /// <returns>The cached path, or <see langword="null"/> when unavailable.</returns>
        private static string ReadCachedExecutablePath() {
            try {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegistryKeyPath, false)) {
                    return key == null ? null : key.GetValue(RegistryValueName) as string;
                }
            } catch (UnauthorizedAccessException exception) {
                Debug.WriteLine(exception);
                return null;
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                return null;
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                return null;
            }
        }

        /// <summary>Stores a path found by the recursive search for the current user.</summary>
        /// <param name="executable">The verified absolute executable path.</param>
        private static void WriteCachedExecutablePath(string executable) {
            try {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RegistryKeyPath)) {
                    if (key != null) {
                        key.SetValue(RegistryValueName, executable, RegistryValueKind.String);
                    }
                }
            } catch (UnauthorizedAccessException exception) {
                Debug.WriteLine(exception);
                // Failure to cache a successful result must not prevent startup.
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                // Failure to cache a successful result must not prevent startup.
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                // Failure to cache a successful result must not prevent startup.
            }
        }

        /// <summary>Deletes the path value previously written by the deep search.</summary>
        private static void DeleteCachedExecutablePath() {
            try {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegistryKeyPath, true)) {
                    if (key != null) {
                        key.DeleteValue(RegistryValueName, false);
                    }
                }
            } catch (UnauthorizedAccessException exception) {
                Debug.WriteLine(exception);
                // Registry cleanup is optional and must never prevent startup.
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                // Registry cleanup is optional and must never prevent startup.
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                // Registry cleanup is optional and must never prevent startup.
            }
        }

        /// <summary>Validates a candidate against the analyzed executable hash.</summary>
        /// <param name="executable">The candidate executable path.</param>
        /// <returns><see langword="true"/> only for the supported readable binary.</returns>
        private static bool IsSupportedExecutable(string executable) {
            try {
                if (string.IsNullOrEmpty(executable) || !Path.IsPathRooted(executable) || !IsReadableFile(executable)) {
                    return false;
                }
            } catch (ArgumentException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (NotSupportedException exception) {
                Debug.WriteLine(exception);
                return false;
            }
            try {
                using (FileStream stream = File.OpenRead(executable)) {
                    using (SHA256 sha256 = SHA256.Create()) {
                        string actual = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "");
                        return actual.Equals(ExpectedSha256, StringComparison.OrdinalIgnoreCase);
                    }
                }
            } catch (UnauthorizedAccessException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (IOException exception) {
                Debug.WriteLine(exception);
                return false;
            } catch (System.Security.SecurityException exception) {
                Debug.WriteLine(exception);
                return false;
            }
        }

        /// <summary>Verifies the exact executable before using fixed addresses.</summary>
        /// <param name="executable">The absolute path of the executable to verify.</param>
        private static void VerifyExecutable(string executable) {
            // Hash the stream directly instead of loading the entire executable into
            // a managed byte array.
            string actual;
            using (FileStream stream = File.OpenRead(executable)) {
                using (SHA256 sha256 = SHA256.Create()) {
                    actual = BitConverter.ToString(sha256.ComputeHash(stream)).Replace("-", "");
                }
            }

            if (!actual.Equals(ExpectedSha256, StringComparison.OrdinalIgnoreCase)) {
                throw new InvalidOperationException("IconCatcher.exe is not the analyzed 4.2.0.37 binary. Its memory will not be modified.");
            }
        }

        /// <summary>
        /// Preserves the activation check result but bypasses the intermediate
        /// "Activation is Required!" dialog before the Save dialog.
        /// </summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        private static void DisableActivationDialog(IntPtr process) {
            IntPtr address = AddressToIntPtr(ActivationDialogBranch);

            // The original JE skips the dialog only when the activation check does
            // not request it. Changing JE to JMP always follows the same skip path
            // without changing BL, which is the value returned to the caller.
            byte[] expected = new byte[] { 0x74, 0x41 };
            byte[] replacement = new byte[] { 0xEB };

            byte[] original = Read(process, address, expected.Length);
            if (!ByteArraysEqual(original, expected)) {
                throw new InvalidOperationException("The expected activation dialog branch instruction was not found.");
            }
            uint oldProtection;
            if (!NativeMethods.VirtualProtectEx(process, address,
                    new UIntPtr((uint)replacement.Length), NativeMethods.PageExecuteReadWrite, out oldProtection)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try {
                UIntPtr written;
                if (!NativeMethods.WriteProcessMemory(process, address, replacement,
                        new UIntPtr((uint)replacement.Length), out written) || written.ToUInt32() != (uint)replacement.Length) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                byte[] check = Read(process, address, expected.Length);
                if (check == null || check[0] != replacement[0] || check[1] != expected[1]) {
                    throw new InvalidOperationException("The activation dialog branch patch could not be verified.");
                }
                if (!NativeMethods.FlushInstructionCache(process, address, new UIntPtr((uint)replacement.Length))) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            } finally {
                uint ignoredProtection;
                NativeMethods.VirtualProtectEx(process, address, new UIntPtr((uint)replacement.Length), oldProtection, out ignoredProtection);
            }
        }

        /// <summary>
        /// Preserves the Save Library check but prevents its result from skipping
        /// creation of the Save dialog.
        /// </summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        private static void DisableSaveLibraryEarlyExit(IntPtr process) {
            IntPtr address = AddressToIntPtr(SaveLibraryEarlyExit);

            // The original instruction is a six-byte JNE to 004C0CCA. Replacing
            // only the branch with NOP instructions preserves all side effects of
            // the check that immediately precedes it.
            byte[] expected = new byte[] {
                0x0F, 0x85, 0x59, 0x03, 0x00, 0x00
            };
            byte[] replacement = new byte[] {
                0x90, 0x90, 0x90, 0x90, 0x90, 0x90
            };

            byte[] original = Read(process, address, expected.Length);
            if (!ByteArraysEqual(original, expected)) {
                throw new InvalidOperationException("The expected Save Library branch instruction was not found.");
            }
            uint oldProtection;
            if (!NativeMethods.VirtualProtectEx(process, address, 
                    new UIntPtr((uint)replacement.Length), NativeMethods.PageExecuteReadWrite, out oldProtection)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try {
                UIntPtr written;
                if (!NativeMethods.WriteProcessMemory(process, address, replacement,
                        new UIntPtr((uint)replacement.Length), out written) || written.ToUInt32() != (uint)replacement.Length) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                byte[] check = Read(process, address, replacement.Length);
                if (!ByteArraysEqual(check, replacement)) {
                    throw new InvalidOperationException("The Save Library branch patch could not be verified.");
                }
                if (!NativeMethods.FlushInstructionCache(process, address, new UIntPtr((uint)replacement.Length))) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            } finally {
                uint ignoredProtection;
                NativeMethods.VirtualProtectEx(process, address, new UIntPtr((uint)replacement.Length),
                    oldProtection, out ignoredProtection);
            }
        }

        /// <summary>
        /// Installs a fallback that creates TICLExport if the protected code leaves
        /// its local exporter variable empty.
        /// </summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <returns>The address of the shared export state in the target process.</returns>
        private static IntPtr InstallSaveLibraryWriterFallback(IntPtr process) {
            IntPtr callSite = AddressToIntPtr(SaveLibraryWriterCallSite);
            byte[] expected = new byte[] {
                0x8B, 0x45, 0xFC,                         // mov eax,[ebp-4]
                0x8B, 0x90, 0x10, 0x05, 0x00, 0x00        // mov edx,[eax+510h]
            };
            byte[] original = Read(process, callSite, expected.Length);
            if (!ByteArraysEqual(original, expected)) {
                throw new InvalidOperationException("The expected Save Library writer instructions were not found.");
            }

            byte[] code = new byte[] {
                0x83, 0x7D, 0xF8, 0x00,                   // cmp dword ptr [ebp-8],0
                0x75, 0x0F,                               // jne short HaveWriter
                0xB2, 0x01,                               // mov dl,1
                0xA1, 0x1C, 0x6C, 0x4B, 0x00,             // mov eax,[004B6C1Ch]
                0xE8, 0x00, 0x00, 0x00, 0x00,             // call TExport.Create
                0x89, 0x45, 0xF8,                         // mov [ebp-8],eax
                0x8B, 0x45, 0xF8,                         // HaveWriter: mov eax,[ebp-8]
                0x83, 0xC0, 0x40,                         // add eax,40h
                0x8B, 0x55, 0xF4,                         // mov edx,[ebp-0Ch]
                0x8B, 0x52, 0x70,                         // mov edx,[edx+70h]
                0xE8, 0x00, 0x00, 0x00, 0x00,             // call @LStrAsg
                0xB8, 0x00, 0x00, 0x00, 0x00,             // mov eax,SaveLibraryState
                0x8B, 0x55, 0xF4,                         // mov edx,[ebp-0Ch]
                0x8B, 0x52, 0x70,                         // mov edx,[edx+70h]
                0xE8, 0x00, 0x00, 0x00, 0x00,             // call @LStrAsg
                0x8B, 0x45, 0xFC,                         // mov eax,[ebp-4]
                0x8B, 0x90, 0x10, 0x05, 0x00, 0x00,       // mov edx,[eax+510h]
                0x8B, 0x45, 0xF8,                         // mov eax,[ebp-8]
                0x8B, 0x08,                               // mov ecx,[eax]
                0xFF, 0x11,                               // call dword ptr [ecx]
                0xA2, 0x00, 0x00, 0x00, 0x00,             // mov [SaveLibraryState+8],al
                0xFF, 0x05, 0x00, 0x00, 0x00, 0x00,       // inc dword ptr [SaveLibraryState+4]
                0x84, 0xC0,                               // test al,al
                0x75, 0x05,                               // jne short Success
                0xE9, 0x00, 0x00, 0x00, 0x00,             // jmp 004C0C64h
                0xE9, 0x00, 0x00, 0x00, 0x00              // Success: jmp 004C0C83h
            };

            int stateOffset = (code.Length + 3) & ~3;
            int allocationSize = stateOffset + SaveLibraryStateSize;
            IntPtr hook = NativeMethods.VirtualAllocEx(process, IntPtr.Zero, new UIntPtr((uint)allocationSize),
                NativeMethods.MemCommit | NativeMethods.MemReserve, NativeMethods.PageExecuteReadWrite);
            if (hook == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            bool callSiteRedirected = false;
            try {
                long hookAddress = hook.ToInt64();
                if (hookAddress < 0 || hookAddress > uint.MaxValue) {
                    throw new InvalidOperationException("The Save Library hook was not allocated in the 32-bit address space.");
                }
                long stateAddress = hookAddress + stateOffset;
                WriteRelativeDisplacement(code, 14, hookAddress + 18, ExportConstructor);
                WriteRelativeDisplacement(code, 34, hookAddress + 38, LongStringAssign);
                BitConverter.GetBytes(unchecked((uint)stateAddress)).CopyTo(code, 39);
                WriteRelativeDisplacement(code, 50, hookAddress + 54, LongStringAssign);
                BitConverter.GetBytes(unchecked((uint)stateAddress) + 8).CopyTo(code, 71);
                BitConverter.GetBytes(unchecked((uint)stateAddress) + 4).CopyTo(code, 77);
                WriteRelativeDisplacement(code, 86, hookAddress + 90, SaveLibraryFailureResume);
                WriteRelativeDisplacement(code, 91, hookAddress + 95, SaveLibrarySuccessResume);
                UIntPtr hookWritten;
                if (!NativeMethods.WriteProcessMemory(process, hook, code,
                        new UIntPtr((uint)code.Length), out hookWritten) || hookWritten.ToUInt32() != (uint)code.Length) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.FlushInstructionCache(process, hook, new UIntPtr((uint)code.Length))) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                byte[] redirect = new byte[] {
                    0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90
                };
                WriteRelativeDisplacement(redirect, 1, SaveLibraryWriterCallSite + 5L, unchecked((uint)hookAddress));
                uint oldProtection;
                if (!NativeMethods.VirtualProtectEx(process, callSite,
                        new UIntPtr((uint)redirect.Length), NativeMethods.PageExecuteReadWrite, out oldProtection)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                try {
                    UIntPtr redirectWritten;
                    if (!NativeMethods.WriteProcessMemory(process, callSite, redirect,
                            new UIntPtr((uint)redirect.Length), out redirectWritten) || redirectWritten.ToUInt32() != (uint)redirect.Length) {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    callSiteRedirected = true;
                    byte[] check = Read(process, callSite, redirect.Length);
                    if (!ByteArraysEqual(check, redirect)) {
                        throw new InvalidOperationException("The Save Library fallback redirection could not be verified.");
                    }
                    if (!NativeMethods.FlushInstructionCache(process, callSite, new UIntPtr((uint)redirect.Length))) {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                } finally {
                    uint ignoredProtection;
                    NativeMethods.VirtualProtectEx(process, callSite, new UIntPtr((uint)redirect.Length), oldProtection, out ignoredProtection);
                }
                return AddressToIntPtr(unchecked((uint)stateAddress));
            } catch (Exception exception) {
                Debug.WriteLine(exception);
                if (!callSiteRedirected) {
                    NativeMethods.VirtualFreeEx(process, hook, UIntPtr.Zero, NativeMethods.MemRelease);
                }
                throw;
            }
        }

        /// <summary>Writes a 32-bit relative operand for a CALL or JMP instruction.</summary>
        /// <param name="code">The machine-code buffer to modify.</param>
        /// <param name="operandOffset">The location of the four-byte operand in the buffer.</param>
        /// <param name="nextInstruction">The process address following the instruction.</param>
        /// <param name="target">The absolute destination address.</param>
        private static void WriteRelativeDisplacement(byte[] code, int operandOffset, long nextInstruction, uint target) {
            long displacement = target - nextInstruction;
            if (displacement < int.MinValue || displacement > int.MaxValue) {
                throw new InvalidOperationException("The relative instruction target is outside its 32-bit range.");
            }
            BitConverter.GetBytes((int)displacement).CopyTo(code, operandOffset);
        }

        /// <summary>Determines whether two byte arrays contain identical data.</summary>
        /// <param name="first">The first array.</param>
        /// <param name="second">The second array.</param>
        /// <returns><see langword="true"/> if both arrays are non-null and equal; otherwise, <see langword="false"/>.</returns>
        private static bool ByteArraysEqual(byte[] first, byte[] second) {
            if (first == null || second == null || first.Length != second.Length) {
                return false;
            }
            for (int index = 0; index < first.Length; index++) {
                if (first[index] != second[index]) {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Installs the hook that releases the Save dialog after use.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <returns>The address of the installed hook.</returns>
        private static IntPtr InstallSaveHook(IntPtr process) {
            // The hook contains 32-bit machine code for the x86 target. The allocated
            // region remains valid until the target process exits.
            const int hookSize = 40;
            IntPtr hook = NativeMethods.VirtualAllocEx(process, IntPtr.Zero,
                new UIntPtr(hookSize), NativeMethods.MemCommit | NativeMethods.MemReserve, NativeMethods.PageExecuteReadWrite);
            if (hook == IntPtr.Zero) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try {
                long hookAddress64 = hook.ToInt64();
                if (hookAddress64 < 0 || hookAddress64 > uint.MaxValue) {
                    throw new InvalidOperationException("The hook was not allocated in the 32-bit IconCatcher address space.");
                }

                byte[] code = new byte[] {
                    0x53,                                           // push ebx                 ; preserve EBX
                    0x8B, 0xD8,                                     // mov ebx,eax              ; EBX = main form
                    0xE8, 0x00, 0x00, 0x00, 0x00,                   // call actSaveIconExecute  ; patched below
                    0x8B, 0x83, 0x24, 0x05, 0x00, 0x00,             // mov eax,[ebx+524h]       ; TAgSaveDialog
                    0x85, 0xC0,                                     // test eax,eax
                    0x74, 0x14,                                     // je short Return          ; no dialog was created
                    0xC7, 0x83, 0x24, 0x05, 0x00, 0x00,             // mov dword ptr [ebx+524h],
                    0x00, 0x00, 0x00, 0x00,                         // 0                        ; clear before destruction
                    0x8B, 0x08,                                     // mov ecx,[eax]            ; object VMT
                    0xBA, 0x01, 0x00, 0x00, 0x00,                   // mov edx,1                ; destroy the instance
                    0xFF, 0x51, 0xFC,                               // call dword ptr [ecx-4]   ; virtual destructor
                    0x5B,                                           // pop ebx
                    0xC3                                            // ret
                };

                // A CALL operand is relative to the address of the following
                // instruction, which is hookAddress + 8 in this hook.
                long displacement64 = ExecuteHandler - (hookAddress64 + 8);
                if (displacement64 < int.MinValue || displacement64 > int.MaxValue) {
                    throw new InvalidOperationException("The original Save handler is outside the range of a relative CALL instruction.");
                }

                BitConverter.GetBytes((int)displacement64).CopyTo(code, 4);

                UIntPtr written;
                if (!NativeMethods.WriteProcessMemory(process, hook, code,
                        new UIntPtr((uint)code.Length), out written) || written.ToUInt32() != (uint)code.Length) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Prevent the processor from executing stale cached instructions.
                if (!NativeMethods.FlushInstructionCache(process, hook, new UIntPtr((uint)code.Length))) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return hook;
            } catch (Exception exception) {
                Debug.WriteLine(exception);
                NativeMethods.VirtualFreeEx(process, hook, UIntPtr.Zero, NativeMethods.MemRelease);
                throw;
            }
        }

        /// <summary>Redirects the action and both menu handlers to the installed hook.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <param name="action">The address of the actSaveIcon object.</param>
        /// <param name="menuCallbacks">The OnClick.Code addresses for the main and context menu items.</param>
        /// <param name="hook">The address of the installed machine-code hook.</param>
        private static void RedirectToHook(IntPtr process, IntPtr action, IList<IntPtr> menuCallbacks, IntPtr hook) {
            long hookAddress64 = hook.ToInt64();
            if (hookAddress64 < 0 || hookAddress64 > uint.MaxValue) {
                throw new InvalidOperationException("The hook address does not fit in the 32-bit TMethod.Code field.");
            }

            uint hookAddress = (uint)hookAddress64;

            // Redirect the central TAction first.
            WriteHandler(process, AddOffset(action, OnExecuteOffset), hookAddress);

            // Each menu item has a direct OnClick handler in addition to its
            // ActionLink. The direct handler takes precedence and must also be
            // redirected.
            foreach (IntPtr callback in menuCallbacks) {
                WriteHandler(process, callback, hookAddress);
            }
        }

        /// <summary>Writes the hook address to a TMethod.Code field.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <param name="address">The address of the TMethod.Code field.</param>
        /// <param name="handler">The 32-bit handler address to write.</param>
        private static void WriteHandler(IntPtr process, IntPtr address, uint handler) {
            // Modify only Code. The following four-byte Data field containing Self
            // remains unchanged.
            byte[] handlerBytes = BitConverter.GetBytes(handler);

            UIntPtr written;
            if (!NativeMethods.WriteProcessMemory(process, address, handlerBytes,
                    new UIntPtr((uint)handlerBytes.Length), out written) || written.ToUInt32() != (uint)handlerBytes.Length) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Read the field back and verify the exact handler address.
            byte[] check = Read(process, address, handlerBytes.Length);
            if (check == null || BitConverter.ToUInt32(check, 0) != handler) {
                throw new InvalidOperationException("The Save Selected redirection could not be verified.");
            }
        }

        /// <summary>Searches the address space for the actSaveIcon object.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <returns>The actSaveIcon address, or <see cref="IntPtr.Zero"/> if no validated object is found.</returns>
        private static IntPtr FindAction(IntPtr process) {
            // Both processes are x86, so addresses can be calculated as unsigned
            // 32-bit values. Convert them to IntPtr only at the Win32 boundary.
            uint address = 0;
            int infoSize = Marshal.SizeOf(typeof(MemoryBasicInformation));

            // The x86 target uses the conventional user address space below 2 GB.
            while (address < 0x80000000u) {
                // VirtualQueryEx describes one contiguous region with uniform attributes.
                MemoryBasicInformation info;
                if (NativeMethods.VirtualQueryEx(process, AddressToIntPtr(address), out info, new UIntPtr((uint)infoSize)) == UIntPtr.Zero) {
                    break;
                }

                uint start = unchecked((uint)info.BaseAddress.ToInt32());
                uint size = info.RegionSize.ToUInt32();

                // Delphi component instances reside in committed private memory. Skip
                // reserved regions, mapped files, images, guard pages, and inaccessible
                // pages.
                bool readable = info.State == NativeMethods.MemCommit
                    && info.Type == NativeMethods.MemPrivate
                    && (info.Protect & NativeMethods.PageGuard) == 0
                    && (info.Protect & 0xFF) != NativeMethods.PageNoAccess;

                if (readable) {
                    IntPtr result = SearchRegion(process, start, size);
                    if (result != IntPtr.Zero) {
                        return result;
                    }
                }

                // Advance to the first address after the current region.
                uint next = unchecked(start + size);

                // Stop on overflow or if the query fails to advance.
                if (next <= address) {
                    break;
                }

                address = next;
            }

            return IntPtr.Zero;
        }

        /// <summary>Locates the direct OnClick handlers for both "Save Selected..." menu items.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <param name="form">The 32-bit address of the main form.</param>
        /// <returns>The addresses of the two OnClick.Code fields.</returns>
        private static List<IntPtr> FindMenuCallbacks(IntPtr process, uint form) {
            List<IntPtr> result = new List<IntPtr>();
            List<uint> seen = new List<uint>();
            uint address = 0;
            int infoSize = Marshal.SizeOf(typeof(MemoryBasicInformation));
            while (address < 0x80000000u) {
                MemoryBasicInformation info;
                if (NativeMethods.VirtualQueryEx(process, AddressToIntPtr(address), out info,
                        new UIntPtr((uint)infoSize)) == UIntPtr.Zero) {
                    break;
                }
                uint start = unchecked((uint)info.BaseAddress.ToInt32());
                uint size = info.RegionSize.ToUInt32();
                bool readable = info.State == NativeMethods.MemCommit
                    && info.Type == NativeMethods.MemPrivate
                    && (info.Protect & NativeMethods.PageGuard) == 0
                    && (info.Protect & 0xFF) != NativeMethods.PageNoAccess;
                if (readable) {
                    SearchMenuCallbacksInRegion(process, start, size, form, result, seen);
                }
                uint next = unchecked(start + size);
                if (next <= address) {
                    break;
                }
                address = next;
            }
            return result;
        }

        /// <summary>Searches one private memory region for direct Save handlers.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <param name="start">The first address in the region.</param>
        /// <param name="size">The size of the region, in bytes.</param>
        /// <param name="form">The 32-bit address of the main form.</param>
        /// <param name="result">The collection that receives matching handler-field addresses.</param>
        /// <param name="seen">The collection used to reject duplicate addresses.</param>
        private static void SearchMenuCallbacksInRegion(IntPtr process, uint start, uint size, uint form, List<IntPtr> result, List<uint> seen) {
            const int chunkSize = 1024 * 1024;
            byte[] prefix = new byte[0];
            for (uint offset = 0; offset < size; offset += chunkSize) {
                int count = (int)Math.Min((uint)chunkSize, size - offset);
                byte[] current = Read(process, AddressToIntPtr(unchecked(start + offset)), count);
                if (current == null) {
                    prefix = new byte[0];
                    continue;
                }
                byte[] data = new byte[prefix.Length + current.Length];
                prefix.CopyTo(data, 0);
                current.CopyTo(data, prefix.Length);
                uint dataStart = unchecked(start + offset - (uint)prefix.Length);
                for (int index = 0; index <= data.Length - 8; index++) {
                    if (BitConverter.ToUInt32(data, index) != ExecuteHandler || BitConverter.ToUInt32(data, index + 4) != form) {
                        continue;
                    }
                    uint callback = unchecked(dataStart + (uint)index);
                    if (callback < MenuClickOffset) {
                        continue;
                    }
                    uint menuItem = callback - MenuClickOffset;
                    byte[] vmt = Read(process, AddressToIntPtr(menuItem), sizeof(uint));
                    if (vmt != null && BitConverter.ToUInt32(vmt, 0) == MenuItemVmt && !seen.Contains(callback)) {
                        seen.Add(callback);
                        result.Add(AddressToIntPtr(callback));
                    }
                }
                int keep = Math.Min(7, data.Length);
                prefix = new byte[keep];
                Array.Copy(data, data.Length - keep, prefix, 0, keep);
            }
        }

        /// <summary>Searches one private memory region for the action-event signature.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <param name="start">The first address in the region.</param>
        /// <param name="size">The size of the region, in bytes.</param>
        /// <returns>The validated actSaveIcon address, or <see cref="IntPtr.Zero"/>.</returns>
        private static IntPtr SearchRegion(IntPtr process, uint start, uint size) {
            // One-megabyte chunks limit the size of temporary arrays.
            const int chunkSize = 1024 * 1024;

            // The signature is 16 bytes long. Prefix each chunk with the last 15
            // bytes of the preceding chunk so that a boundary-spanning signature is
            // not missed.
            byte[] prefix = new byte[0];

            for (uint offset = 0; offset < size; offset += chunkSize) {
                int count = (int)Math.Min((uint)chunkSize, size - offset);
                byte[] current = Read(process, AddressToIntPtr(unchecked(start + offset)), count);

                // Memory attributes can change while scanning. Skip an unreadable
                // chunk and continue with the remainder of the address space.
                if (current == null) {
                    prefix = new byte[0];
                    continue;
                }

                byte[] data = new byte[prefix.Length + current.Length];
                prefix.CopyTo(data, 0);
                current.CopyTo(data, prefix.Length);

                // Calculate the process address represented by data[0].
                uint dataStart = unchecked(start + offset - (uint)prefix.Length);

                // Start at 0x30 because the object address is calculated by
                // subtracting that offset. This prevents unsigned underflow.
                for (int index = OnExecuteOffset; index <= data.Length - 16; index++) {
                    // Four little-endian DWORD values represent two adjacent TMethod
                    // structures.
                    uint executeCode = BitConverter.ToUInt32(data, index);
                    uint executeSelf = BitConverter.ToUInt32(data, index + 4);
                    uint updateCode = BitConverter.ToUInt32(data, index + 8);
                    uint updateSelf = BitConverter.ToUInt32(data, index + 12);

                    // Both events are methods of the same main form, so their fixed
                    // Code addresses and their Self pointers must match.
                    if (executeCode != ExecuteHandler || updateCode != UpdateHandler || executeSelf != updateSelf) {
                        continue;
                    }

                    // The matching index identifies action + OnExecuteOffset.
                    uint action = unchecked(dataStart + (uint)index - (uint)OnExecuteOffset);

                    // The 16-byte signature alone is not sufficient. Validate the
                    // candidate through its VMT and the main form's back-reference.
                    if (ValidateAction(process, action, executeSelf)) {
                        return AddressToIntPtr(action);
                    }
                }
                int keep = Math.Min(15, data.Length);
                prefix = new byte[keep];
                Array.Copy(data, data.Length - keep, prefix, 0, keep);
            }
            return IntPtr.Zero;
        }

        /// <summary>Determines whether a candidate is the actSaveIcon object for the specified form.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <param name="action">The 32-bit candidate object address.</param>
        /// <param name="form">The 32-bit main-form address.</param>
        /// <returns><see langword="true"/> if the candidate is valid; otherwise, <see langword="false"/>.</returns>
        private static bool ValidateAction(IntPtr process, uint action, uint form) {
            // The first DWORD of a Delphi object points to its virtual method table.
            byte[] vmt = Read(process, AddressToIntPtr(action), 4);

            // The form field at offset 0x46C must point back to the same object.
            byte[] field = Read(process, AddressToIntPtr(unchecked(form + (uint)ActionFieldOffset)), 4);

            return vmt != null && field != null && BitConverter.ToUInt32(vmt, 0) == ActionVmt && BitConverter.ToUInt32(field, 0) == action;
        }

        /// <summary>
        /// Monitors completed Save Library exports and converts them to PE DLLs.
        /// </summary>
        /// <param name="process">The IconCatcher process whose lifetime is monitored.</param>
        /// <param name="processHandle">A handle used to read the shared export state.</param>
        /// <param name="saveLibraryState">The shared Save Library state address.</param>
        private static void WatchSaveLibraryExports(Process process, IntPtr processHandle, IntPtr saveLibraryState) {
            uint lastExportSequence = 0;
            while (!process.HasExited) {
                ConvertCompletedSaveLibraryExport(processHandle, saveLibraryState, ref lastExportSequence);

                // A 10-millisecond interval observes even rapid consecutive exports
                // without continuously occupying a processor core.
                Thread.Sleep(10);
            }
        }

        /// <summary>Converts a newly completed successful ICL export to a PE DLL.</summary>
        /// <param name="process">A handle used to read the IconCatcher process.</param>
        /// <param name="stateAddress">The shared Save Library state address.</param>
        /// <param name="lastSequence">The last sequence number processed by the loader.</param>
        private static void ConvertCompletedSaveLibraryExport(IntPtr process, IntPtr stateAddress, ref uint lastSequence) {
            byte[] state = Read(process, stateAddress, SaveLibraryStateSize);
            if (state == null) {
                return;
            }
            uint sequence = BitConverter.ToUInt32(state, 4);
            if (sequence == lastSequence) {
                return;
            }
            lastSequence = sequence;
            if (state[8] == 0) {
                return;
            }
            try {
                string iclPath = ReadDelphiAnsiString(process, BitConverter.ToUInt32(state, 0));
                NeIconLibraryConverter.ConvertToPeDll(iclPath);
            } catch (Exception exception) {
                Debug.WriteLine(exception);
                NativeMethods.MessageBox(IntPtr.Zero, exception.Message, "IconCatcherLoader - ICL to PE conversion", 0x10);
            }
        }

        /// <summary>Reads a Delphi AnsiString from the IconCatcher address space.</summary>
        /// <param name="process">A handle used to read the IconCatcher process.</param>
        /// <param name="stringAddress">The address of the first AnsiString character.</param>
        /// <returns>The converted Unicode string.</returns>
        private static string ReadDelphiAnsiString(IntPtr process, uint stringAddress) {
            if (stringAddress < sizeof(int)) {
                throw new InvalidOperationException("IconCatcher did not provide the saved ICL path.");
            }
            byte[] lengthData = Read(process, AddressToIntPtr(stringAddress - sizeof(int)), sizeof(int));
            if (lengthData == null) {
                throw new InvalidOperationException("The saved ICL path length could not be read.");
            }
            int length = BitConverter.ToInt32(lengthData, 0);
            if (length <= 0 || length > short.MaxValue) {
                throw new InvalidOperationException("IconCatcher provided an invalid saved ICL path.");
            }
            byte[] bytes = Read(process, AddressToIntPtr(stringAddress), length);
            if (bytes == null) {
                throw new InvalidOperationException("The saved ICL path could not be read.");
            }
            int characterCount = NativeMethods.MultiByteToWideChar(0, 0, bytes, bytes.Length, null, 0);
            if (characterCount == 0) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            char[] characters = new char[characterCount];
            if (NativeMethods.MultiByteToWideChar(0, 0, bytes, bytes.Length, characters, characters.Length) != characterCount) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new string(characters);
        }

        /// <summary>Reads an exact number of bytes from the target process.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <param name="address">The address from which to read.</param>
        /// <param name="count">The required number of bytes.</param>
        /// <returns>The requested bytes, or <see langword="null"/> if the read fails or is incomplete.</returns>
        private static byte[] Read(IntPtr process, IntPtr address, int count) {
            byte[] buffer = new byte[count];
            UIntPtr read;
            return NativeMethods.ReadProcessMemory(process, address, buffer,
                new UIntPtr((uint)count), out read) && read.ToUInt32() == (uint)count ? buffer : null;
        }

        /// <summary>Converts a 32-bit process address to IntPtr without changing its bits.</summary>
        /// <param name="address">The unsigned 32-bit process address.</param>
        /// <returns>An IntPtr containing the same 32 bits.</returns>
        private static IntPtr AddressToIntPtr(uint address) {
            return new IntPtr(unchecked((int)address));
        }

        /// <summary>Adds a byte offset to a 32-bit process address.</summary>
        /// <param name="address">The original process address.</param>
        /// <param name="offset">The signed byte offset to add.</param>
        /// <returns>The resulting 32-bit process address.</returns>
        private static IntPtr AddOffset(IntPtr address, int offset) {
            return new IntPtr(unchecked(address.ToInt32() + offset));
        }
    }
}
