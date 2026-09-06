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
 * Version 1.0.0.0
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

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
    /// After installing the hook, the loader continues running. When IconCatcher
    /// displays the intermediate modal dialog that contains the "Continue >>"
    /// button, the loader posts WM_CLOSE to that dialog. This is equivalent to
    /// closing the intermediate dialog by using its title-bar close button; it does
    /// not activate Continue and does not close the subsequent Save dialog.
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

        // SHA-256 of the analyzed executable. This prevents fixed addresses from
        // being used with another version that may contain unrelated data or code.
        private const string ExpectedSha256 = "B0583B666869A1446B4F656AE74351E8E9245BA5D4333D5481BA2959338CE50E";

        // Keep the native callback delegates alive for the entire loader lifetime.
        private static readonly NativeMethods.EnumWindowCallback PreSaveDialogCallback =
            new NativeMethods.EnumWindowCallback(InspectPreSaveDialog);

        private static readonly NativeMethods.EnumWindowCallback ContinueButtonCallback =
            new NativeMethods.EnumWindowCallback(InspectContinueButton);

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
                        byte[] formData = Read(processHandle, IntPtr.Add(action, OnExecuteOffset + sizeof(uint)), sizeof(uint));
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

                        IntPtr hook = InstallSaveHook(processHandle);
                        RedirectToHook(processHandle, action, menuCallbacks, hook);

                        // Keep the loader alive after installing the hook. This thread
                        // monitors top-level target windows and closes the intermediate
                        // dialog when it finds its "Continue >>" TButton. The method
                        // returns only after IconCatcher exits.
                        WatchAndClosePreSaveDialogs(process);
                        return;
                    }

                    // A short delay limits CPU usage while polling.
                    Thread.Sleep(10);
                }

                throw new TimeoutException("The actSaveIcon object was not found before the timeout expired.");
            } catch (Exception exception) {
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
            // Always prefer a portable deployment with IconCatcher next to the loader.
            string adjacent = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ExecutableFileName);
            if (IsReadableFile(adjacent)) {
                return adjacent;
            }

            // Obtain installation roots from Windows instead of assuming a drive or
            // a localized Program Files directory name. ProgramW6432 is required
            // because this loader is a 32-bit process on 64-bit Windows.
            List<string> searchRoots = new List<string>();
            AddSearchRoot(searchRoots, Environment.GetEnvironmentVariable("ProgramFiles(x86)"));
            AddSearchRoot(searchRoots, Environment.GetEnvironmentVariable("ProgramW6432"));
            AddSearchRoot(searchRoots, Environment.GetEnvironmentVariable("ProgramFiles"));

            // Some portable or per-user installations may be stored below either
            // the roaming or local application-data directory.
            AddSearchRoot(searchRoots, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            AddSearchRoot(searchRoots, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));

            foreach (string searchRoot in searchRoots) {
                string executable = FindIconCatcherInRoot(searchRoot);
                if (executable != null) {
                    return executable;
                }
            }

            throw new FileNotFoundException("IconCatcher.exe was not found.");
        }

        /// <summary>Adds an existing, unique directory to the ordered search list.</summary>
        /// <param name="searchRoots">The ordered collection of directories to search.</param>
        /// <param name="path">The directory to add.</param>
        private static void AddSearchRoot(List<string> searchRoots, string path) {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) {
                return;
            }

            foreach (string searchRoot in searchRoots) {
                if (string.Equals(searchRoot, path, StringComparison.OrdinalIgnoreCase)) {
                    return;
                }
            }

            searchRoots.Add(path);
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
            if (IsReadableFile(executable)) {
                return executable;
            }

            // A version may form a separate level, for example
            // Icon Catcher\4.2.0.37\IconCatcher.exe.
            foreach (string versionDirectory in GetDirectoriesSafely(productDirectory)) {
                executable = Path.Combine(versionDirectory, ExecutableFileName);
                if (IsReadableFile(executable)) {
                    return executable;
                }
            }

            return null;
        }

        /// <summary>Returns child directories without propagating access failures.</summary>
        /// <param name="directory">The directory whose immediate children are requested.</param>
        /// <returns>The accessible child paths, or an empty array when the directory cannot be enumerated.</returns>
        private static string[] GetDirectoriesSafely(string directory) {
            try {
                return Directory.Exists(directory) ? Directory.GetDirectories(directory) : new string[0];
            } catch (UnauthorizedAccessException) {
                return new string[0];
            } catch (IOException) {
                return new string[0];
            } catch (System.Security.SecurityException) {
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
            } catch (UnauthorizedAccessException) {
                return false;
            } catch (IOException) {
                return false;
            } catch (System.Security.SecurityException) {
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

        /// <summary>Installs the hook that releases the Save dialog after use.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <returns>The address of the installed hook.</returns>
        private static IntPtr InstallSaveHook(IntPtr process) {
            // The hook contains 32-bit machine code for the x86 target. The allocated
            // region remains valid until the target process exits.
            const int hookSize = 40;
            IntPtr hook = NativeMethods.VirtualAllocEx(process, IntPtr.Zero, new UIntPtr(hookSize),
                NativeMethods.MemCommit | NativeMethods.MemReserve, NativeMethods.PageExecuteReadWrite);
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
                if (!NativeMethods.WriteProcessMemory(process, hook, code, new UIntPtr((uint)code.Length), out written)
                        || written.ToUInt32() != (uint)code.Length) {

                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // Prevent the processor from executing stale cached instructions.
                if (!NativeMethods.FlushInstructionCache(process, hook, new UIntPtr((uint)code.Length))) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return hook;
            } catch {
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
            WriteHandler(process, IntPtr.Add(action, OnExecuteOffset), hookAddress);

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
            if (!NativeMethods.WriteProcessMemory(process, address, handlerBytes, new UIntPtr((uint)handlerBytes.Length), out written)
                    || written.ToUInt32() != (uint)handlerBytes.Length) {

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
            int infoSize = Marshal.SizeOf(typeof(NativeMethods.MemoryBasicInformation));

            // The x86 target uses the conventional user address space below 2 GB.
            while (address < 0x80000000u) {
                // VirtualQueryEx describes one contiguous region with uniform attributes.
                NativeMethods.MemoryBasicInformation info;
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
            HashSet<uint> seen = new HashSet<uint>();
            uint address = 0;
            int infoSize = Marshal.SizeOf(typeof(NativeMethods.MemoryBasicInformation));

            while (address < 0x80000000u) {
                NativeMethods.MemoryBasicInformation info;
                if (NativeMethods.VirtualQueryEx(process, AddressToIntPtr(address), out info, new UIntPtr((uint)infoSize)) == UIntPtr.Zero) {
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
        /// <param name="seen">The set used to reject duplicate addresses.</param>
        private static void SearchMenuCallbacksInRegion(IntPtr process, uint start, uint size, uint form, List<IntPtr> result, HashSet<uint> seen) {
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
                    if (vmt != null && BitConverter.ToUInt32(vmt, 0) == MenuItemVmt && seen.Add(callback)) {
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
        /// Monitors IconCatcher for the intermediate modal dialog and closes it by
        /// posting WM_CLOSE.
        /// </summary>
        /// <param name="process">The IconCatcher process to monitor.</param>
        private static void WatchAndClosePreSaveDialogs(Process process) {
            // Post WM_CLOSE only once to each observed window. Reset the stored
            // handle after the window disappears so that another Save Selected
            // operation can create a new dialog, possibly with a reused HWND value.
            IntPtr lastClosedDialog = IntPtr.Zero;

            while (!process.HasExited) {
                IntPtr dialog = FindPreSaveDialog(process.Id);

                if (dialog == IntPtr.Zero) {
                    lastClosedDialog = IntPtr.Zero;
                } else if (dialog != lastClosedDialog) {
                    // PostMessage queues WM_CLOSE on the IconCatcher GUI thread. The
                    // loader therefore cannot block inside the target dialog as it
                    // could with a synchronous SendMessage call.
                    if (NativeMethods.PostMessage(dialog, NativeMethods.WmClose, IntPtr.Zero, IntPtr.Zero)) {
                        lastClosedDialog = dialog;
                    }
                }

                // A 10-millisecond interval provides prompt response without
                // continuously occupying a processor core with EnumWindows calls.
                Thread.Sleep(10);
            }
        }

        /// <summary>
        /// Locates a visible owned IconCatcher window that contains the designated
        /// Continue button.
        /// </summary>
        /// <param name="processId">The identifier of the IconCatcher process.</param>
        /// <returns>The dialog handle, or <see cref="IntPtr.Zero"/> if no matching dialog is visible.</returns>
        private static IntPtr FindPreSaveDialog(int processId) {
            SearchState searchState = new SearchState();
            searchState.ProcessId = processId;
            GCHandle searchStateHandle = GCHandle.Alloc(searchState);

            try {
                NativeMethods.EnumWindows(PreSaveDialogCallback, GCHandle.ToIntPtr(searchStateHandle));
                return searchState.Window;
            } finally {
                searchStateHandle.Free();
            }
        }

        /// <summary>Examines an enumerated top-level window for the pre-save dialog.</summary>
        /// <param name="window">The handle of the top-level window being examined.</param>
        /// <param name="parameter">A GCHandle pointer for the current search state.</param>
        /// <returns><see langword="true"/> to continue enumeration; otherwise, <see langword="false"/>.</returns>
        private static bool InspectPreSaveDialog(IntPtr window, IntPtr parameter) {
            GCHandle searchStateHandle = GCHandle.FromIntPtr(parameter);
            SearchState searchState = (SearchState)searchStateHandle.Target;

            uint windowProcessId;
            NativeMethods.GetWindowThreadProcessId(window, out windowProcessId);

            // Ignore windows owned by other processes and invisible windows.
            if (windowProcessId != (uint)searchState.ProcessId || !NativeMethods.IsWindowVisible(window)) {
                return true;
            }

            // The main window has no owner. Requiring one prevents a similarly
            // named control on the main form from being mistaken for the modal
            // dialog.
            IntPtr owner = NativeMethods.GetWindow(window, NativeMethods.GwOwner);
            if (owner == IntPtr.Zero) {
                return true;
            }

            uint ownerProcessId;
            NativeMethods.GetWindowThreadProcessId(owner, out ownerProcessId);
            if (ownerProcessId != (uint)searchState.ProcessId) {
                return true;
            }

            if (ContainsContinueButton(window)) {
                searchState.Window = window;

                // Stop enumeration after finding an unambiguous match.
                return false;
            }

            return true;
        }

        /// <summary>
        /// Determines whether a window contains a Delphi TButton captioned
        /// "Continue >>". EnumChildWindows includes nested descendants.
        /// </summary>
        /// <param name="dialog">The handle of the candidate dialog.</param>
        /// <returns><see langword="true"/> if the button is present; otherwise, <see langword="false"/>.</returns>
        private static bool ContainsContinueButton(IntPtr dialog) {
            SearchState searchState = new SearchState();
            GCHandle searchStateHandle = GCHandle.Alloc(searchState);

            try {
                NativeMethods.EnumChildWindows(dialog, ContinueButtonCallback, GCHandle.ToIntPtr(searchStateHandle));
                return searchState.Found;
            } finally {
                searchStateHandle.Free();
            }
        }

        /// <summary>Examines an enumerated child window for the Continue button.</summary>
        /// <param name="child">The handle of the child window being examined.</param>
        /// <param name="parameter">A GCHandle pointer for the current search state.</param>
        /// <returns><see langword="true"/> to continue enumeration; otherwise, <see langword="false"/>.</returns>
        private static bool InspectContinueButton(IntPtr child, IntPtr parameter) {
            StringBuilder className = new StringBuilder(64);
            if (NativeMethods.GetClassName(child, className, className.Capacity) == 0
                    || !className.ToString().Equals("TButton", StringComparison.Ordinal)) {

                return true;
            }

            StringBuilder caption = new StringBuilder(256);
            NativeMethods.GetWindowText(child, caption, caption.Capacity);

            // An ampersand in a Win32 caption marks a keyboard accelerator.
            // Removing it accepts both "Continue >>" and "&Continue >>".
            if (caption.ToString().Replace("&", "").Equals("Continue >>", StringComparison.Ordinal)) {
                GCHandle searchStateHandle = GCHandle.FromIntPtr(parameter);
                SearchState searchState = (SearchState)searchStateHandle.Target;
                searchState.Found = true;
                return false;
            }

            return true;
        }

        /// <summary>Reads an exact number of bytes from the target process.</summary>
        /// <param name="process">A handle to the IconCatcher process.</param>
        /// <param name="address">The address from which to read.</param>
        /// <param name="count">The required number of bytes.</param>
        /// <returns>The requested bytes, or <see langword="null"/> if the read fails or is incomplete.</returns>
        private static byte[] Read(IntPtr process, IntPtr address, int count) {
            byte[] buffer = new byte[count];
            UIntPtr read;
            return NativeMethods.ReadProcessMemory(process, address, buffer, new UIntPtr((uint)count), out read)
                && read.ToUInt32() == (uint)count ? buffer : null;
        }

        /// <summary>Converts a 32-bit process address to IntPtr without changing its bits.</summary>
        /// <param name="address">The unsigned 32-bit process address.</param>
        /// <returns>An IntPtr containing the same 32 bits.</returns>
        private static IntPtr AddressToIntPtr(uint address) {
            return new IntPtr(unchecked((int)address));
        }
    }
}
