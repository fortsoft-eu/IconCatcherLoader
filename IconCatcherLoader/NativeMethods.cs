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
using System.Runtime.InteropServices;
using System.Text;

namespace IconCatcherLoader {

    /// <summary>
    /// Contains the Win32 constants, data structures, delegates, and platform
    /// invocation declarations used by the loader.
    /// </summary>
    internal static class NativeMethods {
        /// <summary>Enables operations on a process address space.</summary>
        internal const uint ProcessVmOperation = 0x0008;

        /// <summary>Enables reading from a process address space.</summary>
        internal const uint ProcessVmRead = 0x0010;

        /// <summary>Enables writing to a process address space.</summary>
        internal const uint ProcessVmWrite = 0x0020;

        /// <summary>Enables retrieval of process information.</summary>
        internal const uint ProcessQueryInformation = 0x0400;

        /// <summary>Indicates that physical storage is committed for a memory region.</summary>
        internal const uint MemCommit = 0x1000;

        /// <summary>Indicates that a memory region is private to the process.</summary>
        internal const uint MemPrivate = 0x20000;

        /// <summary>Reserves a range of the process virtual address space.</summary>
        internal const uint MemReserve = 0x2000;

        /// <summary>Releases an entire region allocated by VirtualAllocEx.</summary>
        internal const uint MemRelease = 0x8000;

        /// <summary>Disables all access to a memory page.</summary>
        internal const uint PageNoAccess = 0x01;

        /// <summary>Marks a memory page as a guard page.</summary>
        internal const uint PageGuard = 0x100;

        /// <summary>Enables reading, writing, and execution for a memory page.</summary>
        internal const uint PageExecuteReadWrite = 0x40;

        /// <summary>Requests that a window close.</summary>
        internal const uint WmClose = 0x0010;

        /// <summary>Requests the owner window from GetWindow.</summary>
        internal const uint GwOwner = 4;

        /// <summary>Defines a callback that receives enumerated windows.</summary>
        /// <param name="window">The handle of the window being enumerated.</param>
        /// <param name="parameter">The application-defined callback value.</param>
        /// <returns><see langword="true"/> to continue enumeration; otherwise, <see langword="false"/>.</returns>
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool EnumWindowCallback(IntPtr window, IntPtr parameter);

        /// <summary>
        /// Describes a contiguous range of pages in the virtual address space of a
        /// 32-bit process.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct MemoryBasicInformation {
            /// <summary>Gets or sets the base address of the region.</summary>
            internal IntPtr BaseAddress;

            /// <summary>Gets or sets the base address of the original allocation.</summary>
            internal IntPtr AllocationBase;

            /// <summary>Gets or sets the protection used when the region was allocated.</summary>
            internal uint AllocationProtect;

            /// <summary>Gets or sets the size of the region, in bytes.</summary>
            internal UIntPtr RegionSize;

            /// <summary>Gets or sets the state of the pages in the region.</summary>
            internal uint State;

            /// <summary>Gets or sets the current access protection.</summary>
            internal uint Protect;

            /// <summary>Gets or sets the type of pages in the region.</summary>
            internal uint Type;
        }

        /// <summary>Opens an existing local process.</summary>
        /// <param name="desiredAccess">The access rights requested for the process handle.</param>
        /// <param name="inheritHandle">
        /// <see langword="true"/> to allow child processes to inherit the returned handle;
        /// otherwise, <see langword="false"/>.
        /// </param>
        /// <param name="processId">The identifier of the process to open.</param>
        /// <returns>A handle to the process, or <see cref="IntPtr.Zero"/> if the operation fails.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

        /// <summary>Reads memory from another process.</summary>
        /// <param name="process">A handle to the process whose memory is read.</param>
        /// <param name="baseAddress">The address at which reading begins.</param>
        /// <param name="buffer">The buffer that receives the copied bytes.</param>
        /// <param name="size">The number of bytes to read.</param>
        /// <param name="bytesRead">Receives the number of bytes copied.</param>
        /// <returns><see langword="true"/> if the operation succeeds; otherwise, <see langword="false"/>.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ReadProcessMemory(IntPtr process, IntPtr baseAddress, [Out] byte[] buffer, UIntPtr size, out UIntPtr bytesRead);

        /// <summary>Writes memory to another process.</summary>
        /// <param name="process">A handle to the process whose memory is modified.</param>
        /// <param name="baseAddress">The address at which writing begins.</param>
        /// <param name="buffer">The buffer containing the bytes to write.</param>
        /// <param name="size">The number of bytes to write.</param>
        /// <param name="bytesWritten">Receives the number of bytes copied.</param>
        /// <returns><see langword="true"/> if the operation succeeds; otherwise, <see langword="false"/>.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WriteProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, UIntPtr size, out UIntPtr bytesWritten);

        /// <summary>Allocates memory in another process.</summary>
        /// <param name="process">A handle to the process in which memory is allocated.</param>
        /// <param name="address">The preferred base address, or <see cref="IntPtr.Zero"/> to let the system choose one.</param>
        /// <param name="size">The size of the allocation, in bytes.</param>
        /// <param name="allocationType">The requested allocation type.</param>
        /// <param name="protection">The requested memory protection.</param>
        /// <returns>The base address of the allocated region, or <see cref="IntPtr.Zero"/> if the operation fails.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, UIntPtr size, uint allocationType, uint protection);

        /// <summary>Releases memory allocated in another process.</summary>
        /// <param name="process">A handle to the process that owns the allocation.</param>
        /// <param name="address">The base address of the allocation.</param>
        /// <param name="size">The size to release; this must be zero when <paramref name="freeType"/> is MEM_RELEASE.</param>
        /// <param name="freeType">The requested free operation.</param>
        /// <returns><see langword="true"/> if the operation succeeds; otherwise, <see langword="false"/>.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool VirtualFreeEx(IntPtr process, IntPtr address, UIntPtr size, uint freeType);

        /// <summary>Flushes the processor instruction cache for a process.</summary>
        /// <param name="process">A handle to the process whose instruction cache is flushed.</param>
        /// <param name="baseAddress">The first address in the region to flush.</param>
        /// <param name="size">The size of the region, in bytes.</param>
        /// <returns><see langword="true"/> if the operation succeeds; otherwise, <see langword="false"/>.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FlushInstructionCache(IntPtr process, IntPtr baseAddress, UIntPtr size);

        /// <summary>Retrieves information about a range of pages in another process.</summary>
        /// <param name="process">A handle to the process whose address space is queried.</param>
        /// <param name="address">An address in the region to query.</param>
        /// <param name="buffer">Receives information about the region.</param>
        /// <param name="length">The size of <paramref name="buffer"/>, in bytes.</param>
        /// <returns>The number of bytes written to <paramref name="buffer"/>, or zero if the operation fails.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MemoryBasicInformation buffer, UIntPtr length);

        /// <summary>Closes an open object handle.</summary>
        /// <param name="handle">The handle to close.</param>
        /// <returns><see langword="true"/> if the operation succeeds; otherwise, <see langword="false"/>.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        /// <summary>Displays a modal message box.</summary>
        /// <param name="owner">The handle of the owner window, or <see cref="IntPtr.Zero"/> for no owner.</param>
        /// <param name="text">The message displayed in the dialog box.</param>
        /// <param name="caption">The dialog-box title.</param>
        /// <param name="type">The buttons, icon, and behavior requested for the dialog box.</param>
        /// <returns>An integer identifying the button selected by the user.</returns>
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern int MessageBox(IntPtr owner, string text, string caption, uint type);

        /// <summary>Enumerates top-level windows.</summary>
        /// <param name="callback">The callback invoked for each top-level window.</param>
        /// <param name="parameter">An application-defined value passed to the callback.</param>
        /// <returns><see langword="true"/> if enumeration completes; otherwise, <see langword="false"/>.</returns>
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool EnumWindows(EnumWindowCallback callback, IntPtr parameter);

        /// <summary>Enumerates child windows that belong to a parent window.</summary>
        /// <param name="parent">The handle of the parent window.</param>
        /// <param name="callback">The callback invoked for each child window.</param>
        /// <param name="parameter">An application-defined value passed to the callback.</param>
        /// <returns><see langword="true"/> if enumeration completes; otherwise, <see langword="false"/>.</returns>
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool EnumChildWindows(IntPtr parent, EnumWindowCallback callback, IntPtr parameter);

        /// <summary>Retrieves the process identifier associated with a window.</summary>
        /// <param name="window">The handle of the window.</param>
        /// <param name="processId">Receives the identifier of the process that created the window.</param>
        /// <returns>The identifier of the thread that created the window.</returns>
        [DllImport("user32.dll")]
        internal static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

        /// <summary>Determines whether a window is visible.</summary>
        /// <param name="window">The handle of the window to test.</param>
        /// <returns><see langword="true"/> if the window is visible; otherwise, <see langword="false"/>.</returns>
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWindowVisible(IntPtr window);

        /// <summary>Retrieves a window related to the specified window.</summary>
        /// <param name="window">The handle of the source window.</param>
        /// <param name="command">The relationship between the source and requested windows.</param>
        /// <returns>The related window handle, or <see cref="IntPtr.Zero"/> if no such window exists.</returns>
        [DllImport("user32.dll")]
        internal static extern IntPtr GetWindow(IntPtr window, uint command);

        /// <summary>Retrieves the class name of a window.</summary>
        /// <param name="window">The handle of the window.</param>
        /// <param name="className">The buffer that receives the class name.</param>
        /// <param name="maximumCount">The capacity of <paramref name="className"/>, in characters.</param>
        /// <returns>The number of characters copied, or zero if the operation fails.</returns>
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetClassName(IntPtr window, StringBuilder className, int maximumCount);

        /// <summary>Retrieves the title or text of a window.</summary>
        /// <param name="window">The handle of the window.</param>
        /// <param name="text">The buffer that receives the window text.</param>
        /// <param name="maximumCount">The capacity of <paramref name="text"/>, in characters.</param>
        /// <returns>The number of characters copied, or zero if the window has no text or the operation fails.</returns>
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetWindowText(IntPtr window, StringBuilder text, int maximumCount);

        /// <summary>Posts a message to a window-owning thread.</summary>
        /// <param name="window">The handle of the window that receives the message.</param>
        /// <param name="message">The message identifier.</param>
        /// <param name="wParam">Additional message-specific information.</param>
        /// <param name="lParam">Additional message-specific information.</param>
        /// <returns><see langword="true"/> if the operation succeeds; otherwise, <see langword="false"/>.</returns>
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    }
}
