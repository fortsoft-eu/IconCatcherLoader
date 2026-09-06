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
using System.Runtime.InteropServices;

namespace IconCatcherLoader {

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
}
