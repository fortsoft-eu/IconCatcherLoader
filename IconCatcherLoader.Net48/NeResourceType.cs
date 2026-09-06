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

using System.Collections.Generic;

namespace IconCatcherLoader {

    /// <summary>Groups numeric resources of one Win32 resource type.</summary>
    internal sealed class NeResourceType {
        private readonly ushort typeId;
        private readonly List<NeResource> resources;

        /// <summary>Initializes an empty group for the specified resource type.</summary>
        /// <param name="typeId">The numeric Win32 resource type.</param>
        internal NeResourceType(ushort typeId) {
            this.typeId = typeId;
            resources = new List<NeResource>();
        }

        /// <summary>Gets the numeric Win32 resource type.</summary>
        internal ushort TypeId {
            get {
                return typeId;
            }
        }

        /// <summary>Gets the resources in this group.</summary>
        internal List<NeResource> Resources {
            get {
                return resources;
            }
        }

        /// <summary>Gets or sets the .rsrc-relative type-directory offset.</summary>
        internal int DirectoryOffset { get; set; }
    }
}
