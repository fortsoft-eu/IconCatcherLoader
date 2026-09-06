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

namespace IconCatcherLoader {

    /// <summary>Represents one numeric icon resource read from an NE library.</summary>
    internal sealed class NeResource {
        private readonly ushort typeId;
        private readonly ushort resourceId;
        private readonly byte[] data;

        /// <summary>Initializes a resource with its numeric type, identifier, and data.</summary>
        /// <param name="typeId">The Win32 resource type identifier.</param>
        /// <param name="resourceId">The numeric resource identifier.</param>
        /// <param name="data">The complete resource data.</param>
        internal NeResource(ushort typeId, ushort resourceId, byte[] data) {
            this.typeId = typeId;
            this.resourceId = resourceId;
            this.data = data;
        }

        /// <summary>Gets the numeric Win32 resource type.</summary>
        internal ushort TypeId {
            get {
                return typeId;
            }
        }

        /// <summary>Gets the numeric resource identifier.</summary>
        internal ushort ResourceId {
            get {
                return resourceId;
            }
        }

        /// <summary>Gets the complete resource data.</summary>
        internal byte[] Data {
            get {
                return data;
            }
        }

        /// <summary>Gets or sets the .rsrc-relative language-directory offset.</summary>
        internal int LanguageDirectoryOffset { get; set; }

        /// <summary>Gets or sets the .rsrc-relative data-entry offset.</summary>
        internal int DataEntryOffset { get; set; }

        /// <summary>Gets or sets the .rsrc-relative resource-data offset.</summary>
        internal int DataOffset { get; set; }
    }
}
