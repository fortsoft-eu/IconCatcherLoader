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
using System.Diagnostics;
using System.IO;

namespace IconCatcherLoader {

    /// <summary>
    /// Converts an IconCatcher NE icon library to a PE32 resource-only DLL with
    /// no executable entry point.
    /// </summary>
    internal static class NeIconLibraryConverter {
        private const ushort DosSignature = 0x5A4D;
        private const ushort NeSignature = 0x454E;
        private const uint PeSignature = 0x00004550;
        private const ushort ResourceTypeIcon = 3;
        private const ushort ResourceTypeGroupIcon = 14;
        private const int ResourceSectionRva = 0x1000;
        private const int PeHeaderOffset = 0x80;
        private const int FileAlignment = 0x200;
        private const int SectionAlignment = 0x1000;

        /// <summary>Creates or replaces a same-named PE DLL beside an NE ICL file.</summary>
        /// <param name="iclPath">The complete path of the successfully saved ICL file.</param>
        /// <returns>The complete path of the generated DLL.</returns>
        internal static string ConvertToPeDll(string iclPath) {
            if (string.IsNullOrEmpty(iclPath) || iclPath.Trim().Length == 0) {
                throw new ArgumentException("The ICL path must not be empty.", "iclPath");
            }

            byte[] source = File.ReadAllBytes(iclPath);
            List<NeResource> resources = ReadIconResources(source);
            byte[] resourceSection = BuildResourceSection(resources);
            byte[] portableExecutable = BuildPortableExecutable(resourceSection);
            string dllPath = Path.ChangeExtension(iclPath, ".dll");
            WriteReplacement(dllPath, portableExecutable);
            return dllPath;
        }

        /// <summary>Reads numeric RT_ICON and RT_GROUP_ICON entries from an NE file.</summary>
        /// <param name="image">The complete NE file.</param>
        /// <returns>The icon resources required by a Windows icon library.</returns>
        private static List<NeResource> ReadIconResources(byte[] image) {
            if (image.Length < 0x40 || ReadUInt16(image, 0) != DosSignature) {
                throw new InvalidDataException("The saved ICL file does not contain an MZ header.");
            }

            int neOffset = checked((int)ReadUInt32(image, 0x3C));
            EnsureRange(image, neOffset, 0x28);
            if (ReadUInt16(image, neOffset) != NeSignature) {
                throw new InvalidDataException("The saved ICL file is not an NE icon library.");
            }

            int resourceTable = checked(neOffset + ReadUInt16(image, neOffset + 0x24));
            EnsureRange(image, resourceTable, sizeof(ushort));
            int alignmentShift = ReadUInt16(image, resourceTable);
            if (alignmentShift > 15) {
                throw new InvalidDataException("The NE resource alignment value is invalid.");
            }

            int position = resourceTable + sizeof(ushort);
            List<NeResource> resources = new List<NeResource>();
            bool containsIcon = false;
            bool containsGroupIcon = false;

            while (true) {
                EnsureRange(image, position, 2 * sizeof(ushort));
                ushort rawType = ReadUInt16(image, position);
                ushort count = ReadUInt16(image, position + sizeof(ushort));
                position += 2 * sizeof(ushort);

                if (rawType == 0) {
                    break;
                }

                // Skip the reserved DWORD in the NE TYPEINFO structure.
                EnsureRange(image, position, sizeof(uint));
                position += sizeof(uint);

                bool numericType = (rawType & 0x8000) != 0;
                ushort typeId = (ushort)(rawType & 0x7FFF);

                for (int index = 0; index < count; index++) {
                    // Each NE NAMEINFO contains six consecutive WORD values.
                    EnsureRange(image, position, 6 * sizeof(ushort));
                    ushort offsetUnits = ReadUInt16(image, position);
                    ushort lengthUnits = ReadUInt16(image, position + 2);
                    ushort rawId = ReadUInt16(image, position + 6);
                    position += 6 * sizeof(ushort);

                    bool numericId = (rawId & 0x8000) != 0;
                    ushort resourceId = (ushort)(rawId & 0x7FFF);
                    if (!numericType || !numericId
                            || (typeId != ResourceTypeIcon
                                && typeId != ResourceTypeGroupIcon)) {

                        continue;
                    }

                    int dataOffset = checked(offsetUnits << alignmentShift);
                    int dataLength = checked(lengthUnits << alignmentShift);
                    EnsureRange(image, dataOffset, dataLength);

                    byte[] data = new byte[dataLength];
                    Buffer.BlockCopy(image, dataOffset, data, 0, dataLength);
                    resources.Add(new NeResource(typeId, resourceId, data));

                    containsIcon |= typeId == ResourceTypeIcon;
                    containsGroupIcon |= typeId == ResourceTypeGroupIcon;
                }
            }

            if (!containsIcon || !containsGroupIcon) {
                throw new InvalidDataException("The NE library does not contain complete icon resources.");
            }

            return resources;
        }

        /// <summary>Builds the IMAGE_RESOURCE_DIRECTORY tree for the PE .rsrc section.</summary>
        /// <param name="resources">The numeric icon resources to store.</param>
        /// <returns>A complete unaligned .rsrc section.</returns>
        private static byte[] BuildResourceSection(List<NeResource> resources) {
            resources.Sort(new Comparison<NeResource>(delegate (NeResource first, NeResource second) {
                int comparison = first.TypeId.CompareTo(second.TypeId);
                return comparison != 0 ? comparison : first.ResourceId.CompareTo(second.ResourceId);
            }));

            List<NeResourceType> types = new List<NeResourceType>();
            NeResourceType currentType = null;
            foreach (NeResource resource in resources) {
                if (currentType == null || currentType.TypeId != resource.TypeId) {
                    currentType = new NeResourceType(resource.TypeId);
                    types.Add(currentType);
                }
                if (currentType.Resources.Count != 0 && currentType.Resources[currentType.Resources.Count - 1].ResourceId == resource.ResourceId) {
                    throw new InvalidDataException("The NE library contains duplicate numeric resource identifiers.");
                }
                currentType.Resources.Add(resource);
            }

            // Reserve the root directory and one root entry for every resource type.
            int offset = checked(16 + 8 * types.Count);
            foreach (NeResourceType type in types) {
                type.DirectoryOffset = offset;
                offset = checked(offset + 16 + 8 * type.Resources.Count);
            }

            // PE resources use a third directory level for the language identifier.
            foreach (NeResource resource in resources) {
                resource.LanguageDirectoryOffset = offset;
                offset = checked(offset + 24);
            }

            foreach (NeResource resource in resources) {
                resource.DataEntryOffset = offset;
                offset = checked(offset + 16);
            }

            offset = Align(offset, 4);
            foreach (NeResource resource in resources) {
                resource.DataOffset = offset;
                offset = checked(Align(offset + resource.Data.Length, 4));
            }

            byte[] section = new byte[offset];
            WriteDirectoryHeader(section, 0, types.Count);

            for (int typeIndex = 0; typeIndex < types.Count; typeIndex++) {
                NeResourceType type = types[typeIndex];
                int rootEntry = 16 + typeIndex * 8;
                WriteUInt32(section, rootEntry, type.TypeId);
                WriteUInt32(section, rootEntry + 4, 0x80000000u | (uint)type.DirectoryOffset);

                WriteDirectoryHeader(section, type.DirectoryOffset, type.Resources.Count);
                for (int resourceIndex = 0; resourceIndex < type.Resources.Count; resourceIndex++) {

                    NeResource resource = type.Resources[resourceIndex];
                    int typeEntry = type.DirectoryOffset + 16 + resourceIndex * 8;
                    WriteUInt32(section, typeEntry, resource.ResourceId);
                    WriteUInt32(section, typeEntry + 4, 0x80000000u | (uint)resource.LanguageDirectoryOffset);

                    WriteDirectoryHeader(section, resource.LanguageDirectoryOffset, 1);
                    int languageEntry = resource.LanguageDirectoryOffset + 16;
                    WriteUInt32(section, languageEntry, 0);
                    WriteUInt32(section, languageEntry + 4, (uint)resource.DataEntryOffset);

                    WriteUInt32(section, resource.DataEntryOffset, (uint)(ResourceSectionRva + resource.DataOffset));
                    WriteUInt32(section, resource.DataEntryOffset + 4, (uint)resource.Data.Length);
                    Buffer.BlockCopy(resource.Data, 0, section, resource.DataOffset, resource.Data.Length);
                }
            }

            return section;
        }

        /// <summary>Wraps the resource section in a minimal PE32 DLL.</summary>
        /// <param name="resourceSection">The complete .rsrc section data.</param>
        /// <returns>A PE32 DLL image whose AddressOfEntryPoint is zero.</returns>
        private static byte[] BuildPortableExecutable(byte[] resourceSection) {
            const int optionalHeaderSize = 0xE0;
            const int headersSize = FileAlignment;
            int rawSectionSize = Align(resourceSection.Length, FileAlignment);
            int imageSize = Align(ResourceSectionRva + resourceSection.Length, SectionAlignment);
            byte[] image = new byte[checked(headersSize + rawSectionSize)];

            // DOS header and PE signature.
            WriteUInt16(image, 0, DosSignature);
            WriteUInt32(image, 0x3C, PeHeaderOffset);
            WriteUInt32(image, PeHeaderOffset, PeSignature);

            // IMAGE_FILE_HEADER: x86, one section, PE32 optional header, DLL, and
            // no relocation information because the image contains no code.
            int fileHeader = PeHeaderOffset + sizeof(uint);
            WriteUInt16(image, fileHeader, 0x014C);
            WriteUInt16(image, fileHeader + 2, 1);
            WriteUInt16(image, fileHeader + 16, optionalHeaderSize);
            WriteUInt16(image, fileHeader + 18, 0x2103);

            // IMAGE_OPTIONAL_HEADER32. AddressOfEntryPoint remains zero because
            // the zero-initialized field is deliberately not assigned.
            int optionalHeader = fileHeader + 20;
            WriteUInt16(image, optionalHeader, 0x010B);
            image[optionalHeader + 2] = 14;
            WriteUInt32(image, optionalHeader + 8, (uint)rawSectionSize);
            WriteUInt32(image, optionalHeader + 24, ResourceSectionRva);
            WriteUInt32(image, optionalHeader + 28, 0x10000000);
            WriteUInt32(image, optionalHeader + 32, SectionAlignment);
            WriteUInt32(image, optionalHeader + 36, FileAlignment);
            WriteUInt16(image, optionalHeader + 40, 4);
            WriteUInt16(image, optionalHeader + 48, 4);
            WriteUInt32(image, optionalHeader + 56, (uint)imageSize);
            WriteUInt32(image, optionalHeader + 60, headersSize);
            WriteUInt16(image, optionalHeader + 68, 2);
            WriteUInt32(image, optionalHeader + 72, 0x00100000);
            WriteUInt32(image, optionalHeader + 76, 0x00001000);
            WriteUInt32(image, optionalHeader + 80, 0x00100000);
            WriteUInt32(image, optionalHeader + 84, 0x00001000);
            WriteUInt32(image, optionalHeader + 92, 16);

            // The resource data directory is directory entry number two.
            WriteUInt32(image, optionalHeader + 112, ResourceSectionRva);
            WriteUInt32(image, optionalHeader + 116, (uint)resourceSection.Length);

            // The only section contains initialized, read-only resource data.
            int sectionHeader = optionalHeader + optionalHeaderSize;
            image[sectionHeader] = (byte)'.';
            image[sectionHeader + 1] = (byte)'r';
            image[sectionHeader + 2] = (byte)'s';
            image[sectionHeader + 3] = (byte)'r';
            image[sectionHeader + 4] = (byte)'c';
            WriteUInt32(image, sectionHeader + 8, (uint)resourceSection.Length);
            WriteUInt32(image, sectionHeader + 12, ResourceSectionRva);
            WriteUInt32(image, sectionHeader + 16, (uint)rawSectionSize);
            WriteUInt32(image, sectionHeader + 20, headersSize);
            WriteUInt32(image, sectionHeader + 36, 0x40000040);
            Buffer.BlockCopy(resourceSection, 0, image, headersSize, resourceSection.Length);
            return image;
        }

        /// <summary>Writes a completed DLL and replaces an existing same-named file.</summary>
        /// <param name="dllPath">The final DLL path.</param>
        /// <param name="image">The complete PE image.</param>
        private static void WriteReplacement(string dllPath, byte[] image) {
            string directory = Path.GetDirectoryName(dllPath);
            if (string.IsNullOrEmpty(directory)) {
                throw new InvalidOperationException("The destination directory could not be determined.");
            }

            string temporaryPath;
            do {
                temporaryPath = Path.Combine(directory, "." + Path.GetFileName(dllPath) + "." + Guid.NewGuid().ToString("N") + ".tmp");
            } while (File.Exists(temporaryPath));

            try {
                using (FileStream stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    stream.Write(image, 0, image.Length);
                    stream.Flush();
                }

                // The overwrite flag handles both a new DLL and replacement of a
                // DLL generated for an earlier save of the same ICL file.
                File.Copy(temporaryPath, dllPath, true);
            } finally {
                try {
                    File.Delete(temporaryPath);
                } catch (Exception exception) {
                    Debug.WriteLine(exception);
                    // A stale temporary file must not terminate the monitor after
                    // the final DLL has already been written successfully.
                }
            }
        }

        /// <summary>Writes a resource-directory header containing numeric IDs.</summary>
        private static void WriteDirectoryHeader(byte[] buffer, int offset, int identifierCount) {
            if ((uint)identifierCount > ushort.MaxValue) {
                throw new InvalidDataException("The icon library contains too many resources.");
            }
            WriteUInt16(buffer, offset + 14, (ushort)identifierCount);
        }

        /// <summary>Rounds a positive value up to an alignment boundary.</summary>
        private static int Align(int value, int alignment) {
            return checked((value + alignment - 1) & -alignment);
        }

        /// <summary>Reads one little-endian WORD after validating its range.</summary>
        private static ushort ReadUInt16(byte[] buffer, int offset) {
            EnsureRange(buffer, offset, sizeof(ushort));
            return (ushort)(buffer[offset] | (buffer[offset + 1] << 8));
        }

        /// <summary>Reads one little-endian DWORD after validating its range.</summary>
        private static uint ReadUInt32(byte[] buffer, int offset) {
            EnsureRange(buffer, offset, sizeof(uint));
            return (uint)(buffer[offset]
                | (buffer[offset + 1] << 8)
                | (buffer[offset + 2] << 16)
                | (buffer[offset + 3] << 24));
        }

        /// <summary>Writes one little-endian WORD.</summary>
        private static void WriteUInt16(byte[] buffer, int offset, ushort value) {
            buffer[offset] = (byte)value;
            buffer[offset + 1] = (byte)(value >> 8);
        }

        /// <summary>Writes one little-endian DWORD.</summary>
        private static void WriteUInt32(byte[] buffer, int offset, uint value) {
            buffer[offset] = (byte)value;
            buffer[offset + 1] = (byte)(value >> 8);
            buffer[offset + 2] = (byte)(value >> 16);
            buffer[offset + 3] = (byte)(value >> 24);
        }

        /// <summary>Rejects truncated or otherwise invalid file ranges.</summary>
        private static void EnsureRange(byte[] buffer, int offset, int length) {
            if (offset < 0 || length < 0 || offset > buffer.Length - length) {
                throw new InvalidDataException("The icon library contains an invalid or truncated structure.");
            }
        }
    }
}
