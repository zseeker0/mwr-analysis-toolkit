// Prepares the decrypted RVA-laid-out MWR image for Ghidra auto-analysis.
//
// BinaryLoader maps the whole dump at 0x140000000, but the dump retains PE
// headers whose SizeOfRawData/raw-pointer fields describe the original on-disk
// layout.  Using the PE loader would therefore map most sections incorrectly.
// This pre-script reads the PE header, rebuilds one memory block per section
// using VirtualAddress as the byte offset (the dump layout), sets realistic
// section permissions, and applies existing recovered labels as analysis aids.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PrepareMwrImage extends GhidraScript {
    private static final long BASE = 0x140000000L;

    private static class Section {
        String name;
        long va;
        long virtualSize;
        long rawSize;
        long characteristics;
    }

    private Memory memory;
    private long maxMappedOffset;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("PrepareMwrImage: usage: <repo-root>");
            return;
        }

        Path repoRoot = Paths.get(args[0]);
        memory = currentProgram.getMemory();
        println("LOAD_BASE program_image_base=" + hex(currentProgram.getImageBase().getOffset())
                + " mapped_min=" + memory.getMinAddress() + " mapped_max=" + memory.getMaxAddress());

        // BinaryLoader maps bytes at the requested base but a raw binary
        // program keeps its image-base metadata at zero. Use the actual mapped
        // base; changing Program.setImageBase would shift the address space.
        long imageBase = memory.getMinAddress().getOffset();
        if (imageBase != BASE) {
            throw new IllegalStateException("Unexpected mapped base: " + hex(imageBase));
        }
        maxMappedOffset = memory.getMaxAddress().getOffset();

        int peOffset = u16(imageBase + 0x3C);
        if (u16(imageBase + peOffset) != 0x4550) {
            throw new IllegalStateException("No PE signature at RVA 0x" + Integer.toHexString(peOffset));
        }
        int sectionCount = u16(imageBase + peOffset + 6);
        int optionalSize = u16(imageBase + peOffset + 20);
        long tableOffset = imageBase + peOffset + 24 + optionalSize;
        long sizeOfHeaders = u32(imageBase + peOffset + 24 + 60);

        List<Section> sections = new ArrayList<Section>();
        for (int i = 0; i < sectionCount; i++) {
            long off = tableOffset + 40L * i;
            Section s = new Section();
            StringBuilder name = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                int c = u8(off + j);
                if (c == 0) {
                    break;
                }
                name.append((char) c);
            }
            s.name = name.toString();
            s.virtualSize = u32(off + 8);
            s.va = u32(off + 12);
            s.rawSize = u32(off + 16);
            s.characteristics = u32(off + 36);
            sections.add(s);
        }

        // Snapshot bytes before removing the single BinaryLoader block.
        long headerSize = Math.min(sizeOfHeaders, 0x10000L);
        byte[] headerBytes = readBytes(imageBase, headerSize);
        List<byte[]> sectionBytes = new ArrayList<byte[]>();
        for (Section s : sections) {
            long size = sectionSize(s);
            sectionBytes.add(readBytes(imageBase + s.va, size));
        }

        MemoryBlock[] oldBlocks = memory.getBlocks();
        for (MemoryBlock block : oldBlocks) {
            memory.removeBlock(block, monitor);
        }

        MemoryBlock header = memory.createInitializedBlock(
                ".headers", addr(imageBase), new ByteArrayInputStream(headerBytes),
                headerBytes.length, monitor, false);
        header.setRead(true);
        header.setWrite(false);
        header.setExecute(false);

        int blockIndex = 0;
        for (Section s : sections) {
            byte[] bytes = sectionBytes.get(blockIndex++);
            String blockName = s.name.isEmpty() ? "section_" + blockIndex : s.name;
            if (memory.getBlock(blockName) != null) {
                blockName = blockName + "_" + blockIndex;
            }
            MemoryBlock block = memory.createInitializedBlock(
                    blockName, addr(imageBase + s.va), new ByteArrayInputStream(bytes),
                    bytes.length, monitor, false);
            block.setRead(true);
            block.setWrite((s.characteristics & 0x80000000L) != 0);
            block.setExecute((s.characteristics & 0x20000000L) != 0);
        }

        List<long[]> pdata = readPdata(imageBase, sections);
        FunctionManager functions = currentProgram.getFunctionManager();
        int created = 0;
        for (long[] range : pdata) {
            Address entry = addr(imageBase + range[0]);
            if (functions.getFunctionAt(entry) != null) {
                continue;
            }
            try {
                AddressSet body = new AddressSet(entry, addr(imageBase + range[1] - 1));
                Function fn = functions.createFunction(
                        "FUN_" + hex(range[0]), entry, body, SourceType.IMPORTED);
                if (fn != null) {
                    created++;
                }
            } catch (Exception ignored) {
                // Overlapping/nested .pdata entries are kept in the export but
                // must not abort preparation of the other 33k functions.
            }
        }

        int labels = applyLabels(repoRoot, imageBase);
        println("PREPARE_OK sections=" + sections.size() + " pdata=" + pdata.size()
                + " functions_created=" + created + " labels=" + labels);
    }

    private long sectionSize(Section s) {
        long size = s.virtualSize > 0 ? s.virtualSize : s.rawSize;
        // The decrypted dump is RVA-laid-out: bytes for a section begin at its
        // RVA, not at the stale PointerToRawData in the PE header.
        long available = maxMappedOffset - BASE + 1 - s.va;
        return Math.max(0, Math.min(size, available));
    }

    private List<long[]> readPdata(long imageBase, List<Section> sections) throws Exception {
        List<long[]> result = new ArrayList<long[]>();
        for (Section s : sections) {
            if (!s.name.equals(".pdata")) {
                continue;
            }
            long size = sectionSize(s);
            for (long off = s.va; off + 12 <= s.va + size; off += 12) {
                long begin = u32(imageBase + off);
                long end = u32(imageBase + off + 4);
                long unwind = u32(imageBase + off + 8);
                if (begin == 0 && end == 0) {
                    break;
                }
                if (end > begin && end - begin < 0x100000) {
                    result.add(new long[] {begin, end, unwind});
                }
            }
        }
        return result;
    }

    private int applyLabels(Path repoRoot, long imageBase) throws Exception {
        SymbolTable symbols = currentProgram.getSymbolTable();
        int count = 0;

        Path namesPath = repoRoot.resolve("build").resolve("resign").resolve("name_tables.json");
        if (Files.exists(namesPath)) {
            String text = new String(Files.readAllBytes(namesPath), StandardCharsets.UTF_8);
            Matcher entry = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\\[([^\\]]*)]").matcher(text);
            Pattern hexValue = Pattern.compile("\"(0[xX][0-9A-Fa-f]+)\"");
            while (entry.find()) {
                String safe = safeName("nt_" + entry.group(1));
                Matcher values = hexValue.matcher(entry.group(2));
                while (values.find()) {
                    long rva = Long.parseLong(values.group(1).substring(2), 16);
                    if (rva <= 0 || rva >= 0x12654800L) {
                        continue;
                    }
                    try {
                        symbols.createLabel(addr(imageBase + rva), safe, SourceType.IMPORTED);
                        count++;
                    } catch (Exception ignored) {
                        // Duplicate or invalid recovered names are not fatal.
                    }
                }
            }
        }

        Path mappingPath = repoRoot.resolve("build").resolve("resign").resolve("mapping.json");
        if (Files.exists(mappingPath)) {
            String text = new String(Files.readAllBytes(mappingPath), StandardCharsets.UTF_8);
            Matcher entry = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]*)\"\\s*:\\s*\"(0[xX][0-9A-Fa-f]+)\"")
                    .matcher(text);
            while (entry.find()) {
                long rva = Long.parseLong(entry.group(2).substring(2), 16);
                if (rva <= 0 || rva >= 0x12654800L) {
                    continue;
                }
                try {
                    symbols.createLabel(addr(imageBase + rva),
                            safeName("map_" + entry.group(1)), SourceType.IMPORTED);
                    count++;
                } catch (Exception ignored) {
                    // Ignore duplicate labels.
                }
            }
        }
        return count;
    }

    private static String safeName(String name) {
        return name.replaceAll("[^A-Za-z0-9_]", "_");
    }

    private byte[] readBytes(long address, long length) throws Exception {
        byte[] bytes = new byte[(int) length];
        int offset = 0;
        while (offset < bytes.length) {
            int read = memory.getBytes(addr(address + offset), bytes, offset, bytes.length - offset);
            if (read <= 0) {
                throw new IllegalStateException("Short memory read at " + hex(address + offset));
            }
            offset += read;
        }
        return bytes;
    }

    private int u8(long offset) throws Exception {
        return memory.getByte(addr(offset)) & 0xFF;
    }

    private int u16(long offset) throws Exception {
        return u8(offset) | (u8(offset + 1) << 8);
    }

    private long u32(long offset) throws Exception {
        return (long) u8(offset) | ((long) u8(offset + 1) << 8)
                | ((long) u8(offset + 2) << 16) | ((long) u8(offset + 3) << 24);
    }

    private Address addr(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static String hex(long value) {
        return String.format(Locale.US, "0x%X", value);
    }
}
