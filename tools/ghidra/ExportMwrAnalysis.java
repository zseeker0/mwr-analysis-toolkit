// Exports Ghidra analysis of the decrypted 2016 MWR image into build/resign/ghidra.
//
// Script arguments (all positional, no leading '-'):
//   <repo-root> <out-dir> <image-path> <decompile-mode> <max-decompile> <timeout-seconds>
//
// decompile-mode: all | none | max
// max-decompile: 0 means unlimited when mode=all, otherwise the cap for mode=max.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedWriter;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;

public class ExportMwrAnalysis extends GhidraScript {
    private long imageBase;
    private long programImageBase;
    private Memory memory;
    private List<long[]> pdata;
    private Map<Long, long[]> pdataByStart;
    private int pdataFunctionsCreated;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 6) {
            println("ExportMwrAnalysis: expected 6 positional arguments");
            return;
        }

        Path outDir = Paths.get(args[1]);
        Path imagePath = Paths.get(args[2]);
        String decompileMode = args[3].toLowerCase(Locale.US);
        long maxDecompile = parseLong(args[4], 0);
        int decompileTimeout = (int) parseLong(args[5], 120);

        Files.createDirectories(outDir);
        memory = currentProgram.getMemory();
        programImageBase = currentProgram.getImageBase().getOffset();
        // Raw BinaryLoader maps bytes at the requested base but keeps program
        // image-base metadata at zero. Use the actual mapped base.
        imageBase = memory.getMinAddress().getOffset();
        if (imageBase != 0x140000000L) {
            throw new IllegalStateException("Unexpected mapped base: " + hex(imageBase));
        }

        pdata = readPdata();
        pdataByStart = new HashMap<Long, long[]>();
        for (long[] range : pdata) {
            pdataByStart.put(range[0], range);
        }
        pdataFunctionsCreated = createFunctionsFromPdata();

        writeMetadata(args, outDir, imagePath, decompileMode, maxDecompile, decompileTimeout);
        writePdata(outDir);
        writeFunctions(outDir);
        writeSymbols(outDir);
        writeData(outDir);
        writeXrefs(outDir);
        writeDecompilation(outDir, decompileMode, maxDecompile, decompileTimeout);

        println("EXPORT_OK out=" + outDir.toAbsolutePath().normalize()
                + " pdata=" + pdata.size() + " functions_created=" + pdataFunctionsCreated);
    }

    private void writeMetadata(String[] args, Path outDir, Path imagePath, String mode,
                               long maxDecompile, int timeout) throws Exception {
        Path out = outDir.resolve("metadata.json");
        try (BufferedWriter w = writer(out)) {
            w.write("{\n");
            w.write("  \"schema\": \"mwr-ghidra-analysis-v1\",\n");
            w.write("  \"generated\": " + q(Long.toString(System.currentTimeMillis())) + ",\n");
            w.write("  \"program_name\": " + q(currentProgram.getName()) + ",\n");
            w.write("  \"image_base\": " + q(hex(imageBase)) + ",\n");
            w.write("  \"program_image_base\": " + q(hex(programImageBase)) + ",\n");
            w.write("  \"language\": " + q(currentProgram.getLanguage().getLanguageID().toString()) + ",\n");
            w.write("  \"compiler\": " + q(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()) + ",\n");
            w.write("  \"function_count\": " + currentProgram.getFunctionManager().getFunctionCount() + ",\n");
            w.write("  \"pdata_entries\": " + pdata.size() + ",\n");
            w.write("  \"functions_created_from_pdata\": " + pdataFunctionsCreated + ",\n");
            w.write("  \"decompile_mode\": " + q(mode) + ",\n");
            w.write("  \"max_decompile\": " + maxDecompile + ",\n");
            w.write("  \"decompile_timeout_seconds\": " + timeout + ",\n");
            w.write("  \"script_args\": " + jsonStringArray(args) + ",\n");
            w.write("  \"source_image_sha256\": " + q(sha256(imagePath)) + "\n");
            w.write("}\n");
        }
    }

    private void writePdata(Path outDir) throws Exception {
        Path out = outDir.resolve("pdata.json");
        try (BufferedWriter w = writer(out)) {
            w.write("{\n  \"entries\": [\n");
            for (int i = 0; i < pdata.size(); i++) {
                long[] e = pdata.get(i);
                w.write("    {\"begin\":" + q(hex(e[0])) + ",\"end\":" + q(hex(e[1]))
                        + ",\"unwind\":" + q(hex(e[2])) + "}");
                w.write(i + 1 < pdata.size() ? ",\n" : "\n");
            }
            w.write("  ]\n}\n");
        }
    }

    private void writeFunctions(Path outDir) throws Exception {
        Path out = outDir.resolve("functions.json");
        FunctionManager fm = currentProgram.getFunctionManager();
        try (BufferedWriter w = writer(out)) {
            w.write("{\n  \"functions\": [\n");
            boolean first = true;
            FunctionIteratorCompat fns = new FunctionIteratorCompat(fm.getFunctions(true));
            for (Function fn : fns.items) {
                Address entry = fn.getEntryPoint();
                long rva = rva(entry);
                long[] pdataRange = pdataRange(rva);
                long bodyBegin = pdataRange == null ? rva : pdataRange[0];
                long bodyEnd = pdataRange == null ? rva + 1 : pdataRange[1];
                FunctionSignature sig = fn.getSignature();
                if (!first) {
                    w.write(",\n");
                }
                first = false;
                w.write("    {\"rva\":" + q(hex(rva)) + ",\"va\":" + q(hex(entry.getOffset()))
                        + ",\"name\":" + q(fn.getName()) + ",\"body_begin\":"
                        + q(hex(bodyBegin)) + ",\"body_end\":"
                        + q(hex(bodyEnd))
                        + ",\"thunk\":" + fn.isThunk() + ",\"external\":" + fn.isExternal()
                        + ",\"calling_convention\":" + q(sig.getCallingConventionName())
                        + ",\"signature\":" + q(sig.getPrototypeString(false))
                        + ",\"parameters\":" + jsonParameters(fn.getParameters()) + "}");
            }
            w.write("\n  ]\n}\n");
        }
    }

    private void writeSymbols(Path outDir) throws Exception {
        Path out = outDir.resolve("symbols.json");
        SymbolTable table = currentProgram.getSymbolTable();
        try (BufferedWriter w = writer(out)) {
            w.write("{\n  \"symbols\": [\n");
            boolean first = true;
            SymbolIterator it = table.getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                if (!first) {
                    w.write(",\n");
                }
                first = false;
                w.write("    {\"name\":" + q(s.getName()) + ",\"rva\":" + q(hex(rva(s.getAddress())))
                        + ",\"type\":" + q(s.getSymbolType().toString())
                        + ",\"primary\":" + s.isPrimary() + "}");
            }
            w.write("\n  ]\n}\n");
        }
    }

    private void writeData(Path outDir) throws Exception {
        Path dataOut = outDir.resolve("data.json");
        Path stringsOut = outDir.resolve("strings.json");
        // getData(true) walks every undefined byte in a 300 MB raw image.
        // Only defined data (strings, globals, typed constants) is useful here.
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        int dataCount = 0;
        int stringCount = 0;
        try (BufferedWriter dataWriter = writer(dataOut);
             BufferedWriter stringWriter = writer(stringsOut)) {
            dataWriter.write("{\n  \"data\": [\n");
            stringWriter.write("{\n  \"strings\": [\n");
            boolean firstData = true;
            boolean firstString = true;
            while (it.hasNext()) {
                Data d = it.next();
                if (d == null) {
                    continue;
                }
                String rep = null;
                try {
                    rep = d.getDefaultValueRepresentation();
                } catch (Exception ignored) {
                    // Some structures cannot produce a default representation.
                }
                String typeName = d.getDataType() == null ? "" : d.getDataType().getName();
                if (!firstData) {
                    dataWriter.write(",\n");
                }
                firstData = false;
                dataCount++;
                dataWriter.write("    {\"rva\":" + q(hex(rva(d.getAddress())))
                        + ",\"type\":" + q(typeName) + ",\"size\":" + d.getLength()
                        + ",\"value\":" + q(rep) + "}");

                if (rep != null && rep.length() >= 2
                        && rep.startsWith("\"") && rep.endsWith("\"")) {
                    if (!firstString) {
                        stringWriter.write(",\n");
                    }
                    firstString = false;
                    stringCount++;
                    stringWriter.write("    {\"rva\":" + q(hex(rva(d.getAddress())))
                            + ",\"value\":" + q(rep.substring(1, rep.length() - 1))
                            + ",\"type\":" + q(typeName) + "}");
                }
            }
            dataWriter.write("\n  ]\n}\n");
            stringWriter.write("\n  ]\n}\n");
        }
        println("DATA_EXPORT data=" + dataCount + " strings=" + stringCount);
    }

    private void writeXrefs(Path outDir) throws Exception {
        Path xrefOut = outDir.resolve("xrefs.json");
        Path funcOut = outDir.resolve("function_refs.json");
        Path dataOut = outDir.resolve("data_refs.json");

        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        int total = 0;
        int functionRefs = 0;
        int dataRefs = 0;

        try (BufferedWriter xw = writer(xrefOut);
             BufferedWriter fw = writer(funcOut);
             BufferedWriter dw = writer(dataOut)) {
            xw.write("{\n  \"xrefs\": [\n");
            fw.write("{\n  \"function_refs\": [\n");
            dw.write("{\n  \"data_refs\": [\n");
            boolean firstX = true;
            boolean firstF = true;
            boolean firstD = true;

            while (instructions.hasNext()) {
                Instruction ins = instructions.next();
                Address from = ins.getAddress();
                Function fromFn = fm.getFunctionContaining(from);
                long fromRva = rva(from);
                long fromFnRva = fromFn == null ? -1 : rva(fromFn.getEntryPoint());
                Reference[] refs = rm.getReferencesFrom(from);
                for (Reference ref : refs) {
                    RefType type = ref.getReferenceType();
                    Address to = ref.getToAddress();
                    long toRva = isMapped(to) ? rva(to) : -1;
                    String kind = referenceKind(type);
                    if (!firstX) {
                        xw.write(",\n");
                    }
                    firstX = false;
                    total++;
                    xw.write("    {\"from\":" + q(hex(fromRva))
                            + ",\"from_function\":" + (fromFnRva < 0 ? "null" : q(hex(fromFnRva)))
                            + ",\"to\":" + (toRva < 0 ? q(to.toString()) : q(hex(toRva)))
                            + ",\"kind\":" + q(kind)
                            + ",\"operand\":" + ref.getOperandIndex() + "}");

                    if (type.isFlow() && toRva >= 0) {
                        Function toFn = fm.getFunctionAt(to);
                        if (fromFn != null && toFn != null && fromFn != toFn) {
                            if (!firstF) {
                                fw.write(",\n");
                            }
                            firstF = false;
                            functionRefs++;
                            fw.write("    {\"caller\":" + q(hex(fromFnRva))
                                    + ",\"callee\":" + q(hex(rva(toFn.getEntryPoint())))
                                    + ",\"kind\":" + q(kind)
                                    + ",\"from\":" + q(hex(fromRva)) + "}");
                        }
                    } else if (!type.isFlow() && toRva >= 0 && !isExecute(to)) {
                        if (!firstD) {
                            dw.write(",\n");
                        }
                        firstD = false;
                        dataRefs++;
                        dw.write("    {\"function\":" + (fromFnRva < 0 ? "null" : q(hex(fromFnRva)))
                                + ",\"from\":" + q(hex(fromRva))
                                + ",\"data\":" + q(hex(toRva))
                                + ",\"kind\":" + q(kind)
                                + ",\"operand\":" + ref.getOperandIndex() + "}");
                    }
                }
            }
            xw.write("\n  ]\n}\n");
            fw.write("\n  ]\n}\n");
            dw.write("\n  ]\n}\n");
        }
        println("XREF_EXPORT xrefs=" + total + " function_refs=" + functionRefs
                + " data_refs=" + dataRefs);
    }

    private void writeDecompilation(Path outDir, String mode, long max, int timeout) throws Exception {
        Path out = outDir.resolve("decompilation.json");
        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> targets = new ArrayList<Function>();
        if (!mode.equals("none")) {
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext() && (mode.equals("all") || max <= 0 || targets.size() < max)) {
                targets.add(it.next());
            }
        }

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        boolean opened = decompiler.openProgram(currentProgram);

        int ok = 0;
        int failed = 0;
        try (BufferedWriter w = writer(out)) {
            w.write("{\n  \"functions\": [\n");
            for (int i = 0; i < targets.size(); i++) {
                Function fn = targets.get(i);
                long rva = rva(fn.getEntryPoint());
                String code = "";
                String error = "";
                boolean success = false;
                if (opened) {
                    try {
                        DecompileResults result = decompiler.decompileFunction(fn, timeout, monitor);
                        if (result != null && result.decompileCompleted()
                                && result.getDecompiledFunction() != null) {
                            code = result.getDecompiledFunction().getC();
                            success = true;
                            ok++;
                        } else {
                            error = result == null ? "no result" : result.getErrorMessage();
                            failed++;
                        }
                    } catch (Exception ex) {
                        error = ex.getClass().getSimpleName() + ": " + ex.getMessage();
                        failed++;
                    }
                } else {
                    error = "decompiler openProgram failed";
                    failed++;
                }
                if (i > 0) {
                    w.write(",\n");
                }
                w.write("    {\"rva\":" + q(hex(rva)) + ",\"name\":" + q(fn.getName())
                        + ",\"success\":" + success + ",\"error\":" + q(error)
                        + ",\"c\":" + q(code) + "}");
                if ((i + 1) % 250 == 0) {
                    println("DECOMPILE_PROGRESS " + (i + 1) + "/" + targets.size());
                }
            }
            w.write("\n  ]\n}\n");
        } finally {
            decompiler.dispose();
        }
        println("DECOMPILE_EXPORT ok=" + ok + " failed=" + failed + " targets=" + targets.size());
    }

    private List<long[]> readPdata() throws Exception {
        List<long[]> result = new ArrayList<long[]>();
        int peOffset = u16(imageBase + 0x3C);
        int sectionCount = u16(imageBase + peOffset + 6);
        int optionalSize = u16(imageBase + peOffset + 20);
        long table = imageBase + peOffset + 24 + optionalSize;
        for (int i = 0; i < sectionCount; i++) {
            long off = table + 40L * i;
            String name = readSectionName(off);
            if (!name.equals(".pdata")) {
                continue;
            }
            long virtualSize = u32(off + 8);
            long va = u32(off + 12);
            long rawSize = u32(off + 16);
            long size = virtualSize > 0 ? virtualSize : rawSize;
            for (long o = va; o + 12 <= va + size; o += 12) {
                long begin = u32(imageBase + o);
                long end = u32(imageBase + o + 4);
                long unwind = u32(imageBase + o + 8);
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

    private int createFunctionsFromPdata() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        Set<Long> created = new HashSet<Long>();
        for (long[] range : pdata) {
            Address entry = addr(imageBase + range[0]);
            if (fm.getFunctionAt(entry) != null) {
                continue;
            }
            try {
                AddressSet body = new AddressSet(entry, addr(imageBase + range[1] - 1));
                Function fn = fm.createFunction("FUN_" + hex(range[0]), entry, body, SourceType.IMPORTED);
                if (fn != null) {
                    created.add(range[0]);
                }
            } catch (Exception ignored) {
                // Preserve what auto-analysis and .pdata already established.
            }
        }
        return created.size();
    }

    private long[] pdataRange(long rva) {
        return pdataByStart.get(rva);
    }

    private String readSectionName(long off) throws Exception {
        StringBuilder name = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            int c = u8(off + i);
            if (c == 0) {
                break;
            }
            name.append((char) c);
        }
        return name.toString();
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

    private boolean isMapped(Address address) {
        return address != null && address.getOffset() >= imageBase
                && address.getOffset() < imageBase + 0x12654800L;
    }

    private boolean isExecute(Address address) {
        MemoryBlock block = memory.getBlock(address);
        return block != null && block.isExecute();
    }

    private long rva(Address address) {
        return address.getOffset() - imageBase;
    }

    private static String referenceKind(RefType type) {
        if (type.isCall()) {
            return "call";
        }
        if (type.isJump()) {
            return "jump";
        }
        if (type.isFlow()) {
            return "flow";
        }
        if (type.isRead()) {
            return "read";
        }
        if (type.isWrite()) {
            return "write";
        }
        return "data";
    }

    private String jsonParameters(Parameter[] parameters) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < parameters.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            Parameter p = parameters[i];
            sb.append("{\"name\":").append(q(p.getName()))
                    .append(",\"type\":").append(q(p.getDataType() == null
                            ? "" : p.getDataType().getName()))
                    .append(",\"ordinal\":").append(p.getOrdinal()).append('}');
        }
        return sb.append(']').toString();
    }

    private static String jsonStringArray(String[] values) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(q(values[i]));
        }
        return sb.append(']').toString();
    }

    private static BufferedWriter writer(Path path) throws Exception {
        return Files.newBufferedWriter(path, StandardCharsets.UTF_8);
    }

    private static long parseLong(String value, long fallback) {
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException ex) {
            return fallback;
        }
    }

    private static String sha256(Path path) throws Exception {
        if (path == null || !Files.exists(path)) {
            return "";
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(path)) {
            byte[] buffer = new byte[1 << 20];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : digest.digest()) {
            sb.append(String.format(Locale.US, "%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static String hex(long value) {
        return String.format(Locale.US, "0x%X", value);
    }

    private static String q(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format(Locale.US, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }

    private static class FunctionIteratorCompat {
        final List<Function> items = new ArrayList<Function>();
        FunctionIteratorCompat(FunctionIterator iterator) {
            while (iterator.hasNext()) {
                items.add(iterator.next());
            }
        }
    }
}
