import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import com.google.gson.GsonBuilder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

// Export existing analysis only; never create instructions, functions or aliases.
public class ExportProgramIndex extends GhidraScript {
    private Map<String, Object> address(Address value) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("space", value.getAddressSpace().getName());
        row.put("offset", Long.toUnsignedString(value.getOffset(), 16));
        row.put("text", value.toString());
        return row;
    }

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 1) {
            throw new IllegalArgumentException("Expected one fresh output JSON path");
        }
        Path output = Paths.get(arguments[0]);
        if (Files.exists(output)) {
            throw new IllegalArgumentException("Index output already exists");
        }
        Map<String, Object> index = new LinkedHashMap<>();
        index.put("format_version", 1);
        Map<String, Object> program = new LinkedHashMap<>();
        program.put("name", currentProgram.getName());
        program.put("executable_sha256", currentProgram.getExecutableSHA256());
        program.put("language", currentProgram.getLanguageID().toString());
        program.put("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        program.put("image_base", address(currentProgram.getImageBase()));
        index.put("program", program);
        List<Object> spaces = new ArrayList<>();
        for (AddressSpace space : currentProgram.getAddressFactory().getAddressSpaces()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", space.getName());
            row.put("type", space.getType());
            row.put("size_bits", space.getSize());
            spaces.add(row);
        }
        index.put("address_spaces", spaces);
        List<Object> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            Map<String, Object> row = new LinkedHashMap<>();
            Address entry = function.getEntryPoint();
            row.put("id", entry.getAddressSpace().getName() + ":" + entry.toString());
            row.put("name", function.getName());
            row.put("entry", address(entry));
            row.put("external", function.isExternal());
            row.put("thunk", function.isThunk());
            row.put("extent_verified", false);
            row.put("confidence", "existing-ghidra-analysis");
            List<Object> ranges = new ArrayList<>();
            AddressRangeIterator bodies = function.getBody().getAddressRanges(true);
            while (bodies.hasNext()) {
                AddressRange range = bodies.next();
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("start", address(range.getMinAddress()));
                body.put("end_inclusive", address(range.getMaxAddress()));
                ranges.add(body);
            }
            row.put("ranges", ranges);
            List<Object> calls = new ArrayList<>();
            List<Object> references = new ArrayList<>();
            InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                Instruction instruction = instructions.next();
                boolean foundCall = false;
                for (Reference reference : instruction.getReferencesFrom()) {
                    Map<String, Object> referenceRow = new LinkedHashMap<>();
                    referenceRow.put("from", address(reference.getFromAddress()));
                    referenceRow.put("to", address(reference.getToAddress()));
                    referenceRow.put("type", reference.getReferenceType().toString());
                    referenceRow.put("operand", reference.getOperandIndex());
                    referenceRow.put("source", reference.getSource().toString());
                    if (reference.getReferenceType().isCall()) {
                        foundCall = true;
                        calls.add(referenceRow);
                    } else if (reference.isMemoryReference() || reference.isStackReference()) {
                        references.add(referenceRow);
                    }
                }
                if (instruction.getFlowType().isCall() && !foundCall) {
                    Map<String, Object> unresolved = new LinkedHashMap<>();
                    unresolved.put("from", address(instruction.getAddress()));
                    unresolved.put("to", null);
                    unresolved.put("type", "unresolved-call");
                    calls.add(unresolved);
                }
            }
            row.put("calls", calls);
            row.put("memory_references", references);
            functions.add(row);
        }
        index.put("functions", functions);
        index.put("candidate_aliases", Collections.emptyList());
        index.put("limits", "Analysis bodies/references only; discovery is incomplete, extents and segmented aliases unverified. Empty aliases means not analyzed, not absence of aliases.");
        Files.write(output, (new GsonBuilder().setPrettyPrinting().serializeNulls().create().toJson(index) + "\n")
            .getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW);
        println("PROGRAM_INDEX functions=" + functions.size() + " output=" + output);
    }
}
