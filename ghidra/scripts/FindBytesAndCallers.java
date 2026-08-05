// Search initialized memory for byte patterns and list callers of containing functions.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class FindBytesAndCallers extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr(
                "Usage: FindBytesAndCallers <hex-bytes> [<hex-bytes> ...]");
            return;
        }

        Memory memory = currentProgram.getMemory();
        for (String arg : args) {
            byte[] pattern;
            try {
                pattern = parseHex(arg);
            } catch (IllegalArgumentException exception) {
                printerr(exception.getMessage());
                continue;
            }

            println("PATTERN=" + arg);
            int matches = 0;
            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) {
                    continue;
                }
                Address found = block.getStart();
                while (found != null &&
                       found.compareTo(block.getEnd()) <= 0 &&
                       !monitor.isCancelled()) {
                    found = memory.findBytes(
                        found, block.getEnd(), pattern, null, true, monitor);
                    if (found == null) {
                        break;
                    }

                    Instruction instruction =
                        currentProgram.getListing().getInstructionContaining(
                            found);
                    Function function = getFunctionContaining(found);
                    String functionText = function == null
                        ? "<none>"
                        : function.getEntryPoint() + " " + function.getName();
                    String instructionText = instruction == null
                        ? "<no instruction>"
                        : instruction.getAddress() + " | " + instruction;
                    println(found + " | " + instructionText +
                        " | function=" + functionText);
                    if (function != null) {
                        for (Reference reference :
                             getReferencesTo(function.getEntryPoint())) {
                            Function caller = getFunctionContaining(
                                reference.getFromAddress());
                            String callerText = caller == null
                                ? "<none>"
                                : caller.getEntryPoint() + " " +
                                    caller.getName();
                            println("  caller " +
                                reference.getFromAddress() + " | " +
                                callerText);
                        }
                    }
                    matches++;
                    found = found.add(1);
                }
            }
            println("TOTAL_MATCHES=" + matches);
        }
    }

    private byte[] parseHex(String text) {
        String clean = text.replaceAll("[^0-9a-fA-F]", "");
        if (clean.isEmpty()) {
            throw new IllegalArgumentException(
                "Byte pattern contains no hexadecimal digits: " + text);
        }
        if ((clean.length() & 1) != 0) {
            throw new IllegalArgumentException(
                "Byte pattern has an odd number of hexadecimal digits: " +
                text);
        }
        byte[] output = new byte[clean.length() / 2];
        for (int i = 0; i < output.length; i++) {
            output[i] = (byte) Integer.parseInt(
                clean.substring(i * 2, i * 2 + 2), 16);
        }
        return output;
    }
}
