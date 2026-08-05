// Find raw ASCII strings in initialized memory and list direct references.

import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class FindRawStringUsage extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] terms = getScriptArgs();
        if (terms.length == 0) {
            printerr("Usage: FindRawStringUsage <ASCII_term> [<ASCII_term> ...]");
            return;
        }

        Memory memory = currentProgram.getMemory();
        for (String term : terms) {
            if (term.isEmpty() || !isAscii(term)) {
                printerr("Search terms must be non-empty ASCII: " + term);
                continue;
            }

            byte[] pattern = term.getBytes(StandardCharsets.US_ASCII);
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
                    println(found + " \"" + term + "\"");
                    for (Reference reference : getReferencesTo(found)) {
                        println("  " + reference.getFromAddress() + " " +
                            reference.getReferenceType());
                    }
                    matches++;
                    found = found.add(1);
                }
            }
            println("TERM=" + term + " TOTAL_MATCHES=" + matches);
        }
    }

    private boolean isAscii(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) > 0x7f) {
                return false;
            }
        }
        return true;
    }
}
