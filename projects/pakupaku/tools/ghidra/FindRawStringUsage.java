// Finds raw ASCII terms and references to their addresses.
// @category PakuPaku

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;

import java.nio.charset.StandardCharsets;

public class FindRawStringUsage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        for (String term : getScriptArgs()) {
            byte[] pattern = term.getBytes(StandardCharsets.US_ASCII);
            Address found = memory.getMinAddress();
            while (found != null && !monitor.isCancelled()) {
                found = memory.findBytes(found, pattern, null, true, monitor);
                if (found == null) {
                    break;
                }
                println(found + " \"" + term + "\"");
                for (Reference reference : getReferencesTo(found)) {
                    println("  " + reference.getFromAddress() + " " +
                        reference.getReferenceType());
                }
                found = found.add(1);
            }
        }
    }
}
