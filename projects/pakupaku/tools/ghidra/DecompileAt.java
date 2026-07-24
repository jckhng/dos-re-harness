// Decompiles the function containing each supplied address.
// @category PakuPaku

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;

public class DecompileAt extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        for (String text : getScriptArgs()) {
            Address address = toAddr(text);
            Function function =
                currentProgram.getFunctionManager().getFunctionContaining(address);
            if (function == null) {
                printerr(text + ": no containing function");
                continue;
            }
            println("=== " + function.getName() + " @ " +
                function.getEntryPoint() + " (contains " + address + ") ===");
            println("callers:");
            for (Reference reference :
                    getReferencesTo(function.getEntryPoint())) {
                println("  " + reference.getFromAddress() + " " +
                    reference.getReferenceType());
            }
            DecompileResults result =
                decompiler.decompileFunction(function, 60, monitor);
            if (!result.decompileCompleted()) {
                printerr(result.getErrorMessage());
                continue;
            }
            println(result.getDecompiledFunction().getC());
        }
        decompiler.dispose();
    }
}
