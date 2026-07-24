// Dump decompiled C for one or more functions by entry address.
// Headless usage:
//   -postScript DumpFunctionDecomp.java 16c8:39e4 16c8:3973

import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DumpFunctionDecomp extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: DumpFunctionDecomp <entry_addr> [entry_addr...]");
            return;
        }

        FunctionManager functionManager = currentProgram.getFunctionManager();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        try {
            for (String arg : args) {
                Address address = toAddr(arg);
                Function function = functionManager.getFunctionAt(address);
                if (function == null) {
                    function = functionManager.getFunctionContaining(address);
                }
                println("===== " + arg + " =====");
                if (function == null) {
                    println("No function at " + address);
                    continue;
                }

                println("Name: " + function.getName());
                println("Entry: " + function.getEntryPoint());
                DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
                if (!results.decompileCompleted()) {
                    println("Decompile failed: " + results.getErrorMessage());
                    continue;
                }

                println(results.getDecompiledFunction().getC());
            }
        } finally {
            decompiler.dispose();
        }
    }
}
