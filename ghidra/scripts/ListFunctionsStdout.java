// Print the discovered functions for the current program in headless mode.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ListFunctionsStdout extends GhidraScript {

    @Override
    protected void run() throws Exception {
        int count = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        for (Function function : functions) {
            println(function.getEntryPoint() + " " + function.getName());
            count++;
        }
        println("TOTAL_FUNCTIONS=" + count);
    }
}
