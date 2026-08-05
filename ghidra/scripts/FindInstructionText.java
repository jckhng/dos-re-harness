// Find instructions whose rendered text contains one or more patterns.

import java.util.Locale;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class FindInstructionText extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr("Usage: FindInstructionText <pattern> [<pattern> ...]");
            return;
        }

        String[] patterns = new String[args.length];
        for (int i = 0; i < args.length; i++) {
            if (args[i].isEmpty()) {
                printerr("Patterns must not be empty");
                return;
            }
            patterns[i] = args[i].toLowerCase(Locale.ROOT);
        }

        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(true);
        int matches = 0;
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            String text = instruction.toString().toLowerCase(Locale.ROOT);
            for (int i = 0; i < patterns.length; i++) {
                if (!text.contains(patterns[i])) {
                    continue;
                }

                Function function =
                    getFunctionContaining(instruction.getAddress());
                String functionEntry = function != null
                    ? function.getEntryPoint().toString()
                    : "<none>";
                String functionName =
                    function != null ? function.getName() : "<no function>";
                println(instruction.getAddress() + " | " + instruction +
                    " | function=" + functionEntry + " " + functionName +
                    " | pattern=" + args[i]);
                matches++;
                break;
            }
        }
        println("TOTAL_MATCHES=" + matches);
    }
}
