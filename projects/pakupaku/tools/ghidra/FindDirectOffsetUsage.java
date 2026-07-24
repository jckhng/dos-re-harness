// Finds instructions whose rendered operands contain exact 16-bit direct
// offsets such as [0xbbc]. Ghidra's real-mode loader does not expose these
// operands as scalar or address-reference objects.
// @category PakuPaku

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

public class FindDirectOffsetUsage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr("usage: FindDirectOffsetUsage.java <0xoffset> [...]");
            return;
        }

        Set<String> targets = new LinkedHashSet<>();
        for (String arg : args) {
            targets.add(arg.toLowerCase(Locale.ROOT));
        }

        int matches = 0;
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            String rendered =
                instruction.toString().toLowerCase(Locale.ROOT);
            for (String target : targets) {
                if (!rendered.contains("[" + target + "]")) {
                    continue;
                }
                Function function = getFunctionContaining(
                    instruction.getAddress());
                String owner = function == null
                    ? "<no function>"
                    : function.getName() + " @ " + function.getEntryPoint();
                println(target + " | " + instruction.getAddress() + " | " +
                    instruction + " | " + owner);
                ++matches;
            }
        }
        println("TOTAL_MATCHES=" + matches);
    }
}
