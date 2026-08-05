// Find rendered instructions containing exact direct-offset operands.
//
// This is useful for formats and loaders that render offsets such as [0xbbc]
// without exposing them as scalar or address-reference operand objects.

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class FindDirectOffsetUsage extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr(
                "Usage: FindDirectOffsetUsage <numeric_offset> " +
                "[<numeric_offset> ...]");
            return;
        }

        Map<String, String> targets = new LinkedHashMap<>();
        for (String arg : args) {
            long value;
            try {
                value = Long.decode(arg);
            } catch (NumberFormatException exception) {
                printerr("Invalid numeric offset: " + arg);
                continue;
            }
            if (value < 0) {
                printerr("Offsets must not be negative: " + arg);
                continue;
            }
            targets.put(
                "[0x" + Long.toHexString(value).toLowerCase(Locale.ROOT) + "]",
                arg);
        }
        if (targets.isEmpty()) {
            return;
        }

        int matches = 0;
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            String rendered =
                instruction.toString().toLowerCase(Locale.ROOT);
            for (Map.Entry<String, String> target : targets.entrySet()) {
                if (!rendered.contains(target.getKey())) {
                    continue;
                }
                Function function =
                    getFunctionContaining(instruction.getAddress());
                String owner = function == null
                    ? "<no function>"
                    : function.getName() + " @ " +
                        function.getEntryPoint();
                println(target.getValue() + " | " +
                    instruction.getAddress() + " | " + instruction +
                    " | " + owner);
                matches++;
                break;
            }
        }
        println("TOTAL_MATCHES=" + matches);
    }
}
