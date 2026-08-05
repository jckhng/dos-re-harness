// Find MOVS/STOS instructions and print configurable surrounding context.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class FindBulkCopyPatterns extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 2) {
            printerr(
                "Usage: FindBulkCopyPatterns [instructions_before] " +
                "[instructions_after]");
            return;
        }

        int before = args.length >= 1 ? parseNonNegative(args[0]) : 6;
        int after = args.length >= 2 ? parseNonNegative(args[1]) : 3;
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(true);
        int matches = 0;
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            String mnemonic = instruction.getMnemonicString();
            if (!mnemonic.startsWith("MOVS") &&
                !mnemonic.startsWith("STOS")) {
                continue;
            }

            Address address = instruction.getAddress();
            Function function = getFunctionContaining(address);
            String functionName =
                function != null ? function.getName() : "<no function>";
            String functionEntry = function != null
                ? function.getEntryPoint().toString()
                : "<none>";
            println("PATTERN " + address + " | function=" + functionEntry +
                " " + functionName);

            Instruction cursor = instruction;
            for (int i = 0; i < before; i++) {
                cursor = cursor.getPrevious();
                if (cursor == null) {
                    break;
                }
                println("  prev " + cursor.getAddress() + " | " + cursor);
            }
            println("  here " + instruction.getAddress() + " | " +
                instruction);
            cursor = instruction;
            for (int i = 0; i < after; i++) {
                cursor = cursor.getNext();
                if (cursor == null) {
                    break;
                }
                println("  next " + cursor.getAddress() + " | " + cursor);
            }
            matches++;
        }
        println("TOTAL_MATCHES=" + matches);
    }

    private int parseNonNegative(String text) {
        int value = Integer.decode(text);
        if (value < 0) {
            throw new IllegalArgumentException(
                "Context counts must not be negative: " + text);
        }
        return value;
    }
}
