// Find instructions that reference one or more scalar immediate values.

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class FindScalarUsage extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: FindScalarUsage <value> [<value> ...]");
            println("Example: FindScalarUsage 0x0e5 0x09a 0x09b 0x09d");
            return;
        }

        Set<Long> targets = new LinkedHashSet<>();
        for (String arg : args) {
            targets.add(Long.decode(arg));
        }

        println("Target scalar values: " + targets);

        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        int matchCount = 0;
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            List<Long> matches = new ArrayList<>();
            for (int opIndex = 0; opIndex < instruction.getNumOperands(); opIndex++) {
                Scalar scalar = instruction.getScalar(opIndex);
                if (scalar == null) {
                    continue;
                }
                long unsignedValue = scalar.getUnsignedValue();
                if (targets.contains(unsignedValue)) {
                    matches.add(unsignedValue);
                }
            }

            if (!matches.isEmpty()) {
                Address address = instruction.getAddress();
                Function function = getFunctionContaining(address);
                String functionName = function != null ? function.getName() : "<no function>";
                String functionEntry = function != null ? function.getEntryPoint().toString() : "<none>";
                println(address + " | " + instruction + " | function=" + functionEntry + " " + functionName + " | matches=" + matches);
                matchCount++;
            }
        }

        println("TOTAL_MATCHES=" + matchCount);
    }
}
