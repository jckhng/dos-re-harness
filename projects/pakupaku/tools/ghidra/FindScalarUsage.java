// Finds instructions containing an exact scalar operand.
// @category PakuPaku

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class FindScalarUsage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            printerr("usage: FindScalarUsage.java <integer>");
            return;
        }
        long target = Long.decode(args[0]);
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            boolean matched = false;
            for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                for (Object object : instruction.getOpObjects(operand)) {
                    if (object instanceof Scalar &&
                        ((Scalar) object).getUnsignedValue() == target) {
                        matched = true;
                    }
                }
            }
            if (matched) {
                Address address = instruction.getAddress();
                println(address + " " + instruction);
            }
        }
    }
}
