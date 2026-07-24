// Dump instructions in an address range.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class DumpInstructions extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Usage: DumpInstructions <start> <end>");
            return;
        }
        Address start = currentProgram.getAddressFactory().getAddress(args[0]);
        Address end = currentProgram.getAddressFactory().getAddress(args[1]);
        Instruction instruction = getInstructionAt(start);
        if (instruction == null) {
            instruction = getInstructionAfter(start);
        }
        while (instruction != null && instruction.getAddress().compareTo(end) <= 0) {
            Function function = getFunctionContaining(instruction.getAddress());
            String funcText = function == null ? "<none>" : function.getEntryPoint() + " " + function.getName();
            println(instruction.getAddress() + " | " + instruction + " | function=" + funcText);
            instruction = instruction.getNext();
        }
    }
}
