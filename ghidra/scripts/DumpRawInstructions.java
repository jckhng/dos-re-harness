// Bounded pseudo-disassembly without modifying stored instructions or functions.
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;

public class DumpRawInstructions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Usage: start end (inclusive, at most 4096 bytes)");
        }
        Address cursor = toAddr(args[0]);
        Address end = toAddr(args[1]);
        if (cursor == null || end == null ||
                !cursor.getAddressSpace().equals(end.getAddressSpace()) ||
                cursor.compareTo(end) > 0 || end.subtract(cursor) >= 4096) {
            throw new IllegalArgumentException("Expected one ordered address-space range of at most 4096 bytes");
        }
        PseudoDisassembler decoder = new PseudoDisassembler(currentProgram);
        while (cursor.compareTo(end) <= 0) {
            monitor.checkCancelled();
            PseudoInstruction instruction = decoder.disassemble(cursor);
            if (instruction == null || instruction.getLength() <= 0) {
                throw new IllegalStateException("Cannot decode " + cursor);
            }
            Address last = cursor.add(instruction.getLength() - 1);
            if (last.compareTo(end) > 0) {
                throw new IllegalArgumentException("Range ends inside instruction at " + cursor);
            }
            println(cursor + " | " + instruction);
            if (last.equals(end)) break;
            cursor = last.add(1);
        }
    }
}
