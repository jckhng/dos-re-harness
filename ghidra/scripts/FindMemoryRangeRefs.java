// Find instructions whose address operands reference a supplied memory range.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;

public class FindMemoryRangeRefs extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 && args.length != 3) {
            printerr("Usage: FindMemoryRangeRefs <start_addr> <end_addr> [--offset-candidates]");
            return;
        }
        boolean offsets = args.length == 3;
        if (offsets && !args[2].equals("--offset-candidates")) {
            throw new IllegalArgumentException("Unknown option: " + args[2]);
        }

        Address start = toAddr(args[0]);
        Address end = toAddr(args[1]);
        if (start == null || end == null ||
            !start.getAddressSpace().equals(end.getAddressSpace()) ||
            start.compareTo(end) > 0) {
            printerr("Invalid address range: " + args[0] + " " + args[1]);
            return;
        }
        // getOffset() is linear for segmented addresses; masking its low
        // word does not recover the operand displacement.
        long firstOffset = start instanceof SegmentedAddress first
            ? first.getSegmentOffset() : start.getOffset();
        long lastOffset = end instanceof SegmentedAddress last
            ? last.getSegmentOffset() : end.getOffset();
        if (offsets && start instanceof SegmentedAddress first &&
                end instanceof SegmentedAddress last && first.getSegment() != last.getSegment()) {
            throw new IllegalArgumentException("Offset candidate range must stay in one segment");
        }
        if (offsets && firstOffset > lastOffset) {
            throw new IllegalArgumentException("Offset range end precedes its start");
        }

        AddressSetView body = currentProgram.getMemory();
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(body, true);
        int matches = 0;
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            boolean matchedInstruction = false;
            for (int operand = 0;
                 operand < instruction.getNumOperands() && !matchedInstruction;
                 operand++) {
                if (!offsets && (instruction.getOperandType(operand) &
                    OperandType.ADDRESS) == 0) {
                    continue;
                }
                for (Object object : instruction.getOpObjects(operand)) {
                    if (offsets && object instanceof Scalar scalar &&
                            instruction.getDefaultOperandRepresentation(operand).contains("[") &&
                            scalar.getUnsignedValue() >= firstOffset && scalar.getUnsignedValue() <= lastOffset) {
                        println(instruction.getAddress() + " | " + instruction +
                            " | displacement_candidate=" + Long.toHexString(scalar.getUnsignedValue()) +
                            " | segment_not_proven=true");
                        matches++;
                        matchedInstruction = true;
                        break;
                    }
                    if (!(object instanceof Address reference) ||
                        !reference.getAddressSpace().equals(
                            start.getAddressSpace()) ||
                        reference.compareTo(start) < 0 ||
                        reference.compareTo(end) > 0) {
                        continue;
                    }

                    Function function =
                        getFunctionContaining(instruction.getAddress());
                    String functionName = function != null
                        ? function.getName()
                        : "<no function>";
                    String functionEntry = function != null
                        ? function.getEntryPoint().toString()
                        : "<none>";
                    println(instruction.getAddress() + " | " + instruction +
                        " | ref=" + reference + " | function=" +
                        functionEntry + " " + functionName);
                    matches++;
                    matchedInstruction = true;
                    break;
                }
            }
        }

        println("TOTAL_MATCHES=" + matches);
    }
}
