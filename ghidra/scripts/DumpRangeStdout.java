// Dump a memory range as bytes and little-endian 16-bit words.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class DumpRangeStdout extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2 || args.length > 3) {
            printerr("Usage: DumpRangeStdout <start_addr> <length> [stride]");
            return;
        }

        Address start = toAddr(args[0]);
        int length = parseInteger(args[1]);
        int stride = args.length == 3 ? parseInteger(args[2]) : 16;
        if (start == null || length <= 0 || stride <= 0) {
            printerr("Start must be valid; length and stride must be positive");
            return;
        }

        Memory memory = currentProgram.getMemory();
        if (!memory.contains(start)) {
            printerr("Start address is outside loaded memory: " + start);
            return;
        }

        byte[] data = new byte[length];
        int bytesRead = memory.getBytes(start, data);
        println("START=" + start);
        println("LENGTH_REQUESTED=" + length);
        println("LENGTH_READ=" + bytesRead);

        for (int base = 0; base < bytesRead; base += stride) {
            StringBuilder hex = new StringBuilder();
            StringBuilder words = new StringBuilder();
            int lineLength = Math.min(stride, bytesRead - base);
            for (int i = 0; i < lineLength; i++) {
                if (i != 0) {
                    hex.append(' ');
                }
                hex.append(String.format("%02x", data[base + i] & 0xff));
            }
            for (int i = 0; i + 1 < lineLength; i += 2) {
                if (words.length() != 0) {
                    words.append(' ');
                }
                int word = (data[base + i] & 0xff) |
                    ((data[base + i + 1] & 0xff) << 8);
                words.append(String.format("%04x", word));
            }
            println(String.format(
                "%s +%04x: %s | %s",
                start, base, hex.toString(), words.toString()));
        }
    }

    private int parseInteger(String text) {
        if (text.startsWith("0x") || text.startsWith("0X")) {
            return Integer.parseInt(text.substring(2), 16);
        }
        return Integer.parseInt(text);
    }
}
