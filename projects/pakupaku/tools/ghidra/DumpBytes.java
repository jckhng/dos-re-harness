// Prints a short private byte range as hexadecimal and printable ASCII.
// @category PakuPaku

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class DumpBytes extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Address address = toAddr(args[0]);
        int count = Integer.decode(args[1]);
        byte[] bytes = new byte[count];
        currentProgram.getMemory().getBytes(address, bytes);
        StringBuilder hex = new StringBuilder();
        StringBuilder text = new StringBuilder();
        for (byte value : bytes) {
            hex.append(String.format("%02x ", value & 0xff));
            int character = value & 0xff;
            text.append(character >= 32 && character < 127
                ? (char) character : '.');
        }
        println(address + " " + hex + " |" + text + "|");
    }
}
