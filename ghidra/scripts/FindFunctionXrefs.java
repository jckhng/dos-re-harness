import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindFunctionXrefs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        for (String arg : getScriptArgs()) {
            Address target = currentProgram.getAddressFactory().getAddress(arg);
            if (target == null) {
                println("BAD_ADDRESS " + arg);
                continue;
            }
            println("===== XREFS_TO " + target + " =====");
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
            int count = 0;
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address from = ref.getFromAddress();
                var fn = currentProgram.getFunctionManager().getFunctionContaining(from);
                println(from + " " + ref.getReferenceType() + " " + (fn == null ? "<no-fn>" : fn.getName() + " " + fn.getEntryPoint()));
                count++;
            }
            println("TOTAL=" + count);
        }
    }
}
