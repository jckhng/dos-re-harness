// Finds defined strings containing any supplied case-insensitive term.
// @category PakuPaku

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Reference;

public class FindStringUsage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] terms = getScriptArgs();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && !monitor.isCancelled()) {
            Data item = data.next();
            if (!item.hasStringValue()) {
                continue;
            }
            String value = item.getValue().toString();
            for (String term : terms) {
                if (!value.toLowerCase().contains(term.toLowerCase())) {
                    continue;
                }
                println(item.getAddress() + " " + value);
                for (Reference reference : getReferencesTo(item.getAddress())) {
                    println("  " + reference.getFromAddress() + " " +
                        reference.getReferenceType());
                }
                break;
            }
        }
    }
}
