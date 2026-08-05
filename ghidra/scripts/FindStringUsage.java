// Find defined strings containing supplied case-insensitive terms.

import java.util.Locale;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Reference;

public class FindStringUsage extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            printerr("Usage: FindStringUsage <term> [<term> ...]");
            return;
        }

        String[] terms = new String[args.length];
        for (int i = 0; i < args.length; i++) {
            if (args[i].isEmpty()) {
                printerr("Search terms must not be empty");
                return;
            }
            terms[i] = args[i].toLowerCase(Locale.ROOT);
        }

        int matches = 0;
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && !monitor.isCancelled()) {
            Data item = data.next();
            if (!item.hasStringValue()) {
                continue;
            }
            String value = item.getValue().toString();
            String normalizedValue = value.toLowerCase(Locale.ROOT);
            for (int i = 0; i < terms.length; i++) {
                if (!normalizedValue.contains(terms[i])) {
                    continue;
                }
                println(item.getAddress() + " \"" + value +
                    "\" | term=" + args[i]);
                for (Reference reference :
                     getReferencesTo(item.getAddress())) {
                    println("  " + reference.getFromAddress() + " " +
                        reference.getReferenceType());
                }
                matches++;
                break;
            }
        }
        println("TOTAL_MATCHES=" + matches);
    }
}
