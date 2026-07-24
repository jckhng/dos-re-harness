// Lists all program files in the project.
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;

public class ListProgramsStdout extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DomainFolder root = state.getProject().getProjectData().getRootFolder();
        walk(root);
    }

    private void walk(DomainFolder folder) {
        for (DomainFile f : folder.getFiles()) {
            println("FILE " + f.getPathname() + " (" + f.getContentType() + ")");
        }
        for (DomainFolder sub : folder.getFolders()) {
            walk(sub);
        }
    }
}
