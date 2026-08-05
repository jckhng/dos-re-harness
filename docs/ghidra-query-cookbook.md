# Ghidra Query Cookbook

`scripts/ghidra-query.ps1` runs repeatable, headless queries against an
existing Ghidra project. All query inputs are supplied by the caller; the
scripts contain no target-specific addresses or signatures.

## Common invocation

```powershell
$common = @{
    GhidraHeadless = "C:\tools\ghidra\support\analyzeHeadless.bat"
    ProjectDir = "C:\analysis\projects"
    ProjectName = "game"
    Program = "GAME.EXE"
    NoAnalysis = $true
}

.\scripts\ghidra-query.ps1 @common `
    -Query scalar `
    -Args 0x3c8, 0x3c9 `
    -OutputPath .\evidence\palette-ports.txt
```

Use a distinct `-TempRoot` for concurrent runs. Ghidra projects are
single-writer resources, so do not run queries concurrently against the same
project. `-OutputPath` refuses to overwrite existing evidence and leaves a
`.partial` file when the query fails.

## Query selection

| Query | Arguments | Use |
| --- | --- | --- |
| `decompile` | function address | Decompile one function |
| `instructions` | start address, end address | Dump disassembly with function ownership |
| `xrefs` | one or more addresses | List references to addresses |
| `functions` | none | Inventory functions |
| `programs` | none | Inventory project programs |
| `scalar` | one or more numeric values | Find decoded immediate operands |
| `instruction-text` | one or more text fragments | Search rendered instruction text |
| `memory-range-refs` | start address, end address | Find decoded address operands in a range |
| `bytes-and-callers` | one or more hexadecimal byte strings | Find signatures and callers of containing functions |
| `bulk-copy` | optional before and after counts | Find `MOVS`/`STOS` sites with context |
| `dump-range` | start address, length, optional stride | Dump bytes and little-endian words |
| `direct-offset` | one or more numeric offsets | Find rendered direct-offset operands |
| `raw-string` | one or more ASCII terms | Find byte strings whether or not Ghidra defined them |
| `defined-string` | one or more terms | Find Ghidra-defined strings and references |
| `custom` | script-specific | Run a project adapter supplied with `-CustomScript` and `-AdditionalScriptPath` |

## Search escalation

Use the most structured query first:

1. Use `xrefs`, `memory-range-refs`, and `scalar` when Ghidra exposes typed
   operands and references.
2. Use `direct-offset` when a real-mode loader renders an address such as
   `[0xbbc]` but does not expose an address or scalar object.
3. Use `instruction-text` as a broader fallback for syntax fragments.
4. Use `defined-string` first for analyzed data, then `raw-string` when the
   bytes were not defined as a string.
5. Use `bytes-and-callers` for stable machine-code or data signatures.

Text-rendering queries depend on Ghidra's processor language and display
syntax. Treat them as discovery tools, then confirm results with disassembly,
decompilation, references, and runtime evidence.

## Examples

```powershell
# Find decoded writes involving VGA DAC ports.
.\scripts\ghidra-query.ps1 @common -Query scalar -Args 0x3c8,0x3c9

# Find references into a caller-supplied data range.
.\scripts\ghidra-query.ps1 @common -Query memory-range-refs `
    -Args "1000:0200","1000:02ff"

# Search for two byte signatures.
.\scripts\ghidra-query.ps1 @common -Query bytes-and-callers `
    -Args "f3 a5","ba d4 03"

# Inspect bulk memory operations with eight instructions before and four after.
.\scripts\ghidra-query.ps1 @common -Query bulk-copy -Args 8,4

# Find a raw message omitted by auto-analysis.
.\scripts\ghidra-query.ps1 @common -Query raw-string -Args "GAME OVER"
```
