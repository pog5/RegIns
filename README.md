# RegIns

[![AI Slop Inside](https://sladge.net/badge.svg)](https://sladge.net)

C#/.NET 11 offline registry hive inspection, salvage and reconstruction, with a CLI and Avalonia GUI. The recovery engine is managed code and uses no OS registry APIs. BCD is treated as an ordinary hive.

**Status: experimental recovery implementation, not completion of the full recovery roadmap.** Ordinary hive/log recovery and a frozen corruption corpus are implemented. TxR/CLFS replay and direct offline VSS store parsing are not implemented. See [support and limits](docs/support.md).

## Build and test

Install the SDK pinned in `global.json`, then:

```text
dotnet build RegIns.slnx -c Release
dotnet tests/RegIns.Tests/bin/Release/net11.0/RegIns.Tests.dll
dotnet tests/RegIns.Tests/bin/Release/net11.0/RegIns.Tests.dll --corpus tests/corpus corpus-report.json
```

On NixOS, use `nix develop` with flakes enabled. The shared library targets `net11.0`; a native shared object/C ABI is not provided.

## CLI

Examples below use a published `RegIns.Cli` executable. Framework-dependent execution is also supported with `dotnet RegIns.Cli.dll`.

```text
RegIns.Cli inspect /recovery/SYSTEM
RegIns.Cli discover /recovery/SYSTEM --snapshot-root /mnt/snapshot
RegIns.Cli recover /recovery/SYSTEM --out recovery-plan.json
RegIns.Cli export recovery-plan.json --out SYSTEM.recovered
RegIns.Cli validate SYSTEM.recovered
RegIns.Cli logs /recovery/SYSTEM.LOG2
RegIns.Cli recover /recovery/SYSTEM --log /recovery/SYSTEM.LOG2 --allow-unverified-association --out replay-plan.json
RegIns.Cli carve disk.raw --max-bytes 107374182400
RegIns.Cli snapshots
```

`recover` produces an inspectable JSON plan. `export` writes a new hive and a `.report.json` sidecar. Existing outputs are never overwritten. Review alternative roots, `ParentOverrides`, `IncludedSalvageOffsets`, findings and partial value extents before exporting. Explicitly selected orphan keys attach to the selected root if their parent is absent. Missing permissions require `--replace-missing-security`, which writes an empty DACL and reports the change; it does not silently grant access.

Exit statuses: `0` complete within implemented checks, `2` partial/dirty/invalid/limited, `1` operational failure, `130` cancellation. A successful internal structural check is not a Windows loadability guarantee.

A zero-byte or missing primary triggers adjacent-file and RegBack discovery. Supply `--snapshot-root` repeatedly for mounted/extracted snapshots or backup directories. Backups remain separate generations; the tool selects a candidate rather than splicing unrelated trees. Valid logs can supply a partial tree when the primary is absent, with untouched pages marked unreadable. Logs with damaged headers require explicit association and a valid primary before replay.

`snapshots` is an optional Windows host adapter using read-only CIM enumeration. It creates or mounts nothing. Its results can be supplied as snapshot roots. On Linux, supply already mounted/extracted snapshot directories. Failures to enumerate/access snapshots are errors, not reports that no snapshots exist.

Default limits are 1 GiB scanned, 250,000 records, 16 MiB per value, 256 MiB evidence, and 2,000,000 traversed references. The library exposes byte/record/value/evidence limits; the CLI exposes scan bytes and bin-origin overrides. Exceeding limits produces a partial result. Reports may contain recovered registry data: treat them like the source hive.

## Library

```csharp
using RegIns;

using var source = new FileByteSource("SYSTEM");
var inspection = new HiveInspector().Inspect(source, cancellationToken: token);
var plan = Recovery.Plan(inspection, token);
var output = HiveWriter.Export(plan, cancellationToken: token);
// Caller chooses a distinct output destination and persists output.Report.
```

`IByteSource` returns bytes plus per-byte readability. `SliceByteSource` handles embedded hives without copying. Evidence records retain original offsets and record bytes. Value `DataExtent` entries preserve logical offsets across holes. `TransactionLogs.Analyze` returns integrity-checked entries; `Replay` creates a separate overlay and never writes to the primary.

## GUI and packages

Run `dotnet run --project src/RegIns.Gui` or the published GUI. Open a hive, inspect candidates and evidence, select salvage, save a reviewable plan, and export. Add mounted backup/snapshot roots before opening an empty hive. Log analysis is available in the GUI; explicit multi-log replay currently uses the CLI/library. Native desktop dependencies are required on Linux; the CLI works without a desktop.

Run `scripts/publish.ps1` to produce self-contained Windows/Linux x64 CLI and GUI folders and the NuGet package under `artifacts/`.

## Frozen corruption corpus

`scripts/generate_corruption_corpus.py` independently constructs binary REGF data using Python `struct`, without importing or invoking RegIns. It writes corrupt files and expected outcomes first, then freezes them with a manifest hash. The test runner verifies all hashes before recovery. It does not regenerate fixtures or change expectations.

The corpus includes destroyed base/bin headers, zero/overflow/unaligned cell sizes, erased signatures, moved records, bad indexes and parent pointers, readable zeroes, unreadable holes, truncation, explosive counts, cycles, empty inputs, RegBack fallback and multiple embedded hives. Missing evidence has explicit expected loss; no test asserts recovery of bytes that no longer exist anywhere.

Windows native-load scripts under `scripts/` are **test oracles only**, operate on copies, and are not referenced by production projects. Never confuse application-hive loading with the normal system-hive loader: their permission restrictions differ.
