# Implemented support and remaining work

| Area | Implemented | Limitations |
|---|---|---|
| REGF | Base metadata, bins, allocation ownership, nk/vk records, li/lf/lh/ri indexes, security/class data, inline/direct/segmented values | Version 1.5 independently exercised; 1.1–1.6 layouts recognized but legacy variants lack representative acceptance fixtures; layered-key semantics not implemented |
| Corruption | Independent scanning, damaged cell sizes, signature recovery through incoming references, parent reconstruction, partial readable data extents, orphan/deleted evidence | Cannot associate arbitrary moved signatureless payloads without surviving references; invalid/missing names are not invented |
| Writer | New bins/cells, indexes, security deduplication/reference counts, classes, values, segmented data, checksums; internal reparse | Windows loadability must be checked separately; not byte-for-byte archival serialization; access/debug/layered metadata not fully preserved |
| DIRT logs | Bitmap/page extraction, compatible selected-history overlay | No per-page checksum exists; synthetic tests only; no self-healing reconstruction of missing bitmap/header |
| HvLE logs | Sector scan independent of header, both Marvin hashes, bounded page references, sequence checks, isolated replay | Duplicate sequences require manual history selection; no combinatorial branch enumeration; dirty-bin self-healing not implemented |
| TxR/CLFS | Companion artifact discovery and explicit unsupported diagnostics | Container parsing, transaction decoding, commit/rollback reconstruction and replay are not implemented |
| Empty primary | Adjacent logs, RegBack, supplied snapshot/backup roots, log-only sparse reconstruction | Backups do not prove temporal compatibility; partial primary trees are not automatically merged with backups |
| Raw images | Misaligned hive and bin carving; source slices; record scanning with explicit bin origin | No filesystem reconstruction, physical disk acquisition, automated fragment association or VSS container reconstruction |
| VSS | Optional read-only host CIM enumeration; mounted/extracted root search | Windows permissions/services may block enumeration; Linux needs externally exposed snapshots |
| GUI | Inspection, candidate counts/selection, evidence, rename, explicit salvage inclusion, plan persistence, carving, log analysis and export | Multi-log replay and detailed history comparison use CLI/library; large trees are not yet paged |

## Provenance and outcome semantics

Original artifacts are read-only. Integrity-checked log entries can still belong to another hive: association and integrity are separate checks. The explicit association override is recorded by CLI recovery. Zero-filled input is not automatically classified as unreadable. Unknown or incomplete values remain evidence and are omitted from canonical output, with diagnostics.

Confidence labels are qualitative. `StructuralValidationPassed` currently means internal reparse and count/value-completeness checks, not independent certification. A parser accepting a hive, Windows loading it, and Windows successfully booting with it are distinct acceptance criteria.

## Follow-up priorities

1. Resolve normal Windows native-load acceptance with original security descriptors on the supplied SYSTEM case; do not replace ACLs to claim success.
2. Add independently sourced legacy and transaction-history fixtures, stronger writer metadata validation, and broader false-positive measurements.
3. Implement TxR/CLFS using separately validated container and transaction layers.
4. Extend offline VSS discovery and multi-generation recovery selection without mixing uncertain histories.
5. Page GUI trees, expose detailed history comparison and recovery-rule overrides, and validate full GUI workflows on Windows and Linux desktops.

Format references: [Maxim Suhanov's REGF specification](https://github.com/msuhanov/regf), [libregf format documentation](https://github.com/libyal/libregf/tree/main/documentation), and [Microsoft RegLoadAppKey documentation](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeyw). The independent acceptance reader is python-registry 1.3.1; it is a test dependency only.
