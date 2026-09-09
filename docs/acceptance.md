# Acceptance results — 2026-09-08

## Frozen corruption data

29 binary cases were generated with an independent Python builder **before** testing RegIns against them. The manifest was frozen at SHA-256:

```text
433357be51830e8ece6a2fea9bfe9e6e6d7d6a7c0d3e6020bd2bfa7723b2a6a3
```

The initial recovery run missed a key whose `nk` signature had been erased. Reference-based recognition was added, preserving the actual damaged evidence bytes. An inverted zero-byte assertion and cross-platform manifest path handling were corrected in the runner. The fixture bytes, manifest and expected recovery outcomes were not changed. All 29 cases subsequently passed on Windows and NixOS WSL.

The separate behavioral suite contains 18 checks, including 100 deterministic malformed-noise inputs, independent Marvin vectors, transaction integrity/order tests, data holes, resource limits, cancellation, I/O page failures, and empty-primary RegBack discovery. It passes on Windows and Linux.

These tests verify specified recoverable content and preservation of known loss. They do not prove arbitrary-corruption recovery or recovery of overwritten information.

## Supplied SYSTEM and companions

The six original files remain unchanged, verified against SHA-256 hashes recorded before testing. The input directory is excluded from source control.

- SYSTEM: 21,495,808 bytes; header checksum valid, sequence numbers dirty.
- SYSTEM.LOG1: zero bytes.
- SYSTEM.LOG2: header zeroed, but one independently integrity-checked HvLE entry was recovered at file offset 1,667,072, sequence 105746.
- Three TxR/CLFS companion artifacts were discovered; decoding/replay is unsupported.

RegIns generated `artifacts/acceptance/SYSTEM.restored` with **65,885 keys and 124,427 values**. It replayed the explicitly associated headerless log entry and rebuilt the hive. An independent python-registry reader traversed the result. Logical key/value digests matched the original. Security/class/timestamp digests matched a separately constructed Python log overlay, establishing that the metadata change came from the transaction, not an unexplained writer change.

Windows and Linux exports of the selected plan are byte-identical, SHA-256 `c8d399e42e6270ee6cb8ddecd300e77484016c422490ba861f54ab0d7036f45d`.

The independent logical digest is:

```text
91515eacfd76ce8b63c946f260a91473f2b90b3c6608cd7c5f8c65616824a3d9
```

The post-transaction security/class/timestamp digest is:

```text
82f6fcc7f1beec88374db14152ce1c6dde1bdddba28e9facf700437361006b21
```

## Windows load acceptance remains unresolved

The original and preserved-permission reconstruction return error 1009 through `RegLoadAppKey`. A diagnostic reconstruction with uniform security descriptors loads through that API, as does a synthetic control. The uniform-security file is **not** the recovery deliverable: replacing permissions would invalidate the preservation claim. Application-hive permission restrictions mean this result alone cannot establish system-hive validity.

The ordinary `reg load` attempt initially lacked privileges. Subsequent elevated oracle attempts also failed on the clean synthetic control (`reg.exe` reported a filename-length error; direct system-load attempts reported privilege/parameter errors). This normal-loader test setup is therefore not a valid discriminator for the supplied hive. No normal Windows load success or bootability is claimed.

**The supplied hive acceptance criterion is not yet satisfied.** The output is a recovery candidate with independently verified logical content, not a certified deployable SYSTEM hive.

## Distribution and UI

NuGet and self-contained Windows/Linux x64 CLI/GUI folders are generated under `artifacts/`. CLI execution was checked on Windows and Linux. Windows GUI interaction testing used native keyboard/mouse automation: open the erased-key-signature fixture, expand its tree, inspect and rename Beta, save/reopen a plan, and export a hive. The exported hive passed CLI validation and independent python-registry traversal, including the renamed key and its 128-byte value. Outputs are under `artifacts/gui-tests/`.

The supplied SYSTEM opened in the GUI with 65,885 keys and its root expanded successfully. Loading a zero-byte fixture after it reproduced a stale-tree bug; the GUI now clears the previous selection/tree before handling an empty candidate list. This was retested after rebuilding. Tree placement also now respects recovered parent overrides; the broken-parent fixture displays Beta beneath ROOT. Both Windows and Linux GUI distributions were rebuilt. All 18 behavior tests and 29 frozen corpus cases passed again; all six supplied input hashes remain unchanged.

This is bounded Windows interaction QA, not exhaustive UI acceptance. Linux GUI execution, cancellation under UI load, every toolbar operation, and large-hive editing/export through the GUI remain unverified. The large tree currently creates controls eagerly and used roughly 1.4 GB working memory during this test; lazy tree population remains a performance improvement.

Windows host VSS enumeration is implemented as an optional adapter. On this host CIM returned initialization error `0x80041014`; no claim of successful live snapshot discovery is made. Mounted/extracted snapshot-root search is covered by tests. Raw offline VSS stores and TxR/CLFS transactions remain roadmap work.
