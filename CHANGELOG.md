# Changelog

All notable changes to this project are documented in this file and on the [GitHub Releases](https://github.com/cawalch/node-yara-x/releases) page.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- See docs/release-process.md for how this section is promoted. -->

### Added
- **Five more YARA-X modules**: `zip`, `lnk`, `dex`, `crx` and `cuckoo` are now compiled in, so rules importing them compile instead of failing with `error[E010]: unknown module`. Together they cost ~383 KB in the linked binary; `vt` stays out because the public-suffix list it needs is ~1.2 MB on its own.
- **Bun and Deno** are documented as supported — they load the same prebuilt binary through Node-API — and CI now runs a smoke test under both.

---

## [0.12.0] - 2026-10-31

### Added
- **XOR key reporting**: `MatchData.xorKey` carries the XOR key that produced a match for patterns compiled with an `xor` modifier, so an obfuscated sample can be decoded without a second scan. Populated by `scan()`, `scanFile()`, the async scan APIs, and the batch/directory scanners; absent for plain patterns.
- **`BinaryMatchView.getXorKey(index)`**: reads the same key from the binary match ABI. It rides in the existing `flags` word (bits 0-7 hold the key, bit 8 marks its presence), so the 24-byte record layout is unchanged, and `toRuleMatches()` fills `MatchData.xorKey` from it.

### Changed
- Pinned the `npm` CLI used by the publish job to an exact version (`11.21.1`) instead of the `^11.5.1` range, so the toolchain holding the publishing credentials cannot change without review.
- **YARA-X moved from 1.21.0 to 1.22.1**, which brings the `int64`/`int64be`/`uint64`/`uint64be` built-ins and `pe.offset_to_rva` to rule authors. Rule blobs serialized by 0.11.0 or earlier were compiled by 1.21.x and must be recompiled before they can be deserialized.

---

## [0.11.0] - 2026-10-25

### Added
- **Compiled Rules Introspection**:
  - `scanner.ruleCount`: Getter returning the total count of compiled rules.
  - `scanner.getImports()`: Returns an array of imported YARA-X module names (`"pe"`, `"math"`, etc.).
  - `scanner.getRules()`: Returns structured metadata (`RuleInfo[]`) including `identifier`, `namespace`, `tags`, and `patterns`.
  - Introspection data is fully preserved across `serialize()` and `deserialize()`.
- **Scanner `maxScanSize` Protection**:
  - `scanner.setMaxScanSize(maxBytes: number)`: Enforces an upper bound on bytes scanned per buffer or file, guarding against memory and processing exhaustion on oversized inputs.
  - `TaskScanOptions.maxScanSize`: Integrated into async buffer and file scanning tasks.
- **Directory Traversal File Size Filtering**:
  - `BatchScanOptions.minFileSize`: Filters out files below the specified byte size during native traversal.
  - `BatchScanOptions.maxFileSize`: Filters out files exceeding the specified byte size during native traversal.
- **`BinaryMatchView` Lazy Materialization**:
  - `BinaryMatchView.prototype.toRuleMatches(source?: Buffer): RuleMatch[]`: Reconstructs standard `RuleMatch` objects directly from the compact binary match buffer, allowing consumers to scan using the binary ABI and lazily unpack match objects on demand.

### Performance
- **Direct Binary Packing**:
  - Elimination of intermediate `Vec<FlatMatchRecord>` allocation in the binary scanning engine, packing directly into napi `Uint8Array` memory buffers.
- **Batch Scanning Zero-Copy Path Consumption**:
  - Shifted batch file list processing to move strings into worker threads without redundant cloning.
- **$O(1)$ Compiler Error Deduplication**:
  - Replaced linear search with `HashSet<(usize, usize)>` during compilation error deduplication in tolerant mode.

---

## [0.10.0] - 2026-10-19

### Added
- **Native Multi-Threaded Batch and Directory Scanning**:
  - `scanner.scanFiles(paths, options?, variables?)` and `scanner.scanFilesSync(...)`: Parallel file scanning across a native Rayon work-stealing pool.
  - `scanner.scanDirectory(dirPath, options?, variables?)` and `scanner.scanDirectorySync(...)`: Native recursive directory traversal with glob pattern filtering (`includePatterns`, `excludePatterns`) and `maxDepth` limits.
- **Flat / Binary Match ABI**:
  - High-throughput binary match scanning (`scanBinary`, `scanFileBinary`, `scanBinaryAsync`, `scanFileBinaryAsync`) returning a zero-copy `BinaryMatchView`.

---

## [0.8.0] - 2026-10-18

### Fixed
- Fixed missing license files in published `@litko/yara-x` and platform tarballs.
- Dual licensing (`MIT AND BSD-3-Clause`) explicitly declared in package metadata.

### Added
- Platform support matrix, troubleshooting guides, and Sigstore / GitHub attestation verification instructions.
- Benchmarking baseline suite (`pnpm profile:baseline`, `pnpm profile:compare`).
