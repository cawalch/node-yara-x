# API reference

Signatures and options for `@litko/yara-x`. [`index.d.ts`](../index.d.ts) is the authoritative
reference — it is what TypeScript resolves when you import the package — and this page mirrors it.
The README's [API](../README.md#api) section lists the same surface grouped by task.

## Functions

| Function | Description |
| :--- | :--- |
| `compile(ruleSource, options?)` | Compiles rules from a string and returns a `YaraX` scanner. |
| `fromFile(rulePath, options?)` | Compiles rules from a file and returns a `YaraX` scanner. |
| `create()` | Returns an empty `YaraX` scanner for incremental compilation. |
| `deserialize(data)` | Restores a `YaraX` scanner from a serialized `Buffer`. |
| `validate(ruleSource, options?)` | Validates rules without creating a scanner. |
| `rulesFormatInfo()` | Returns `RulesFormatInfo`: the serialized-blob format version and the versions that produce it. |
| `compileToWasm(ruleSource, outputPath, options?)` | Writes the WebAssembly condition module for a rule string. |
| `compileFileToWasm(rulesPath, outputPath, options?)` | Writes the WebAssembly condition module for a rule file. |

## YaraX methods

| Method / Property | Description |
| :--- | :--- |
| `ruleCount` | Total number of compiled rules (`number`). |
| `getImports()` | Imported YARA-X module names (`string[]`). |
| `getRules()` | `RuleInfo[]` metadata for every compiled rule. |
| `scan(data, variables?)` | Scans a `Buffer` synchronously; returns the matching rules. |
| `scanFile(filePath, variables?)` | Scans a file synchronously. |
| `scanAsync(data, variables?, signal?)` | Scans a `Buffer` on a worker thread. |
| `scanFileAsync(filePath, variables?, signal?)` | Scans a file on a worker thread. |
| `scanBinary(data, variables?)` | Scans a `Buffer` with the binary match ABI; returns `BinaryScanResult`. |
| `scanFileBinary(filePath, variables?)` | Scans a file with the binary match ABI; returns `BinaryScanResult`. |
| `scanBinaryAsync(data, variables?, signal?)` | Scans a `Buffer` asynchronously; resolves to `BinaryScanResult`. |
| `scanFileBinaryAsync(filePath, variables?, signal?)` | Scans a file asynchronously; resolves to `BinaryScanResult`. |
| `isMatch(data, variables?)` | Boolean match test on a `Buffer`; allocates no match objects. |
| `isFileMatch(filePath, variables?)` | Boolean match test on a file. |
| `isMatchAsync(data, variables?, signal?)` | Boolean match test on a `Buffer`, on a worker thread. |
| `isFileMatchAsync(filePath, variables?, signal?)` | Boolean match test on a file, on a worker thread. |
| `scanFiles(filePaths, options?, variables?, signal?)` | Scans paths in parallel across a Rayon pool; resolves to `BatchScanResult`. |
| `scanFilesSync(filePaths, options?, variables?)` | Same, synchronously. |
| `scanDirectory(dirPath, options?, variables?, signal?)` | Recursively scans a directory in parallel with native traversal. |
| `scanDirectorySync(dirPath, options?, variables?)` | Same, synchronously. |
| `serialize()` | Serializes compiled rules into a portable `Buffer`. |
| `addRuleSource(ruleSource, namespace?)` | Adds one rule source to an incremental scanner. |
| `addRuleSources(ruleSources)` | Adds several sources as one batch; a source may reference a rule defined by an earlier source in the batch. |
| `addRuleFile(filePath, namespace?)` | Adds rules from a file to an incremental scanner. |
| `defineVariable(name, value)` | Defines a global (`string`, `number`, `boolean`, or `bigint`). A name YARA-X rejects throws here; how the rules read the value is checked on the next read. |
| `getWarnings()` | Compiler warnings from the last compilation. |
| `getIgnoredRules()` | Rules skipped by tolerant compilation or ignored modules. |
| `getCompilationErrors()` | Source-level errors collected when `ignoreInvalidRules` is set. |
| `setMaxMatchesPerPattern(maxMatches)` | Caps the matches collected per pattern. |
| `setMaxScanSize(maxBytes)` | Caps the bytes scanned per buffer or file. |
| `setFastScan(fastScan)` | Stops pattern search at the first match. |
| `setUseMmap(useMmap)` | Turns memory-mapped file scanning on or off. |
| `setTimeout(timeoutMs)` | Sets the best-effort scan timeout in milliseconds (`0` disables it). |
| `setMatchContextSize(size)` | Sets how many context bytes each match returns. |
| `setConsoleLog(callback?)` | Routes `console` module messages from rules to a callback. |
| `getSlowestRules(n)` | The slowest rules so far as `RuleProfile[]`, with pattern and condition timings. |
| `clearProfilingData()` | Discards the accumulated per-rule timings. |
| `emitWasmFile(outputPath)` | Writes the WebAssembly condition module synchronously. |
| `emitWasmFileAsync(outputPath)` | Writes the WebAssembly condition module asynchronously. |

### Cancellation

The `signal` argument on the async scan methods is an `AbortSignal`. Wherever it fires before the work starts the call rejects — never throws — with `name` `AbortError` and `code` `Cancelled`; a batch cut part-way resolves with the partial sweep plus `cancelled` and `cancelledFiles`; a scan already running cannot be interrupted, so `setTimeout()` and `setMaxScanSize()` stay the in-scan bounds, and sync methods take no signal. A call in flight hangs one `abort` listener on the signal and removes it when the task settles, leaving `signal.onabort` and the caller's listeners alone. See [Cancel work you no longer want](../README.md#cancel-work-you-no-longer-want).

## BatchScanOptions

| Option | Type | Description |
| :--- | :--- | :--- |
| `maxDepth` | `number` | Maximum directory recursion depth (default: unlimited). |
| `includePatterns` | `string[]` | Globs for paths to include, relative to the scanned root (`subdir/**`) or full-path (`**/subdir/**`). |
| `excludePatterns` | `string[]` | Globs for paths to exclude; same forms as `includePatterns`. |
| `minFileSize` | `number` | Minimum file size in bytes to scan. |
| `maxFileSize` | `number` | Maximum file size in bytes to scan. |
| `onlyMatches` | `boolean` | When `true`, records matched status only, without `RuleMatch` objects. |
| `includeCleanFiles` | `boolean` | When `true` (default), lists files with 0 matches in the result. |

## CompilerOptions

| Option | Type | Description |
| :--- | :--- | :--- |
| `namespace` | `string` | Target namespace for the compiled rules. |
| `defineVariables` | `Record<string, string \| number \| boolean \| bigint>` | Global variables defined on the compiler; values keep their JavaScript type. |
| `ignoreInvalidRules` | `boolean` | Skips invalid rules instead of failing compilation. |
| `ignoreModules` | `string[]` | Modules to ignore during compilation. Unknown names produce an `unknown_ignored_module` warning. |
| `bannedModules` | `BannedModule[]` | Modules that raise a compilation error when imported. An unknown name throws rather than silently skipping the ban. |
| `features` | `string[]` | Module-defined feature flags. YARA-X accepts unknown names and ignores them. |
| `relaxedReSyntax` | `boolean` | Enables relaxed regular expression syntax. |
| `conditionOptimization` | `boolean` | Enables rule condition optimization. |
| `errorOnSlowPattern` | `boolean` | Promotes slow pattern warnings to errors. |
| `errorOnSlowLoop` | `boolean` | Promotes slow loop warnings to errors. |
| `safeRules` | `boolean` | Fail-closed preset for untrusted rules: turns on `errorOnSlowPattern`, forces `ignoreInvalidRules` off, and disables `include`. Passing `false` for any of them alongside it does not override the preset. |
| `maxWarnings` | `number` | Maximum number of warnings reported. |
| `disableWarnings` | `string[]` | Warning codes to suppress. |
| `enableAllWarnings` | `boolean` | Turns all compiler warnings on or off (default `true`). |
| `includeDirectories` | `string[]` | Directories searched when resolving `include` statements. |
| `enableIncludes` | `boolean` | Turns `include` processing on or off. |

## Types

`index.d.ts` exports these types alongside the `YaraX` class:
`BannedModule`, `BatchFileError`, `BatchFileMatch`, `BatchScanOptions`, `BatchScanResult`,
`BinaryMatchView`, `BinaryScanCatalog`, `BinaryScanResult`, `CompileResult`, `CompilerError`,
`CompilerOptions`, `CompilerWarning`, `IgnoredRule`, `MatchData`, `RuleInfo`, `RuleMatch`,
`RuleProfile`, `RulesFormatInfo`, and `RuleSource`.

`BinaryMatchView` is constructed from a `BinaryScanResult` —
`new BinaryMatchView(scanner.scanBinary(buffer))` — and adds the indexed accessors over the record
buffer; see [Binary match ABI](./binary-match-abi.md). `BinaryScanCatalog` is the shape of its
`catalog`, `RuleProfile` is what `getSlowestRules()` returns, and `RulesFormatInfo` is what
`rulesFormatInfo()` returns.
