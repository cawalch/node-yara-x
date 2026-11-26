# Binary match ABI

The binary match ABI returns match records packed into one flat buffer instead of building a JavaScript
object per match. Use it when a scan produces many thousands of matches: constructing `RuleMatch` and
`MatchData` objects, their strings, and their metadata dominates the scan time and the garbage
collection that follows.

Entry points: `scanBinary()`, `scanFileBinary()`, `scanBinaryAsync()`, `scanFileBinaryAsync()`. Each
returns a `BinaryScanResult` with three fields — `matchCount`, the record `buffer`, and the rule
`catalog` — which is enough to consume the scan directly. Wrapping it in `BinaryMatchView` adds the
indexed accessors. The README's
[Binary match ABI](../README.md#binary-match-abi) section covers the common calls; this page has the
record layout and the metadata behaviour.

## Reading records

```javascript
import { compile, BinaryMatchView } from "@litko/yara-x";

const scanner = compile(`
  rule DetectThreat {
    strings:
      $pattern1 = "malicious_string"
      $pattern2 = "suspicious_signature"
    condition:
      any of them
  }
`);

const result = scanner.scanBinary(sampleBuffer); // { matchCount, buffer, catalog }
const view = new BinaryMatchView(result);

console.log(`Total match occurrences: ${view.matchCount}`);
console.log(
  `Matched rules: ${view.catalog.rules.map((rule) => rule.identifier).join(", ")}`,
);

// O(1) indexed access to the raw records.
for (let i = 0; i < view.matchCount; i++) {
  console.log(
    `Match ${i}: ${view.getRule(i).identifier} / ${view.getPattern(i)} ` +
      `at offset ${view.getOffset(i)}, length ${view.getLength(i)}`,
  );
}

// Materialize standard RuleMatch[] objects when you need them.
const ruleMatches = view.toRuleMatches(sampleBuffer);
```

## The raw buffer

The record array is 24 bytes per match, little-endian — `ruleId` `u32`, `patternId` `u32`,
`offset` `u64`, `length` `u32`, `flags` `u32` — so `result.buffer.byteLength` is `matchCount * 24`.

```javascript
// `BinaryMatchView.buffer` copies the records on every read, so take it once; the
// `BinaryScanResult` hands back the same object each time, so read it from there when you can.
const records = new BinaryMatchView(scanner.scanBinary(sampleBuffer)).buffer;
for (let offset = 0; offset < records.length; offset += 24) {
  const ruleId = records.readUInt32LE(offset);
  const matchOffset = Number(records.readBigUInt64LE(offset + 8));
  const flags = records.readUInt32LE(offset + 20);
}
```

The `flags` word carries the XOR key of a match: bits 0-7 hold the key, and bit 8 is set when the
pattern was compiled with an `xor` modifier. `getXorKey(index)` decodes it, and `toRuleMatches()` fills
`MatchData.xorKey`, so parsing `flags` by hand is only necessary when you consume the raw buffer.

## The catalog

The catalog carries each matching rule's `meta`, `tags`, and pattern identifiers, and `toRuleMatches()`
materializes the same `meta` object as `scan()`. `getRules()` exposes the same metadata for every
compiled rule.

`view.catalog` is built on first read and shared by every later read, so re-reading it is cheap and
`view.catalog === view.catalog` holds. Treat it as read-only: a change made through one read is visible
in the next.

`toRuleMatches()` needs the source buffer to fill `MatchData.data` and `dataBytes`; without it, `data`
is empty and `dataBytes` is absent.
