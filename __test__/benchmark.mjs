import yarax from "../index.js";
import { readFileSync } from "fs";
import { mkdtemp, rm, writeFile, mkdir } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { performance } from "perf_hooks";

async function runBenchmark(name, iterations, fn) {
  console.log(`\nRunning benchmark: ${name}`);

  for (let i = 0; i < 3; i++) {
    await fn();
  }

  const times = [];

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    const end = performance.now();
    times.push(end - start);
  }

  const total = times.reduce((sum, time) => sum + time, 0);
  const average = total / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);

  times.sort((a, b) => a - b);
  const p50 = times[Math.floor(times.length * 0.5)];
  const p95 = times[Math.floor(times.length * 0.95)];
  const p99 = times[Math.floor(times.length * 0.99)];

  console.log(`  Iterations: ${iterations}`);
  console.log(`  Average: ${average.toFixed(3)} ms`);
  console.log(`  Min: ${min.toFixed(3)} ms`);
  console.log(`  Max: ${max.toFixed(3)} ms`);
  console.log(`  p50: ${p50.toFixed(3)} ms`);
  console.log(`  p95: ${p95.toFixed(3)} ms`);
  console.log(`  p99: ${p99.toFixed(3)} ms`);

  return { name, iterations, average, min, max, p50, p95, p99 };
}

const smallData = Buffer.from(
  "This is a small test string with some patterns like malware and virus",
);
const mediumData = Buffer.alloc(1024 * 100);
mediumData.fill("A");
mediumData.write("malware pattern", 1000);
mediumData.write("virus signature", 50000);

let largeData;
try {
  largeData = readFileSync(join(__dirname, "large_test_file.bin"));
} catch (e) {
  console.log("Large test file not found, generating 10MB of test data");
  largeData = Buffer.alloc(1024 * 1024 * 10);
  largeData.fill("X");
  largeData.write("malware pattern", 1000000);
  largeData.write("virus signature", 5000000);
}

const simpleRule = `
  rule simple_rule {
    strings:
      $a = "malware"
      $b = "virus"
    condition:
      any of them
  }
`;

const complexRule = `
  rule complex_rule {
    strings:
      $a1 = "pattern1"
      $a2 = "pattern2"
      $a3 = "pattern3"
      $a4 = "pattern4"
      $a5 = "pattern5"
      $b1 = "malware"
      $b2 = "virus"
      $b3 = "trojan"
      $b4 = "worm"
      $b5 = "ransomware"
    condition:
      (2 of ($a*)) and (1 of ($b*))
  }
`;

const regexRule = `
  rule regex_rule {
    strings:
      $a = /mal[a-z]+/
      $b = /vir[a-z]+/
      $c = /[0-9]{3}-[0-9]{2}-[0-9]{4}/
    condition:
      any of them
  }
`;

const multipleRules = `
  rule rule1 {
    strings:
      $a = "malware"
    condition:
      $a
  }

  rule rule2 {
    strings:
      $a = "virus"
    condition:
      $a
  }

  rule rule3 {
    strings:
      $a = "trojan"
    condition:
      $a
  }

  rule rule4 {
    strings:
      $a = "worm"
    condition:
      $a
  }

  rule rule5 {
    strings:
      $a = "ransomware"
    condition:
      $a
  }
`;

console.log("=== YARA-X Scanner Benchmarks ===");

runBenchmark("Scanner creation with simple rule", 100, () => {
  yarax.compile(simpleRule);
});

runBenchmark("Scanner creation with complex rule", 100, () => {
  yarax.compile(complexRule);
});

runBenchmark("Scanner creation with regex rule", 100, () => {
  yarax.compile(regexRule);
});

runBenchmark("Scanner creation with multiple rules", 100, () => {
  yarax.compile(multipleRules);
});

const simpleScanner = yarax.compile(simpleRule);

runBenchmark("Scanning small data (simple rule)", 1000, () => {
  simpleScanner.scan(smallData);
});

runBenchmark("Scanning medium data (simple rule)", 100, () => {
  simpleScanner.scan(mediumData);
});

runBenchmark("Scanning large data (simple rule)", 10, () => {
  simpleScanner.scan(largeData);
});

const complexScanner = yarax.compile(complexRule);
const regexScanner = yarax.compile(regexRule);
const multipleScanner = yarax.compile(multipleRules);

runBenchmark("Scanning medium data (complex rule)", 100, () => {
  complexScanner.scan(mediumData);
});

runBenchmark("Scanning medium data (regex rule)", 100, () => {
  regexScanner.scan(mediumData);
});

runBenchmark("Scanning medium data (multiple rules)", 100, () => {
  multipleScanner.scan(mediumData);
});

await runBenchmark("Async scanning medium data (simple rule)", 100, async () => {
  await simpleScanner.scanAsync(mediumData);
});

const variableRule = `
  rule variable_rule {
    condition:
      test_var > 50
  }
`;

const variableScanner = yarax.compile(variableRule, {
  defineVariables: { test_var: "100" },
});

runBenchmark("Scanning with variables", 1000, () => {
  variableScanner.scan(smallData);
});

runBenchmark("Scanning with variables (override at scan time)", 1000, () => {
  variableScanner.scan(smallData, { test_var: "75" });
});

console.log("\n=== Boolean Match Check Benchmarks (scan vs isMatch) ===");

const cleanSmallData = Buffer.from("Clean test data without any signatures or suspicious patterns");

runBenchmark("scan: small data (matching)", 1000, () => {
  simpleScanner.scan(smallData);
});

runBenchmark("isMatch: small data (matching - fast path)", 1000, () => {
  simpleScanner.isMatch(smallData);
});

runBenchmark("scan: small data (non-matching)", 1000, () => {
  simpleScanner.scan(cleanSmallData);
});

runBenchmark("isMatch: small data (non-matching - fast path)", 1000, () => {
  simpleScanner.isMatch(cleanSmallData);
});

runBenchmark("scan: medium data (matching)", 100, () => {
  simpleScanner.scan(mediumData);
});

runBenchmark("isMatch: medium data (matching - fast path)", 100, () => {
  simpleScanner.isMatch(mediumData);
});

const multiMatchRule = `
  rule many_matches {
    strings:
      $a = "test"
    condition:
      $a
  }
`;
const multiScanner = yarax.compile(multiMatchRule);
const repetitiveData = Buffer.from("test ".repeat(1000));

runBenchmark("scan: repetitive data with 1000 matches (full V8 object construction)", 500, () => {
  multiScanner.scan(repetitiveData);
});

runBenchmark("isMatch: repetitive data with 1000 matches (fast-path boolean check)", 500, () => {
  multiScanner.isMatch(repetitiveData);
});

console.log("\n=== fastScan Mode Benchmarks ===");

runBenchmark("scan: 1000 matches (standard full scan)", 500, () => {
  multiScanner.scan(repetitiveData);
});

multiScanner.setFastScan(true);
runBenchmark("scan: 1000 matches (fastScan enabled - single match)", 500, () => {
  multiScanner.scan(repetitiveData);
});
multiScanner.setFastScan(false);

console.log("\n=== Zero-Copy Large Buffer Async Benchmarks ===");

const large20Mb = Buffer.alloc(20 * 1024 * 1024);
large20Mb.write("malware", 19 * 1024 * 1024);

await runBenchmark("isMatchAsync: 20MB buffer zero-copy async scan", 20, async () => {
  await simpleScanner.isMatchAsync(large20Mb);
});

console.log("\n=== Native Batch and Directory Scanning Benchmarks ===");

const benchTempDir = await mkdtemp(join(tmpdir(), "yara-x-bench-batch-"));
const benchFiles = [];
for (let i = 0; i < 200; i++) {
  const filePath = join(benchTempDir, `file_${i}.txt`);
  const content = i % 5 === 0 ? "contains virus pattern inside" : "benign non-matching file content";
  await writeFile(filePath, content);
  benchFiles.push(filePath);
}

await runBenchmark("Batch: 200 files via libuv Promise.all(scanFileAsync)", 10, async () => {
  await Promise.all(benchFiles.map((f) => simpleScanner.scanFileAsync(f)));
});

await runBenchmark("Batch: 200 files via native Rayon scanFiles", 10, async () => {
  await simpleScanner.scanFiles(benchFiles);
});

await runBenchmark("Batch: 200 files via native Rayon scanFiles (onlyMatches boolean)", 10, async () => {
  await simpleScanner.scanFiles(benchFiles, { onlyMatches: true });
});

await runBenchmark("Batch: 200 files via native recursive scanDirectory", 10, async () => {
  await simpleScanner.scanDirectory(benchTempDir);
});

await rm(benchTempDir, { recursive: true, force: true });

console.log("\n=== Benchmarks Complete ===");
