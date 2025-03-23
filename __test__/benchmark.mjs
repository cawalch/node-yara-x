import yarax from "../index.js";
import { readFileSync } from "fs";
import { join } from "path";
import { performance } from "perf_hooks";

function runBenchmark(name, iterations, fn) {
  console.log(`\nRunning benchmark: ${name}`);

  for (let i = 0; i < 3; i++) {
    fn();
  }

  const times = [];

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    fn();
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

runBenchmark("Async scanning medium data (simple rule)", 100, async () => {
  await new Promise((resolve) => {
    simpleScanner.scanAsync(mediumData, (err, matches) => {
      resolve(matches);
    });
  });
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

console.log("\n=== Benchmarks Complete ===");
