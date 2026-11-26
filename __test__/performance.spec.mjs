import test from "node:test";
import assert from "node:assert";
import PerformanceRegressionAnalyzer from "./performance-regression.mjs";
import YaraXProfiler from "./profiling.mjs";

test("performance regression GC accounting", () => {
  const profiler = new YaraXProfiler();
  assert.strictEqual(
    profiler.calculateGCStatistics(0),
    null,
    "a fresh profiler has no GC events",
  );

  const analyzer = new PerformanceRegressionAnalyzer();
  const base = {
    timing: { mean: 1, throughput: 10, total: 100, cv: 0.1 },
    memory: null,
    cpu: null,
  };

  const withGC = analyzer.generatePerformanceSummary([
    { ...base, name: "Scan with GC events", gc: { overhead: 10 } },
  ]);
  assert.strictEqual(
    withGC.gcOverhead,
    10,
    "GC overhead is attributed to the test that produced it",
  );

  const withoutGC = analyzer.generatePerformanceSummary([
    { ...base, name: "Scan without GC events", gc: null },
  ]);
  assert.strictEqual(
    withoutGC.gcOverhead,
    null,
    "no GC events must not produce NaN",
  );
});
