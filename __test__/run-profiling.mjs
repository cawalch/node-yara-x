#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import PerformanceRegressionAnalyzer from "./performance-regression.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Main profiling runner script
 * Usage: node run-profiling.mjs [--baseline] [--compare baseline.json]
 */
async function main() {
  const args = process.argv.slice(2);
  const isBaseline = args.includes("--baseline");
  const compareIndex = args.indexOf("--compare");
  const compareFile = compareIndex !== -1 ? args[compareIndex + 1] : null;

  console.log("YARA-X Performance Profiling Tool");
  console.log("==================================");

  if (isBaseline) {
    console.log("Generating baseline performance data...");
  } else if (compareFile) {
    console.log(`Comparing performance against baseline: ${compareFile}`);
  } else {
    console.log("Running performance analysis...");
  }

  // Check if running with --expose-gc for better memory profiling
  if (!global.gc) {
    console.log("Warning: Running without --expose-gc flag");
    console.log(
      "   For better memory profiling, run with: node --expose-gc run-profiling.mjs",
    );
  }

  const analyzer = new PerformanceRegressionAnalyzer();

  try {
    const results = await analyzer.runComprehensiveAnalysis();

    if (isBaseline) {
      // Save as baseline
      const baselinePath = join(__dirname, "baseline-performance.json");
      analyzer.profiler.saveResults(results, "baseline-performance.json");
      console.log(`\nBaseline saved to: ${baselinePath}`);
      console.log(
        "   Use this file for future comparisons with --compare flag",
      );
    }

    if (compareFile) {
      await compareWithBaseline(results, compareFile);
    }

    // Generate recommendations
    generateRecommendations(results);
  } catch (error) {
    console.error("❌ Error during profiling:", error);
    process.exit(1);
  }
}

async function compareWithBaseline(currentResults, baselineFile) {
  const baselinePath = join(__dirname, baselineFile);

  if (!existsSync(baselinePath)) {
    console.error(`Baseline file not found: ${baselinePath}`);
    return;
  }

  console.log("\nPERFORMANCE COMPARISON");
  console.log("======================");

  try {
    const baseline = JSON.parse(readFileSync(baselinePath, "utf8"));

    // Compare key metrics
    const currentScanTests = currentResults.tests.filter((t) =>
      t.name.includes("Scan"),
    );
    const baselineScanTests = baseline.tests.filter((t) =>
      t.name.includes("Scan"),
    );

    console.log("\nScan Performance Comparison:");

    for (const currentTest of currentScanTests) {
      const baselineTest = baselineScanTests.find(
        (t) => t.name === currentTest.name,
      );
      if (!baselineTest) continue;

      const timingChange =
        ((currentTest.timing.mean - baselineTest.timing.mean) /
          baselineTest.timing.mean) *
        100;
      const throughputChange =
        ((currentTest.timing.throughput - baselineTest.timing.throughput) /
          baselineTest.timing.throughput) *
        100;

      console.log(`\n  ${currentTest.name}:`);
      console.log(
        `    Timing: ${timingChange > 0 ? "+" : ""}${timingChange.toFixed(1)}% (${currentTest.timing.mean.toFixed(3)}ms vs ${baselineTest.timing.mean.toFixed(3)}ms)`,
      );
      console.log(
        `    Throughput: ${throughputChange > 0 ? "+" : ""}${throughputChange.toFixed(1)}% (${currentTest.timing.throughput.toFixed(1)} vs ${baselineTest.timing.throughput.toFixed(1)} ops/sec)`,
      );

      if (currentTest.memory && baselineTest.memory) {
        const memoryChange =
          ((currentTest.memory.totalDelta.heapUsed -
            baselineTest.memory.totalDelta.heapUsed) /
            Math.abs(baselineTest.memory.totalDelta.heapUsed || 1)) *
          100;
        console.log(
          `    Memory: ${memoryChange > 0 ? "+" : ""}${memoryChange.toFixed(1)}% (${(currentTest.memory.totalDelta.heapUsed / 1024 / 1024).toFixed(2)}MB vs ${(baselineTest.memory.totalDelta.heapUsed / 1024 / 1024).toFixed(2)}MB)`,
        );
      }

      // Flag significant regressions
      if (timingChange > 20) {
        console.log(
          `    SIGNIFICANT REGRESSION: ${timingChange.toFixed(1)}% slower!`,
        );
      } else if (timingChange > 10) {
        console.log(
          `    Performance regression: ${timingChange.toFixed(1)}% slower`,
        );
      } else if (timingChange < -10) {
        console.log(
          `    Performance improvement: ${Math.abs(timingChange).toFixed(1)}% faster`,
        );
      }
    }
  } catch (error) {
    console.error("Error comparing with baseline:", error);
  }
}

function generateRecommendations(results) {
  console.log("\nOPTIMIZATION RECOMMENDATIONS");
  console.log("============================");

  const scanTests = results.tests.filter((t) => t.name.includes("Scan"));
  const compileTests = results.tests.filter((t) => t.name.includes("Compile"));

  // Analyze scan performance
  const avgScanTime =
    scanTests.reduce((sum, t) => sum + t.timing.mean, 0) / scanTests.length;
  const avgThroughput =
    scanTests.reduce((sum, t) => sum + t.timing.throughput, 0) /
    scanTests.length;

  console.log("\nScanning Performance:");
  if (avgScanTime > 10) {
    console.log("  High average scan time detected");
    console.log("     → Consider optimizing pattern matching algorithms");
    console.log("     → Review rule complexity and compilation optimizations");
  }

  if (avgThroughput < 500) {
    console.log("  Low throughput detected");
    console.log("     → Profile CPU usage during scanning");
    console.log("     → Consider parallel processing for large datasets");
  }

  // Analyze memory usage
  const memoryTests = scanTests.filter((t) => t.memory);
  if (memoryTests.length > 0) {
    const avgMemoryUsage =
      memoryTests.reduce((sum, t) => sum + t.memory.totalDelta.heapUsed, 0) /
      memoryTests.length;

    console.log("\nMemory Usage:");
    if (avgMemoryUsage > 100 * 1024 * 1024) {
      // 100MB
      console.log("  High memory usage detected");
      console.log("     → Review memory allocations in scanning logic");
      console.log("     → Consider streaming or chunked processing");
    }

    const highVarianceTests = memoryTests.filter(
      (t) => t.memory.perIteration.heapUsed.stddev > 1024 * 1024,
    ); // 1MB variance
    if (highVarianceTests.length > 0) {
      console.log("  High memory allocation variance detected");
      console.log("     → Investigate inconsistent memory patterns");
      console.log("     → Consider object pooling or pre-allocation");
    }
  }

  // Analyze GC impact
  const gcTests = scanTests.filter((t) => t.gc && t.gc.count > 0);
  if (gcTests.length > 0) {
    const avgGCOverhead =
      gcTests.reduce((sum, t) => sum + t.gc.overhead / t.timing.total, 0) /
      gcTests.length;

    console.log("\nGarbage Collection:");
    if (avgGCOverhead > 0.1) {
      // 10% overhead
      console.log("  High GC overhead detected");
      console.log("     → Reduce object allocations during scanning");
      console.log("     → Consider reusing objects or using object pools");
      console.log("     → Review string concatenation and buffer usage");
    }
  }

  // Analyze compilation performance
  if (compileTests.length > 0) {
    const avgCompileTime =
      compileTests.reduce((sum, t) => sum + t.timing.mean, 0) /
      compileTests.length;

    console.log("\nCompilation Performance:");
    if (avgCompileTime > 50) {
      console.log("  Slow rule compilation detected");
      console.log("     → Consider caching compiled rules");
      console.log("     → Review rule complexity and optimization flags");
    }
  }

  console.log("\n🎯 Next Steps:");
  console.log("  1. Focus on the highest impact bottlenecks identified above");
  console.log("  2. Use --expose-gc flag for more detailed memory profiling");
  console.log("  3. Run with --baseline to establish performance baseline");
  console.log("  4. Profile specific operations that show regressions");
  console.log("  5. Consider adding performance tests to CI/CD pipeline");
}

// Handle command line execution
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error("Fatal error:", error);
    process.exit(1);
  });
}

export { main, compareWithBaseline, generateRecommendations };
