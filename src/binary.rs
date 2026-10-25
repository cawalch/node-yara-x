//! Flat binary match protocol for high-density match reporting.
//!
//! When rules match thousands of times, allocating individual V8 objects and
//! cloning strings creates significant GC pauses. This module serializes matches
//! into a flat, contiguous 24-byte record buffer and an indexed metadata catalog.

use crate::tasks::{BaseYaraTask, ScanTarget, TaskScanOptions};
use crate::types::VariableMap;
use napi::bindgen_prelude::Buffer;
use napi::{Env, Result, Task};
use napi_derive::napi;
use std::sync::Arc;
use yara_x::Rules;

/// A 24-byte fixed-size binary match record.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct BinaryMatchRecord {
  /// Index of the rule in `BinaryScanCatalog.rules`.
  pub rule_id: u32,
  /// Index of the pattern in `RuleInfo.patterns`.
  pub pattern_id: u32,
  /// Byte offset of the match in the input data.
  pub offset: u64,
  /// Length of the matched data in bytes.
  pub length: u32,
  /// Reserved bitflags.
  pub flags: u32,
}

const _: () = assert!(std::mem::size_of::<BinaryMatchRecord>() == 24);

/// Metadata for a rule that matched in a binary scan.
#[napi(object)]
#[derive(Clone, Debug, PartialEq)]
pub struct RuleInfo {
  /// Rule identifier name.
  pub identifier: String,
  /// Namespace of the rule.
  pub namespace: String,
  /// Rule tags.
  pub tags: Vec<String>,
  /// Rule pattern identifiers that matched.
  pub patterns: Vec<String>,
}

/// Catalog indexing the rules and patterns present in a binary scan result.
#[napi(object)]
#[derive(Clone, Debug, PartialEq)]
pub struct BinaryScanCatalog {
  /// Indexed list of rules that matched.
  pub rules: Vec<RuleInfo>,
}

/// Result of a binary scan containing packed match records and metadata catalog.
#[napi(object)]
pub struct BinaryScanResult {
  /// Flat binary buffer containing 24-byte match records.
  pub buffer: Buffer,
  /// Total number of matches recorded.
  pub match_count: u32,
  /// Indexed catalog of matching rules and patterns.
  pub catalog: BinaryScanCatalog,
}

/// A zero-copy accessor view wrapping binary scan results.
#[napi]
pub struct BinaryMatchView {
  buffer: Buffer,
  match_count: u32,
  catalog: BinaryScanCatalog,
}

#[napi]
impl BinaryMatchView {
  /// Creates a new `BinaryMatchView` from a `BinaryScanResult`.
  #[napi(constructor)]
  pub fn new(result: BinaryScanResult) -> Self {
    Self {
      buffer: result.buffer,
      match_count: result.match_count,
      catalog: result.catalog,
    }
  }

  /// Total number of matches in the view.
  #[napi(getter)]
  pub fn match_count(&self) -> u32 {
    self.match_count
  }

  /// Metadata catalog of rules and patterns.
  #[napi(getter)]
  pub fn catalog(&self) -> BinaryScanCatalog {
    self.catalog.clone()
  }

  /// Returns the underlying flat binary match records buffer.
  #[napi(getter)]
  pub fn buffer(&self) -> Buffer {
    Buffer::from(self.buffer.as_ref())
  }

  fn read_record(&self, index: u32) -> Option<BinaryMatchRecord> {
    let offset = (index as usize).checked_mul(24)?;
    let slice = self.buffer.as_ref().get(offset..offset + 24)?;
    Some(BinaryMatchRecord {
      rule_id: u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
      pattern_id: u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]),
      offset: u64::from_le_bytes([
        slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14], slice[15],
      ]),
      length: u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]),
      flags: u32::from_le_bytes([slice[20], slice[21], slice[22], slice[23]]),
    })
  }

  /// Gets the rule index for the match record at `index`.
  #[napi]
  pub fn get_rule_id(&self, index: u32) -> Option<u32> {
    self.read_record(index).map(|r| r.rule_id)
  }

  /// Gets the pattern index for the match record at `index`.
  #[napi]
  pub fn get_pattern_id(&self, index: u32) -> Option<u32> {
    self.read_record(index).map(|r| r.pattern_id)
  }

  /// Gets the byte offset in the scanned target for the match record at `index`.
  #[napi]
  pub fn get_offset(&self, index: u32) -> Option<i64> {
    self.read_record(index).map(|r| r.offset as i64)
  }

  /// Gets the byte length for the match record at `index`.
  #[napi]
  pub fn get_length(&self, index: u32) -> Option<u32> {
    self.read_record(index).map(|r| r.length)
  }

  /// Gets the reserved flags for the match record at `index`.
  #[napi]
  pub fn get_flags(&self, index: u32) -> Option<u32> {
    self.read_record(index).map(|r| r.flags)
  }

  /// Gets the rule metadata for the match record at `index`.
  #[napi]
  pub fn get_rule(&self, index: u32) -> Option<RuleInfo> {
    let record = self.read_record(index)?;
    self.catalog.rules.get(record.rule_id as usize).cloned()
  }

  /// Gets the pattern identifier for the match record at `index`.
  #[napi]
  pub fn get_pattern(&self, index: u32) -> Option<String> {
    let record = self.read_record(index)?;
    let rule = self.catalog.rules.get(record.rule_id as usize)?;
    rule.patterns.get(record.pattern_id as usize).cloned()
  }

  /// Slices the matched byte slice directly out of the source buffer.
  #[napi]
  pub fn get_slice(&self, index: u32, source: Buffer) -> Option<Buffer> {
    let offset = self.get_offset(index)? as usize;
    let length = self.get_length(index)? as usize;
    if offset.checked_add(length)? <= source.len() {
      Some(Buffer::from(&source[offset..offset + length]))
    } else {
      None
    }
  }
}

/// Extracts binary match records and metadata catalog from scan results.
pub fn extract_binary_scan_results(
  results: yara_x::ScanResults,
) -> (Vec<u8>, u32, BinaryScanCatalog) {
  let matching_rules = results.matching_rules();
  let rule_count = matching_rules.len();

  if rule_count == 0 {
    return (Vec::new(), 0, BinaryScanCatalog { rules: Vec::new() });
  }

  let mut catalog_rules = Vec::with_capacity(rule_count);
  let mut total_matches = 0usize;

  // First pass: count matches and build catalog
  for rule in matching_rules {
    let mut patterns = Vec::new();
    for pattern in rule.patterns() {
      let count = pattern.matches().len();
      if count > 0 {
        patterns.push(pattern.identifier().to_string());
        total_matches += count;
      }
    }

    let tags = rule.tags().map(|t| t.identifier().to_string()).collect();

    catalog_rules.push(RuleInfo {
      identifier: rule.identifier().to_string(),
      namespace: rule.namespace().to_string(),
      tags,
      patterns,
    });
  }

  let mut bytes = Vec::with_capacity(total_matches * 24);

  // Second pass: pack binary records directly into byte buffer
  for (rule_id, rule) in results.matching_rules().enumerate() {
    let mut pattern_idx = 0u32;
    for pattern in rule.patterns() {
      let matches = pattern.matches();
      if matches.len() == 0 {
        continue;
      }

      for match_item in matches {
        let range = match_item.range();
        bytes.extend_from_slice(&(rule_id as u32).to_le_bytes());
        bytes.extend_from_slice(&pattern_idx.to_le_bytes());
        bytes.extend_from_slice(&(range.start as u64).to_le_bytes());
        bytes.extend_from_slice(&((range.end - range.start) as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
      }
      pattern_idx += 1;
    }
  }

  (
    bytes,
    total_matches as u32,
    BinaryScanCatalog {
      rules: catalog_rules,
    },
  )
}

/// Intermediate thread-safe output for async binary scan tasks.
pub struct BinaryScanTaskOutput {
  pub bytes: Vec<u8>,
  pub match_count: u32,
  pub catalog: BinaryScanCatalog,
}

/// N-API task for asynchronous binary scanning.
pub struct BinaryScanTask {
  base: BaseYaraTask,
  target: ScanTarget,
}

impl BinaryScanTask {
  pub fn new(
    rules: Arc<Rules>,
    target: ScanTarget,
    variables: Option<VariableMap>,
    options: TaskScanOptions,
  ) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables, options),
      target,
    }
  }
}

impl Task for BinaryScanTask {
  type Output = BinaryScanTaskOutput;
  type JsValue = BinaryScanResult;

  fn compute(&mut self) -> Result<Self::Output> {
    self.base.with_scanner(|scanner| {
      let results = match &self.target {
        ScanTarget::Buffer(buf) => scanner.scan(buf.as_ref()),
        ScanTarget::File(path) => scanner.scan_file(std::path::Path::new(path)),
      }
      .map_err(crate::error::scan_error_to_napi)?;

      let (bytes, match_count, catalog) = extract_binary_scan_results(results);
      Ok(BinaryScanTaskOutput {
        bytes,
        match_count,
        catalog,
      })
    })
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(BinaryScanResult {
      buffer: Buffer::from(output.bytes),
      match_count: output.match_count,
      catalog: output.catalog,
    })
  }
}
