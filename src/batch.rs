//! Native multi-threaded batch and directory scanning engine.
//!
//! This module coordinates parallel file and directory scanning using Rayon,
//! native recursive directory traversal, glob-based pattern filtering, and
//! thread-local scanner reuse across Rayon worker threads.

use crate::scanner::YaraX;
use crate::tasks::{BaseYaraTask, TaskScanOptions};
use crate::types::{RuleMatch, RuleMatchData, VariableMap};
use globset::{Glob, GlobSet, GlobSetBuilder};
use napi::{Error, Result, Status, Task};
use napi_derive::napi;
use rayon::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use walkdir::WalkDir;
use yara_x::Rules;

/// Options for batch file and directory scanning.
#[napi(object)]
#[derive(Default, Clone)]
pub struct BatchScanOptions {
  /// Number of concurrent threads to use. Defaults to the number of logical CPU cores.
  pub concurrency: Option<u32>,
  /// Maximum traversal depth for directory scanning.
  pub max_depth: Option<u32>,
  /// Whether to follow symbolic links during directory traversal. Default: false.
  pub follow_symlinks: Option<bool>,
  /// Glob patterns to include (e.g. `["*.exe", "*.dll"]`).
  pub include_patterns: Option<Vec<String>>,
  /// Glob patterns to exclude (e.g. `["*.log", ".git/**"]`).
  pub exclude_patterns: Option<Vec<String>>,
  /// If true, includes files with 0 matches in results. Default: false (only matching files).
  pub include_clean_files: Option<bool>,
  /// If true, performs fast boolean match check instead of building full match details.
  pub only_matches: Option<bool>,
  /// Minimum file size in bytes to include in directory scans.
  pub min_file_size: Option<i64>,
  /// Maximum file size in bytes to include in directory scans.
  pub max_file_size: Option<i64>,
}

/// Result of scanning a single file within a batch.
#[napi(object)]
pub struct BatchFileMatch<'a> {
  /// Path of the scanned file.
  pub file_path: String,
  /// Whether any rule matched this file.
  pub is_match: bool,
  /// List of matching rules (empty if only_matches is true or no rules matched).
  pub matches: Vec<RuleMatch<'a>>,
}

/// Internal thread-safe representation of a single file match.
#[derive(Clone)]
pub struct BatchFileMatchData {
  pub file_path: String,
  pub is_match: bool,
  pub matches: Vec<RuleMatchData>,
}

/// Error encountered while scanning an individual file in a batch.
#[napi(object)]
#[derive(Clone)]
pub struct BatchFileError {
  /// Path of the file that failed.
  pub file_path: String,
  /// Error description.
  pub error: String,
}

/// Aggregated result of a batch scan.
#[napi(object)]
pub struct BatchScanResult<'a> {
  /// Total files discovered or submitted for scanning.
  pub total_files: u32,
  /// Total files successfully scanned.
  pub scanned_files: u32,
  /// Total files that matched at least one rule.
  pub matched_files: u32,
  /// Results per file (matching files only, or all files if include_clean_files is true).
  pub results: Vec<BatchFileMatch<'a>>,
  /// Errors encountered during the batch scan.
  pub errors: Vec<BatchFileError>,
  /// Total scan duration in milliseconds.
  pub duration_ms: f64,
}

/// Internal thread-safe representation of the aggregated batch scan result.
#[derive(Clone)]
pub struct BatchScanResultData {
  pub total_files: u32,
  pub scanned_files: u32,
  pub matched_files: u32,
  pub results: Vec<BatchFileMatchData>,
  pub errors: Vec<BatchFileError>,
  pub duration_ms: f64,
}

/// Helper for path-based glob filtering.
pub struct PathFilter {
  include_set: Option<GlobSet>,
  exclude_set: Option<GlobSet>,
}

impl PathFilter {
  fn build_glob_set(patterns: Option<&[String]>, kind: &str) -> Result<Option<GlobSet>> {
    match patterns {
      Some(p) if !p.is_empty() => {
        let mut builder = GlobSetBuilder::new();
        for pat in p {
          let glob = Glob::new(pat).map_err(|e| {
            Error::new(
              Status::InvalidArg,
              format!("Invalid {kind} glob '{pat}': {e}"),
            )
          })?;
          builder.add(glob);
        }
        builder
          .build()
          .map_err(|e| Error::new(Status::InvalidArg, format!("Glob build error: {e}")))
          .map(Some)
      }
      _ => Ok(None),
    }
  }

  /// Creates a new path filter from optional include and exclude glob lists.
  pub fn new(includes: Option<&[String]>, excludes: Option<&[String]>) -> Result<Self> {
    Ok(Self {
      include_set: Self::build_glob_set(includes, "include")?,
      exclude_set: Self::build_glob_set(excludes, "exclude")?,
    })
  }

  /// Returns true if the path passes the include/exclude filters.
  pub fn is_match(&self, path: &Path) -> bool {
    if let Some(ref excludes) = self.exclude_set {
      if excludes.is_match(path) {
        return false;
      }
    }

    if let Some(ref includes) = self.include_set {
      return includes.is_match(path);
    }

    true
  }
}

/// Recursively collects matching file paths from a root directory.
pub fn collect_directory_files(
  dir_path: &str,
  max_depth: Option<u32>,
  follow_symlinks: Option<bool>,
  min_file_size: Option<i64>,
  max_file_size: Option<i64>,
  filter: &PathFilter,
) -> Result<Vec<String>> {
  let root = Path::new(dir_path);
  if !root.exists() {
    return Err(Error::new(
      Status::GenericFailure,
      format!("Directory not found: {dir_path}"),
    ));
  }
  if !root.is_dir() {
    return Err(Error::new(
      Status::InvalidArg,
      format!("Path is not a directory: {dir_path}"),
    ));
  }

  let mut walker = WalkDir::new(dir_path);
  if let Some(depth) = max_depth {
    walker = walker.max_depth(depth as usize);
  }
  if follow_symlinks.unwrap_or(false) {
    walker = walker.follow_links(true);
  }

  let mut files = Vec::new();
  for entry in walker {
    match entry {
      Ok(e) => {
        let p = e.into_path();
        if p.is_file() && filter.is_match(&p) {
          if min_file_size.is_some() || max_file_size.is_some() {
            if let Ok(metadata) = p.metadata() {
              let len = metadata.len() as i64;
              if let Some(min) = min_file_size {
                if len < min {
                  continue;
                }
              }
              if let Some(max) = max_file_size {
                if len > max {
                  continue;
                }
              }
            }
          }
          files.push(
            p.into_os_string()
              .into_string()
              .unwrap_or_else(|os| os.to_string_lossy().into_owned()),
          );
        }
      }
      Err(err) => {
        // Skip unreadable files/permission issues during traversal,
        // but if root failed completely, bubble error.
        if files.is_empty() && !root.exists() {
          return Err(Error::new(
            Status::GenericFailure,
            format!("Error traversing directory {dir_path}: {err}"),
          ));
        }
      }
    }
  }

  Ok(files)
}

/// Core multi-threaded batch scanning engine.
pub fn execute_batch_scan(
  rules: Arc<Rules>,
  file_paths: Vec<String>,
  scan_options: TaskScanOptions,
  variables: Option<VariableMap>,
  batch_options: BatchScanOptions,
) -> Result<BatchScanResultData> {
  let start_time = Instant::now();
  let total_files = file_paths.len() as u32;

  let base_task = BaseYaraTask::new(rules, variables, scan_options);
  let only_matches = batch_options.only_matches.unwrap_or(false);
  let include_clean_files = batch_options.include_clean_files.unwrap_or(false);

  let scan_one = |file_path: String| -> std::result::Result<BatchFileMatchData, BatchFileError> {
    if only_matches {
      match base_task.is_file_match(&file_path) {
        Ok(is_match) => Ok(BatchFileMatchData {
          file_path,
          is_match,
          matches: Vec::new(),
        }),
        Err(err) => Err(BatchFileError {
          file_path,
          error: err.to_string(),
        }),
      }
    } else {
      match base_task.scan_file_to_data(&file_path) {
        Ok(matches) => {
          let is_match = !matches.is_empty();
          Ok(BatchFileMatchData {
            file_path,
            is_match,
            matches,
          })
        }
        Err(err) => Err(BatchFileError {
          file_path,
          error: err.to_string(),
        }),
      }
    }
  };

  let scan_all =
    |paths: Vec<String>| -> Vec<std::result::Result<BatchFileMatchData, BatchFileError>> {
      paths.into_par_iter().map(scan_one).collect()
    };

  let raw_results = if let Some(concurrency) = batch_options.concurrency {
    if concurrency > 0 {
      let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(concurrency as usize)
        .build()
        .map_err(|e| {
          Error::new(
            Status::GenericFailure,
            format!("Failed to build Rayon thread pool: {e}"),
          )
        })?;
      pool.install(|| scan_all(file_paths))
    } else {
      scan_all(file_paths)
    }
  } else {
    scan_all(file_paths)
  };

  let mut results = Vec::with_capacity(if include_clean_files {
    total_files as usize
  } else {
    0
  });
  let mut errors = Vec::new();
  let mut scanned_files = 0u32;
  let mut matched_files = 0u32;

  for item in raw_results {
    match item {
      Ok(match_data) => {
        scanned_files += 1;
        if match_data.is_match {
          matched_files += 1;
        }
        if include_clean_files || match_data.is_match {
          results.push(match_data);
        }
      }
      Err(err) => {
        errors.push(err);
      }
    }
  }

  let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;

  Ok(BatchScanResultData {
    total_files,
    scanned_files,
    matched_files,
    results,
    errors,
    duration_ms,
  })
}

/// Converts `BatchScanResultData` into N-API `BatchScanResult`.
pub fn convert_batch_result<'a>(
  env: napi::Env,
  output: BatchScanResultData,
) -> Result<BatchScanResult<'a>> {
  let mut converted_results = Vec::with_capacity(output.results.len());

  for item in output.results {
    let matches = if item.matches.is_empty() {
      Vec::new()
    } else {
      YaraX::convert_to_rule_matches(env, item.matches)?
    };

    converted_results.push(BatchFileMatch {
      file_path: item.file_path,
      is_match: item.is_match,
      matches,
    });
  }

  Ok(BatchScanResult {
    total_files: output.total_files,
    scanned_files: output.scanned_files,
    matched_files: output.matched_files,
    results: converted_results,
    errors: output.errors,
    duration_ms: output.duration_ms,
  })
}

/// Target to scan in a batch operation.
pub enum BatchScanTarget {
  Files(Vec<String>),
  Directory(String),
}

/// N-API background task for parallel batch scanning.
pub struct BatchScanTask {
  rules: Arc<Rules>,
  target: BatchScanTarget,
  scan_options: TaskScanOptions,
  variables: Option<VariableMap>,
  batch_options: BatchScanOptions,
}

impl BatchScanTask {
  pub fn new(
    rules: Arc<Rules>,
    target: BatchScanTarget,
    scan_options: TaskScanOptions,
    variables: Option<VariableMap>,
    batch_options: BatchScanOptions,
  ) -> Self {
    Self {
      rules,
      target,
      scan_options,
      variables,
      batch_options,
    }
  }
}

impl Task for BatchScanTask {
  type Output = BatchScanResultData;
  type JsValue = BatchScanResult<'static>;

  fn compute(&mut self) -> Result<Self::Output> {
    let files = match &mut self.target {
      BatchScanTarget::Files(paths) => std::mem::take(paths),
      BatchScanTarget::Directory(dir_path) => {
        let filter = PathFilter::new(
          self.batch_options.include_patterns.as_deref(),
          self.batch_options.exclude_patterns.as_deref(),
        )?;
        collect_directory_files(
          dir_path,
          self.batch_options.max_depth,
          self.batch_options.follow_symlinks,
          self.batch_options.min_file_size,
          self.batch_options.max_file_size,
          &filter,
        )?
      }
    };

    execute_batch_scan(
      self.rules.clone(),
      files,
      self.scan_options.clone(),
      self.variables.clone(),
      self.batch_options.clone(),
    )
  }

  fn resolve(&mut self, env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    convert_batch_result(env, output)
  }
}
