#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

function printHelp() {
  console.log(`TMDb patch-and-quarantine tool

Usage:
  node scripts/patch_tmdb_ids.mjs [options]

Options:
  --repo-root <path>     Repo root to patch. Default: uploader repo root
  --report <path>        TMDb backfill report JSON. Default: <repo-root>/reports/tmdb-id-backfill/tmdb-id-backfill-report.json
  --index-file <path>    Index file to patch. Default: <repo-root>/index.json
  --movies-dir <path>    Movie JSON directory. Default: <repo-root>/movies
  --output-dir <path>    Patch report directory. Default: <repo-root>/reports/tmdb-patch
  --apply                Write changes. Without this, the script is dry-run only.
  --help                 Show this help
`);
}

function parseArgs(argv) {
  const parsed = {
    repoRoot: null,
    reportPath: null,
    indexFile: null,
    moviesDir: null,
    outputDir: null,
    apply: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    if (arg === "--repo-root") {
      parsed.repoRoot = argv[++i] || "";
      continue;
    }
    if (arg === "--report") {
      parsed.reportPath = argv[++i] || "";
      continue;
    }
    if (arg === "--index-file") {
      parsed.indexFile = argv[++i] || "";
      continue;
    }
    if (arg === "--movies-dir") {
      parsed.moviesDir = argv[++i] || "";
      continue;
    }
    if (arg === "--output-dir") {
      parsed.outputDir = argv[++i] || "";
      continue;
    }
    if (arg === "--apply") {
      parsed.apply = true;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function normalizeImdbId(value) {
  const imdbId = String(value || "").trim().toLowerCase();
  return /^tt\d{7,9}$/.test(imdbId) ? imdbId : "";
}

function getMovieTmdbId(value) {
  if (!value || typeof value !== "object") {
    return 0;
  }
  const type = String(value.type || "").trim().toLowerCase();
  const id = Number(value.id || 0) || 0;
  return type === "movie" && id > 0 ? id : 0;
}

function getTmdbIdFromPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return 0;
  }
  if (payload.tmdb && typeof payload.tmdb === "object") {
    return getMovieTmdbId(payload.tmdb);
  }
  if (payload.ids && typeof payload.ids === "object") {
    return getMovieTmdbId(payload.ids.tmdb);
  }
  return 0;
}

function getImdbIdFromPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const direct = normalizeImdbId(payload.imdb_id);
  if (direct) {
    return direct;
  }
  if (payload.ids && typeof payload.ids === "object") {
    return normalizeImdbId(payload.ids.imdb);
  }
  return "";
}

function unique(items) {
  return [...new Set(items.filter(Boolean))];
}

function buildResolvedMap(report) {
  const resolved = new Map();
  for (const section of [report.already_present || [], report.matched || []]) {
    for (const item of section) {
      const imdbId = normalizeImdbId(item.imdb_id);
      const tmdbId = Number(item.tmdb_id || 0) || 0;
      if (!imdbId || tmdbId <= 0) {
        continue;
      }
      if (resolved.has(imdbId) && resolved.get(imdbId).tmdb_id !== tmdbId) {
        throw new Error(`Conflicting TMDb IDs for ${imdbId}: ${resolved.get(imdbId).tmdb_id} vs ${tmdbId}`);
      }
      resolved.set(imdbId, {
        imdb_id: imdbId,
        tmdb_id: tmdbId,
        source: item.source || "report",
        reference_paths: unique(item.reference_paths || []),
      });
    }
  }
  return resolved;
}

function buildQuarantine(report) {
  const byPath = new Map();
  const add = (pathValue, payload) => {
    const relPath = String(pathValue || "").trim();
    if (!relPath) {
      return;
    }
    byPath.set(relPath, {
      ...payload,
      path: relPath,
    });
  };

  for (const item of report.no_match || []) {
    for (const relPath of item.reference_paths || []) {
      add(relPath, {
        imdb_id: normalizeImdbId(item.imdb_id),
        title: String(item.local_title || "").trim(),
        reason: String(item.note || "no match").trim(),
        category: "no_match",
      });
    }
  }
  for (const item of report.suspicious || []) {
    for (const relPath of item.reference_paths || []) {
      add(relPath, {
        imdb_id: normalizeImdbId(item.imdb_id),
        title: String(item.local_title || "").trim(),
        reason: Array.isArray(item.reasons) ? item.reasons.join("; ") : String(item.reasons || "").trim(),
        category: "suspicious",
      });
    }
  }
  for (const item of report.invalid_entries || []) {
    add(item.path, {
      imdb_id: normalizeImdbId(item.imdb_id),
      title: String(item.title || item.local_title || "").trim(),
      reason: String(item.reason || "invalid entry").trim(),
      category: "invalid_entry",
    });
  }
  for (const item of report.broken_paths || []) {
    add(item.path, {
      imdb_id: normalizeImdbId(item.imdb_id),
      title: String(item.title || "").trim(),
      reason: String(item.reason || "broken path").trim(),
      category: "broken_path",
    });
  }
  return byPath;
}

function buildUpgradedMoviePayload(rawPayload, tmdbId, imdbId, fallbackTitle) {
  const payload = rawPayload && typeof rawPayload === "object" ? rawPayload : {};
  const scenes = Array.isArray(payload.scenes) ? payload.scenes : [];
  const title = String(payload.title || fallbackTitle || "").trim();
  const upgraded = {
    schema_version: 3,
    content_type: "movie",
    ids: {
      tmdb: {
        type: "movie",
        id: tmdbId,
      },
    },
    title,
  };

  if (imdbId) {
    upgraded.ids.imdb = imdbId;
  }
  if (payload.year !== undefined && payload.year !== null && String(payload.year).trim() !== "") {
    upgraded.year = payload.year;
  }
  if (payload.video_duration_ms !== undefined && payload.video_duration_ms !== null && String(payload.video_duration_ms).trim() !== "") {
    upgraded.video_duration_ms = payload.video_duration_ms;
  }
  if (String(payload.created_at || "").trim()) {
    upgraded.created_at = String(payload.created_at).trim();
  }
  if (String(payload.label || "").trim()) {
    upgraded.label = String(payload.label).trim();
  }
  if (payload.source !== undefined) {
    upgraded.source = payload.source;
  }
  if (payload.source_app && typeof payload.source_app === "object") {
    upgraded.source_app = payload.source_app;
  }

  const passthroughKeys = Object.keys(payload).filter(
    (key) =>
      ![
        "schema_version",
        "content_type",
        "imdb_id",
        "tmdb",
        "ids",
        "title",
        "year",
        "video_duration_ms",
        "created_at",
        "label",
        "source",
        "source_app",
        "scenes",
      ].includes(key),
  );
  for (const key of passthroughKeys) {
    upgraded[key] = payload[key];
  }

  upgraded.scenes = scenes;
  return upgraded;
}

function stringifyJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function buildMarkdownSummary(report) {
  const lines = [];
  lines.push("# TMDb Patch Report");
  lines.push("");
  lines.push(`Generated: ${report.generated_at}`);
  lines.push(`Mode: ${report.apply ? "apply" : "dry-run"}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Count |");
  lines.push("| --- | ---: |");
  for (const [key, value] of Object.entries(report.summary)) {
    lines.push(`| ${key} | ${value} |`);
  }
  lines.push("");
  lines.push("## Quarantine");
  lines.push("");
  if (!report.quarantine_manifest.length) {
    lines.push("_None_");
    lines.push("");
  } else {
    for (const item of report.quarantine_manifest) {
      lines.push(`- ${item.path}: ${item.category} (${item.reason})`);
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(args.repoRoot || path.join(thisDir, ".."));
  const reportPath = path.resolve(
    args.reportPath || path.join(repoRoot, "reports", "tmdb-id-backfill", "tmdb-id-backfill-report.json"),
  );
  const indexFile = path.resolve(args.indexFile || path.join(repoRoot, "index.json"));
  const moviesDir = path.resolve(args.moviesDir || path.join(repoRoot, "movies"));
  const outputDir = path.resolve(args.outputDir || path.join(repoRoot, "reports", "tmdb-patch"));

  const report = await readJson(reportPath);
  const indexPayload = await readJson(indexFile);
  if (!indexPayload || typeof indexPayload !== "object" || !Array.isArray(indexPayload.movies)) {
    throw new Error(`Index file is not a valid scene library object: ${indexFile}`);
  }

  const resolvedMap = buildResolvedMap(report);
  const quarantineMap = buildQuarantine(report);
  const quarantineManifest = [];
  const skippedFiles = [];
  const alreadyCorrect = [];
  const updatedFiles = [];
  const keptMovies = [];
  let updatedIndexRows = 0;
  let removedIndexRows = 0;

  const fileWrites = new Map();
  const fileBackups = new Map();

  for (const entry of indexPayload.movies) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const relPath = String(entry.path || "").trim();
    const imdbId = normalizeImdbId(entry.imdb_id);

    if (quarantineMap.has(relPath)) {
      removedIndexRows += 1;
      quarantineManifest.push({
        ...quarantineMap.get(relPath),
        imdb_id: quarantineMap.get(relPath).imdb_id || imdbId,
        index_title: String(entry.title || "").trim(),
      });
      continue;
    }

    if (!imdbId) {
      removedIndexRows += 1;
      quarantineManifest.push({
        path: relPath,
        imdb_id: "",
        title: String(entry.title || "").trim(),
        reason: "missing IMDb ID for resolved set",
        category: "unresolved",
      });
      continue;
    }

    const resolved = resolvedMap.get(imdbId);
    if (!resolved) {
      removedIndexRows += 1;
      quarantineManifest.push({
        path: relPath,
        imdb_id: imdbId,
        title: String(entry.title || "").trim(),
        reason: "IMDb ID missing from resolved TMDb mapping set",
        category: "unresolved",
      });
      continue;
    }

    const tmdbId = resolved.tmdb_id;
    const existingIndexTmdb = getMovieTmdbId(entry.tmdb);
    const updatedEntry = { ...entry };
    if (existingIndexTmdb !== tmdbId) {
      updatedEntry.tmdb = { type: "movie", id: tmdbId };
      updatedIndexRows += 1;
    }
    keptMovies.push(updatedEntry);

    if (!relPath) {
      skippedFiles.push({
        path: relPath,
        imdb_id: imdbId,
        reason: "index row missing path",
      });
      continue;
    }

    const absPath = path.resolve(repoRoot, relPath);
    if (!(await fileExists(absPath))) {
      skippedFiles.push({
        path: relPath,
        imdb_id: imdbId,
        reason: "movie file does not exist",
      });
      continue;
    }

    const rawPayload = await readJson(absPath);
    const fileImdbId = getImdbIdFromPayload(rawPayload);
    if (fileImdbId && fileImdbId !== imdbId) {
      skippedFiles.push({
        path: relPath,
        imdb_id: imdbId,
        file_imdb_id: fileImdbId,
        reason: "movie file IMDb does not match index/report IMDb",
      });
      continue;
    }

    const upgraded = buildUpgradedMoviePayload(rawPayload, tmdbId, imdbId, String(entry.title || "").trim());
    const before = stringifyJson(rawPayload);
    const after = stringifyJson(upgraded);
    if (before === after) {
      alreadyCorrect.push({
        path: relPath,
        imdb_id: imdbId,
        tmdb_id: tmdbId,
      });
      continue;
    }

    updatedFiles.push({
      path: relPath,
      imdb_id: imdbId,
      tmdb_id: tmdbId,
      from_schema_version: Number(rawPayload.schema_version || 0) || 0,
      to_schema_version: 3,
    });
    fileWrites.set(absPath, after);
    fileBackups.set(absPath, before);
  }

  const updatedIndexPayload = {
    ...indexPayload,
    movies: keptMovies,
  };

  const now = new Date().toISOString();
  const summary = {
    resolved_imdb_ids: resolvedMap.size,
    quarantine_entries: quarantineManifest.length,
    index_rows_updated: updatedIndexRows,
    index_rows_removed: removedIndexRows,
    movie_files_updated: updatedFiles.length,
    movie_files_already_correct: alreadyCorrect.length,
    movie_files_skipped: skippedFiles.length,
    remaining_index_movies: keptMovies.length,
  };

  const patchReport = {
    generated_at: now,
    apply: args.apply,
    input: {
      repo_root: repoRoot,
      report_path: reportPath,
      index_file: indexFile,
      movies_dir: moviesDir,
    },
    summary,
    quarantine_manifest: quarantineManifest,
    updated_files: updatedFiles,
    already_correct: alreadyCorrect,
    skipped_files: skippedFiles,
  };

  await fs.mkdir(outputDir, { recursive: true });
  const reportJsonPath = path.join(outputDir, "tmdb-patch-report.json");
  const reportMdPath = path.join(outputDir, "tmdb-patch-report.md");
  const quarantineJsonPath = path.join(outputDir, "quarantine-manifest.json");

  if (args.apply) {
    const backupPath = path.join(outputDir, `index.json.backup.${now.replace(/[:.]/g, "-")}`);
    await fs.writeFile(backupPath, stringifyJson(indexPayload), "utf8");
    await fs.writeFile(indexFile, stringifyJson(updatedIndexPayload), "utf8");
    for (const [absPath, content] of fileWrites.entries()) {
      await fs.writeFile(absPath, content, "utf8");
    }
    patchReport.index_backup = backupPath;
  }

  await fs.writeFile(reportJsonPath, stringifyJson(patchReport), "utf8");
  await fs.writeFile(reportMdPath, buildMarkdownSummary(patchReport), "utf8");
  await fs.writeFile(quarantineJsonPath, stringifyJson(quarantineManifest), "utf8");

  console.log(args.apply ? "APPLY mode" : "DRY-RUN mode");
  console.log(`Resolved mappings: ${resolvedMap.size}`);
  console.log(`Index rows to update: ${updatedIndexRows}`);
  console.log(`Index rows to remove: ${removedIndexRows}`);
  console.log(`Movie files to update: ${updatedFiles.length}`);
  console.log(`Movie files already correct: ${alreadyCorrect.length}`);
  console.log(`Movie files skipped: ${skippedFiles.length}`);
  console.log(`Patch report: ${reportJsonPath}`);
  console.log(`Quarantine manifest: ${quarantineJsonPath}`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  console.error(message);
  process.exit(1);
});
