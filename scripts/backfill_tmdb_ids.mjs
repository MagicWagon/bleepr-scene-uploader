#!/usr/bin/env node

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const TMDB_BASE_URL = "https://api.themoviedb.org/3";
const DEFAULT_TIMEOUT_MS = 12000;
const PROGRESS_EVERY = 25;

function printHelp() {
  console.log(`TMDb ID backfill report generator

Usage:
  node scripts/backfill_tmdb_ids.mjs [options]

Options:
  --repo-root <path>     Repo root to scan. Default: uploader repo root
  --index-file <path>    Index file to scan. Default: <repo-root>/index.json
  --movies-dir <path>    Movie JSON directory. Default: <repo-root>/movies
  --output-dir <path>    Report directory. Default: <repo-root>/reports/tmdb-id-backfill
  --settings <path>      Explicit Bleepr settings.json path
  --limit <n>            Limit IMDb lookups for smoke testing
  --timeout-ms <n>       HTTP timeout in milliseconds. Default: ${DEFAULT_TIMEOUT_MS}
  --help                 Show this help

TMDb API key lookup order:
  1. TMDB_API_KEY environment variable
  2. Explicit --settings file
  3. Common Bleepr settings.json locations
`);
}

function parseArgs(argv) {
  const parsed = {
    repoRoot: null,
    indexFile: null,
    moviesDir: null,
    outputDir: null,
    settingsPath: null,
    limit: null,
    timeoutMs: DEFAULT_TIMEOUT_MS,
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
    if (arg === "--settings") {
      parsed.settingsPath = argv[++i] || "";
      continue;
    }
    if (arg === "--limit") {
      const raw = argv[++i] || "";
      const value = Number.parseInt(raw, 10);
      if (!Number.isFinite(value) || value <= 0) {
        throw new Error(`Invalid --limit value: ${raw}`);
      }
      parsed.limit = value;
      continue;
    }
    if (arg === "--timeout-ms") {
      const raw = argv[++i] || "";
      const value = Number.parseInt(raw, 10);
      if (!Number.isFinite(value) || value <= 0) {
        throw new Error(`Invalid --timeout-ms value: ${raw}`);
      }
      parsed.timeoutMs = value;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
}

async function readJson(filePath) {
  const text = await fs.readFile(filePath, "utf8");
  return JSON.parse(text);
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

function getTmdbIdFromMovieFile(payload) {
  if (!payload || typeof payload !== "object") {
    return 0;
  }
  const ids = payload.ids;
  if (!ids || typeof ids !== "object") {
    return 0;
  }
  return getMovieTmdbId(ids.tmdb);
}

function getImdbIdFromMovieFile(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const direct = normalizeImdbId(payload.imdb_id);
  if (direct) {
    return direct;
  }
  const ids = payload.ids;
  if (!ids || typeof ids !== "object") {
    return "";
  }
  return normalizeImdbId(ids.imdb);
}

function coerceYear(value) {
  const year = Number.parseInt(String(value || "").trim(), 10);
  return Number.isFinite(year) && year > 1800 && year < 3000 ? year : 0;
}

function extractReleaseYear(candidate) {
  const raw = String(candidate?.release_date || "").trim();
  const match = raw.match(/^(\d{4})/);
  return match ? coerceYear(match[1]) : 0;
}

function normalizeTitle(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .replace(/\(\d{4}\)/g, " ")
    .replace(/&/g, " and ")
    .replace(/[^a-zA-Z0-9]+/g, " ")
    .trim()
    .toLowerCase();
}

function titleSimilarity(a, b) {
  const left = new Set(normalizeTitle(a).split(/\s+/).filter(Boolean));
  const right = new Set(normalizeTitle(b).split(/\s+/).filter(Boolean));
  if (!left.size || !right.size) {
    return 0;
  }
  let shared = 0;
  for (const token of left) {
    if (right.has(token)) {
      shared += 1;
    }
  }
  return shared / Math.max(left.size, right.size);
}

function titleMatches(localTitle, candidateTitle) {
  const left = normalizeTitle(localTitle);
  const right = normalizeTitle(candidateTitle);
  if (!left || !right) {
    return false;
  }
  if (left === right) {
    return true;
  }
  if (left.includes(right) || right.includes(left)) {
    return true;
  }
  return titleSimilarity(left, right) >= 0.6;
}

function candidateLooksSuspicious(group, candidate) {
  const reasons = [];
  const candidateYear = extractReleaseYear(candidate);
  const candidateTitle = String(candidate?.title || "").trim();
  const candidateOriginalTitle = String(candidate?.original_title || "").trim();

  const localYears = [...new Set(group.references.map((ref) => ref.year).filter((year) => year > 0))];
  if (
    localYears.length &&
    candidateYear > 0 &&
    localYears.every((year) => Math.abs(year - candidateYear) > 1)
  ) {
    reasons.push(`year mismatch (local: ${localYears.join(", ")}, TMDb: ${candidateYear})`);
  }

  const localTitles = [...new Set(group.references.map((ref) => ref.title).filter(Boolean))];
  if (localTitles.length) {
    const hasTitleMatch = localTitles.some(
      (title) => titleMatches(title, candidateTitle) || titleMatches(title, candidateOriginalTitle),
    );
    if (!hasTitleMatch) {
      reasons.push(`title mismatch (local: ${localTitles[0]}, TMDb: ${candidateTitle || candidateOriginalTitle || "(none)"})`);
    }
  }

  return reasons;
}

function summarizeCandidate(candidate) {
  return {
    tmdb_id: Number(candidate?.id || 0) || 0,
    title: String(candidate?.title || "").trim(),
    original_title: String(candidate?.original_title || "").trim(),
    release_date: String(candidate?.release_date || "").trim(),
    popularity: Number(candidate?.popularity || 0) || 0,
  };
}

function buildSettingsCandidates(explicitPath) {
  const home = os.homedir();
  const candidates = [];
  if (explicitPath) {
    candidates.push(path.resolve(explicitPath));
  }
  const envPath = String(process.env.BLEEPR_SETTINGS_PATH || "").trim();
  if (envPath) {
    candidates.push(path.resolve(envPath));
  }
  candidates.push(
    path.join(home, ".bleepr", "settings.json"),
    path.join(home, "Library", "Application Support", "bleepr", "settings.json"),
    path.join(home, "Library", "Application Support", "Bleepr", "settings.json"),
    path.join(home, "Library", "Preferences", "MagicWagon", "Bleepr", "settings.json"),
    path.join(home, "Library", "Preferences", "Bleepr", "settings.json"),
    path.join(home, ".config", "bleepr", "settings.json"),
  );
  return [...new Set(candidates)];
}

async function resolveTmdbApiKey(explicitSettingsPath) {
  const envKey = String(process.env.TMDB_API_KEY || "").trim();
  if (envKey) {
    return { apiKey: envKey, source: { type: "env", location: "TMDB_API_KEY" } };
  }

  const candidates = buildSettingsCandidates(explicitSettingsPath);
  for (const settingsPath of candidates) {
    if (!(await fileExists(settingsPath))) {
      continue;
    }
    try {
      const payload = await readJson(settingsPath);
      const apiKey = String(payload?.tmdb?.api_key || "").trim();
      if (apiKey) {
        return { apiKey, source: { type: "settings", location: settingsPath } };
      }
    } catch {
      // Ignore unreadable settings candidates and continue.
    }
  }

  throw new Error("TMDb API key not found. Set TMDB_API_KEY or provide a readable Bleepr settings.json.");
}

async function fetchTmdbFind(imdbId, apiKey, timeoutMs) {
  const url = new URL(`${TMDB_BASE_URL}/find/${encodeURIComponent(imdbId)}`);
  url.searchParams.set("api_key", apiKey);
  url.searchParams.set("external_source", "imdb_id");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
        "User-Agent": "bleepr-scene-uploader-tmdb-backfill/1.0",
      },
      signal: controller.signal,
    });
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`TMDb HTTP ${response.status}: ${response.statusText}\n${body.slice(0, 500)}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function collectRepoData(indexFile, moviesDir, repoRoot) {
  const indexPayload = await readJson(indexFile);
  if (!indexPayload || typeof indexPayload !== "object" || !Array.isArray(indexPayload.movies)) {
    throw new Error(`Index file is not a scene library object with a movies array: ${indexFile}`);
  }

  const groups = new Map();
  const brokenPaths = [];
  const invalidEntries = [];
  const referencedMovieFiles = new Set();

  for (let indexPos = 0; indexPos < indexPayload.movies.length; indexPos += 1) {
    const entry = indexPayload.movies[indexPos];
    if (!entry || typeof entry !== "object") {
      invalidEntries.push({
        index_position: indexPos,
        reason: "index entry is not an object",
      });
      continue;
    }

    const relPath = String(entry.path || "").trim();
    if (!relPath) {
      invalidEntries.push({
        index_position: indexPos,
        imdb_id: normalizeImdbId(entry.imdb_id),
        title: String(entry.title || "").trim(),
        reason: "index entry is missing path",
      });
      continue;
    }

    const absPath = path.resolve(repoRoot, relPath);
    referencedMovieFiles.add(absPath);

    let filePayload = null;
    let fileReadError = "";
    if (await fileExists(absPath)) {
      try {
        filePayload = await readJson(absPath);
      } catch (error) {
        fileReadError = error instanceof Error ? error.message : String(error);
      }
    } else {
      brokenPaths.push({
        index_position: indexPos,
        path: relPath,
        imdb_id: normalizeImdbId(entry.imdb_id),
        title: String(entry.title || "").trim(),
        reason: "referenced file does not exist",
      });
    }

    if (fileReadError) {
      invalidEntries.push({
        index_position: indexPos,
        path: relPath,
        reason: `movie file is not valid JSON: ${fileReadError}`,
      });
      continue;
    }

    const imdbId = normalizeImdbId(entry.imdb_id) || getImdbIdFromMovieFile(filePayload);
    if (!imdbId) {
      invalidEntries.push({
        index_position: indexPos,
        path: relPath,
        title: String(entry.title || "").trim(),
        reason: "no valid IMDb ID found in index entry or movie file",
      });
      continue;
    }

    const indexTmdbId = getMovieTmdbId(entry.tmdb);
    const fileTmdbId = getTmdbIdFromMovieFile(filePayload);
    const existingTmdbIds = [indexTmdbId, fileTmdbId].filter((value) => value > 0);
    const title =
      String(entry.title || "").trim() || String(filePayload?.title || "").trim();
    const year = coerceYear(entry.year) || coerceYear(filePayload?.year);

    const ref = {
      index_position: indexPos,
      path: relPath,
      abs_path: absPath,
      title,
      year,
      existing_tmdb_id: existingTmdbIds[0] || 0,
      file_has_tmdb: fileTmdbId > 0,
      index_has_tmdb: indexTmdbId > 0,
    };

    if (!groups.has(imdbId)) {
      groups.set(imdbId, {
        imdb_id: imdbId,
        references: [],
        existing_tmdb_ids: new Set(),
      });
    }
    const group = groups.get(imdbId);
    group.references.push(ref);
    for (const tmdbId of existingTmdbIds) {
      group.existing_tmdb_ids.add(tmdbId);
    }
  }

  const orphanFiles = [];
  let movieFiles = [];
  try {
    movieFiles = await fs.readdir(moviesDir);
  } catch {
    movieFiles = [];
  }
  for (const name of movieFiles) {
    if (!name.endsWith(".json")) {
      continue;
    }
    const absPath = path.join(moviesDir, name);
    if (!referencedMovieFiles.has(absPath)) {
      orphanFiles.push({
        path: path.relative(repoRoot, absPath),
        reason: "movie file is not referenced by index.json",
      });
    }
  }

  return {
    indexPayload,
    groups,
    brokenPaths,
    invalidEntries,
    orphanFiles,
  };
}

function escapeMarkdown(value) {
  return String(value ?? "")
    .replace(/\|/g, "\\|")
    .replace(/\n/g, " ")
    .trim();
}

function buildMarkdownReport(report) {
  const lines = [];
  lines.push("# TMDb ID Backfill Report");
  lines.push("");
  lines.push(`Generated: ${report.generated_at}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Count |");
  lines.push("| --- | ---: |");
  for (const [key, value] of Object.entries(report.summary)) {
    lines.push(`| ${escapeMarkdown(key)} | ${escapeMarkdown(value)} |`);
  }
  lines.push("");
  lines.push("## TMDb Key Source");
  lines.push("");
  lines.push(`- Type: ${escapeMarkdown(report.tmdb_key_source.type)}`);
  lines.push(`- Location: ${escapeMarkdown(report.tmdb_key_source.location)}`);
  lines.push("");

  const mappingSections = [
    ["already_present", "Already Present"],
    ["matched", "Matched By Lookup"],
    ["no_match", "No Match"],
    ["ambiguous", "Ambiguous"],
    ["suspicious", "Suspicious"],
    ["invalid_entries", "Invalid Entries"],
    ["broken_paths", "Broken Paths"],
    ["orphan_files", "Orphan Files"],
  ];

  for (const [key, title] of mappingSections) {
    const items = report[key] || [];
    lines.push(`## ${title}`);
    lines.push("");
    if (!items.length) {
      lines.push("_None_");
      lines.push("");
      continue;
    }

    if (key === "already_present" || key === "matched") {
      lines.push("| IMDb | TMDb | Title | Release Date | Source | References |");
      lines.push("| --- | ---: | --- | --- | --- | ---: |");
      for (const item of items) {
        lines.push(
          `| ${escapeMarkdown(item.imdb_id)} | ${escapeMarkdown(item.tmdb_id)} | ${escapeMarkdown(item.tmdb_title)} | ${escapeMarkdown(item.tmdb_release_date)} | ${escapeMarkdown(item.source)} | ${escapeMarkdown(item.reference_count)} |`,
        );
      }
      lines.push("");
      continue;
    }

    if (key === "no_match") {
      lines.push("| IMDb | Title | References | Note |");
      lines.push("| --- | --- | ---: | --- |");
      for (const item of items) {
        lines.push(
          `| ${escapeMarkdown(item.imdb_id)} | ${escapeMarkdown(item.local_title)} | ${escapeMarkdown(item.reference_count)} | ${escapeMarkdown(item.note)} |`,
        );
      }
      lines.push("");
      continue;
    }

    if (key === "ambiguous") {
      for (const item of items) {
        lines.push(`- \`${escapeMarkdown(item.imdb_id)}\` (${escapeMarkdown(item.local_title)})`);
        for (const candidate of item.candidates || []) {
          lines.push(
            `  - TMDb ${escapeMarkdown(candidate.tmdb_id)}: ${escapeMarkdown(candidate.title)} (${escapeMarkdown(candidate.release_date)})`,
          );
        }
      }
      lines.push("");
      continue;
    }

    if (key === "suspicious") {
      for (const item of items) {
        lines.push(
          `- \`${escapeMarkdown(item.imdb_id)}\` -> TMDb ${escapeMarkdown(item.candidate.tmdb_id)} (${escapeMarkdown(item.candidate.title)})`,
        );
        for (const reason of item.reasons || []) {
          lines.push(`  - ${escapeMarkdown(reason)}`);
        }
      }
      lines.push("");
      continue;
    }

    for (const item of items) {
      lines.push(`- ${escapeMarkdown(JSON.stringify(item))}`);
    }
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function logProgress(pos, total, imdbId, summary) {
  const current = pos + 1;
  if (current === 1 || current === total || current % PROGRESS_EVERY === 0) {
    console.log(
      `[${current}/${total}] ${imdbId} | matched=${summary.matched} existing=${summary.already_present} no_match=${summary.no_match} ambiguous=${summary.ambiguous} suspicious=${summary.suspicious} invalid=${summary.invalid_entries}`,
    );
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(args.repoRoot || path.join(thisDir, ".."));
  const indexFile = path.resolve(args.indexFile || path.join(repoRoot, "index.json"));
  const moviesDir = path.resolve(args.moviesDir || path.join(repoRoot, "movies"));
  const outputDir = path.resolve(args.outputDir || path.join(repoRoot, "reports", "tmdb-id-backfill"));

  const { apiKey, source: apiKeySource } = await resolveTmdbApiKey(args.settingsPath);
  const { indexPayload, groups, brokenPaths, invalidEntries, orphanFiles } = await collectRepoData(
    indexFile,
    moviesDir,
    repoRoot,
  );

  const imdbIds = [...groups.keys()].sort();
  const limit = args.limit ? Math.min(args.limit, imdbIds.length) : imdbIds.length;
  const selectedImdbIds = imdbIds.slice(0, limit);

  const matched = [];
  const alreadyPresent = [];
  const noMatch = [];
  const ambiguous = [];
  const suspicious = [];
  const mappings = {};

  console.log(`Scanning ${indexFile}`);
  console.log(`Using TMDb key from ${apiKeySource.type}:${apiKeySource.location}`);
  console.log(
    `Found ${Array.isArray(indexPayload.movies) ? indexPayload.movies.length : 0} movie rows and ${imdbIds.length} unique IMDb IDs.`,
  );
  console.log(`Processing ${selectedImdbIds.length} IMDb IDs${args.limit ? ` (limited by --limit=${args.limit})` : ""}...`);

  for (let pos = 0; pos < selectedImdbIds.length; pos += 1) {
    const imdbId = selectedImdbIds[pos];
    const group = groups.get(imdbId);
    const titles = [...new Set(group.references.map((ref) => ref.title).filter(Boolean))];
    const localTitle = titles[0] || "";
    const existingTmdbIds = [...group.existing_tmdb_ids].sort((a, b) => a - b);

    if (existingTmdbIds.length > 1) {
      invalidEntries.push({
        imdb_id: imdbId,
        title: localTitle,
        reason: `conflicting existing TMDb IDs: ${existingTmdbIds.join(", ")}`,
        references: group.references.map((ref) => ref.path),
      });
      logProgress(pos, selectedImdbIds.length, imdbId, {
        matched: matched.length,
        already_present: alreadyPresent.length,
        no_match: noMatch.length,
        ambiguous: ambiguous.length,
        suspicious: suspicious.length,
        invalid_entries: invalidEntries.length,
      });
      continue;
    }

    if (existingTmdbIds.length === 1) {
      const resolved = {
        imdb_id: imdbId,
        tmdb_id: existingTmdbIds[0],
        tmdb_title: "",
        tmdb_original_title: "",
        tmdb_release_date: "",
        local_title: localTitle,
        reference_count: group.references.length,
        reference_paths: group.references.map((ref) => ref.path),
        source: "existing",
      };
      alreadyPresent.push(resolved);
      mappings[imdbId] = resolved;
      logProgress(pos, selectedImdbIds.length, imdbId, {
        matched: matched.length,
        already_present: alreadyPresent.length,
        no_match: noMatch.length,
        ambiguous: ambiguous.length,
        suspicious: suspicious.length,
        invalid_entries: invalidEntries.length,
      });
      continue;
    }

    const payload = await fetchTmdbFind(imdbId, apiKey, args.timeoutMs);
    const movieResults = Array.isArray(payload?.movie_results) ? payload.movie_results : [];

    if (movieResults.length === 0) {
      noMatch.push({
        imdb_id: imdbId,
        local_title: localTitle,
        reference_count: group.references.length,
        reference_paths: group.references.map((ref) => ref.path),
        note: `no movie_results (tv_results=${Array.isArray(payload?.tv_results) ? payload.tv_results.length : 0})`,
      });
      logProgress(pos, selectedImdbIds.length, imdbId, {
        matched: matched.length,
        already_present: alreadyPresent.length,
        no_match: noMatch.length,
        ambiguous: ambiguous.length,
        suspicious: suspicious.length,
        invalid_entries: invalidEntries.length,
      });
      continue;
    }

    if (movieResults.length > 1) {
      ambiguous.push({
        imdb_id: imdbId,
        local_title: localTitle,
        reference_count: group.references.length,
        reference_paths: group.references.map((ref) => ref.path),
        candidates: movieResults.slice(0, 10).map(summarizeCandidate),
      });
      logProgress(pos, selectedImdbIds.length, imdbId, {
        matched: matched.length,
        already_present: alreadyPresent.length,
        no_match: noMatch.length,
        ambiguous: ambiguous.length,
        suspicious: suspicious.length,
        invalid_entries: invalidEntries.length,
      });
      continue;
    }

    const candidate = movieResults[0];
    const reasons = candidateLooksSuspicious(group, candidate);
    if (reasons.length) {
      suspicious.push({
        imdb_id: imdbId,
        local_title: localTitle,
        reference_count: group.references.length,
        reference_paths: group.references.map((ref) => ref.path),
        candidate: summarizeCandidate(candidate),
        reasons,
      });
      logProgress(pos, selectedImdbIds.length, imdbId, {
        matched: matched.length,
        already_present: alreadyPresent.length,
        no_match: noMatch.length,
        ambiguous: ambiguous.length,
        suspicious: suspicious.length,
        invalid_entries: invalidEntries.length,
      });
      continue;
    }

    const resolved = {
      imdb_id: imdbId,
      tmdb_id: Number(candidate.id || 0) || 0,
      tmdb_title: String(candidate.title || "").trim(),
      tmdb_original_title: String(candidate.original_title || "").trim(),
      tmdb_release_date: String(candidate.release_date || "").trim(),
      local_title: localTitle,
      reference_count: group.references.length,
      reference_paths: group.references.map((ref) => ref.path),
      source: "lookup",
    };
    matched.push(resolved);
    mappings[imdbId] = resolved;
    logProgress(pos, selectedImdbIds.length, imdbId, {
      matched: matched.length,
      already_present: alreadyPresent.length,
      no_match: noMatch.length,
      ambiguous: ambiguous.length,
      suspicious: suspicious.length,
      invalid_entries: invalidEntries.length,
    });
  }

  const report = {
    generated_at: new Date().toISOString(),
    tmdb_key_source: apiKeySource,
    input: {
      repo_root: repoRoot,
      index_file: indexFile,
      movies_dir: moviesDir,
      limit: args.limit,
      timeout_ms: args.timeoutMs,
    },
    summary: {
      index_movie_rows: Array.isArray(indexPayload.movies) ? indexPayload.movies.length : 0,
      unique_imdb_ids: imdbIds.length,
      imdb_ids_processed: selectedImdbIds.length,
      matched: matched.length,
      already_present: alreadyPresent.length,
      no_match: noMatch.length,
      ambiguous: ambiguous.length,
      suspicious: suspicious.length,
      invalid_entries: invalidEntries.length,
      broken_paths: brokenPaths.length,
      orphan_files: orphanFiles.length,
    },
    mappings,
    already_present: alreadyPresent,
    matched,
    no_match: noMatch,
    ambiguous,
    suspicious,
    invalid_entries: invalidEntries,
    broken_paths: brokenPaths,
    orphan_files: orphanFiles,
  };

  await fs.mkdir(outputDir, { recursive: true });
  const jsonPath = path.join(outputDir, "tmdb-id-backfill-report.json");
  const mdPath = path.join(outputDir, "tmdb-id-backfill-report.md");
  await fs.writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await fs.writeFile(mdPath, buildMarkdownReport(report), "utf8");

  console.log(`Report written to ${jsonPath}`);
  console.log(`Markdown summary written to ${mdPath}`);
  console.log(JSON.stringify(report.summary, null, 2));
}

main().catch((error) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  console.error(message);
  process.exit(1);
});
