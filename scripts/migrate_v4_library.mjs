#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

function printHelp() {
  console.log(`V4 scene library migration tool

Usage:
  node scripts/migrate_v4_library.mjs [options]

Options:
  --repo-root <path>     Repo root to migrate. Default: uploader repo root
  --index-file <path>    Index file to migrate. Default: <repo-root>/index.json
  --output-dir <path>    Report directory. Default: <repo-root>/reports/v4-migration
  --apply                Write changes. Without this, the script is dry-run only.
  --help                 Show this help
`);
}

function parseArgs(argv) {
  const parsed = {
    repoRoot: null,
    indexFile: null,
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
    if (arg === "--index-file") {
      parsed.indexFile = argv[++i] || "";
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

function normalizeAsin(value) {
  const asin = String(value || "").trim().toUpperCase();
  return /^[A-Z0-9]{10}$/.test(asin) ? asin : "";
}

function safePositiveInt(value) {
  const num = Number(value || 0) || 0;
  return Number.isFinite(num) && num > 0 ? Math.trunc(num) : 0;
}

function normalizeTmdb(value, expectedType = "") {
  if (!value || typeof value !== "object") {
    return null;
  }
  const type = String(value.type || "").trim().toLowerCase();
  const id = safePositiveInt(value.id);
  if (!id || (type !== "movie" && type !== "tv")) {
    return null;
  }
  if (expectedType && type !== expectedType) {
    return null;
  }
  return { type, id };
}

function readIds(container, expectedType = "") {
  if (!container || typeof container !== "object") {
    return { tmdb: null, imdb: "" };
  }
  const ids = container.ids && typeof container.ids === "object" ? container.ids : container;
  return {
    tmdb: normalizeTmdb(ids.tmdb || container.tmdb, expectedType),
    imdb: normalizeImdbId(ids.imdb || container.imdb_id),
  };
}

function readScenes(rawPayload) {
  return Array.isArray(rawPayload?.scenes) ? rawPayload.scenes : null;
}

function readSubmittedAt(entry, rawPayload) {
  const value =
    String(rawPayload?.submitted_at || "").trim() ||
    String(rawPayload?.created_at || "").trim() ||
    String(entry?.submitted_at || "").trim() ||
    String(entry?.created_at || "").trim();
  return value || "";
}

function legacySceneListId(relPath) {
  return `legacy_${crypto.createHash("sha1").update(String(relPath || "").trim()).digest("hex").slice(0, 12)}`;
}

function sanitizeRelativePosix(relPath) {
  return String(relPath || "").trim().replace(/\\/g, "/").replace(/^\/+/, "");
}

function buildMovieWorkId(tmdbId) {
  return `tmdb:movie:${tmdbId}`;
}

function buildEpisodeWorkId(tmdbId, seasonNumber, episodeNumber) {
  return `tmdb:tv:${tmdbId}:s${String(seasonNumber).padStart(2, "0")}e${String(episodeNumber).padStart(2, "0")}`;
}

function buildAudiobookWorkId(asin) {
  return `asin:${asin}`;
}

function readExistingSceneListId(rawPayload, relPath) {
  const current = String(rawPayload?.scene_list_id || "").trim();
  return current || legacySceneListId(relPath);
}

function readMoviePayload(entry, rawPayload, relPath) {
  const scenes = readScenes(rawPayload);
  if (!scenes || scenes.length === 0) {
    return { error: "scene file has no scenes" };
  }

  const ids = readIds(rawPayload, "movie");
  const entryIds = readIds(entry, "movie");
  const tmdb = ids.tmdb || entryIds.tmdb;
  if (!tmdb || tmdb.type !== "movie" || tmdb.id <= 0) {
    return { error: "movie entry is missing a valid TMDb movie id" };
  }

  const imdbId = ids.imdb || entryIds.imdb;
  const sceneListId = readExistingSceneListId(rawPayload, relPath);
  const workId = String(rawPayload?.work_id || "").trim() || buildMovieWorkId(tmdb.id);
  const title = String(rawPayload?.title || entry?.title || "").trim();
  if (!title) {
    return { error: "movie entry is missing a title" };
  }

  const submittedAt = readSubmittedAt(entry, rawPayload);
  const label = String(rawPayload?.label || entry?.label || entry?.filter_label || "").trim();
  const year = safePositiveInt(rawPayload?.year || entry?.year);
  const videoDurationMs = safePositiveInt(rawPayload?.video_duration_ms || entry?.video_duration_ms);
  const payload = {
    schema_version: 4,
    content_type: "movie",
    scene_list_id: sceneListId,
    work_id: workId,
    ids: {
      tmdb: { type: "movie", id: tmdb.id },
      ...(imdbId ? { imdb: imdbId } : {}),
    },
    title,
    ...(year ? { year } : {}),
    ...(videoDurationMs ? { video_duration_ms: videoDurationMs } : {}),
    ...(submittedAt ? { submitted_at: submittedAt } : {}),
    ...(label ? { label } : {}),
    ...(rawPayload?.source !== undefined ? { source: rawPayload.source } : {}),
    ...(rawPayload?.source_app && typeof rawPayload.source_app === "object" ? { source_app: rawPayload.source_app } : {}),
    scenes,
  };
  const nextPath = `movies/tmdb_movie_${tmdb.id}/${sceneListId}.json`;
  const indexEntry = {
    scene_list_id: sceneListId,
    work_id: workId,
    content_type: "movie",
    title,
    path: nextPath,
    scene_count: scenes.length,
    ...(submittedAt ? { submitted_at: submittedAt } : {}),
    ...(label ? { label } : {}),
    ids: payload.ids,
    ...(year ? { year } : {}),
    ...(videoDurationMs ? { video_duration_ms: videoDurationMs } : {}),
  };
  return { payload, indexEntry, nextPath, workId, sceneListId };
}

function readEpisodePayload(entry, rawPayload, relPath) {
  const scenes = readScenes(rawPayload);
  if (!scenes || scenes.length === 0) {
    return { error: "episode scene file has no scenes" };
  }

  const ids = readIds(rawPayload, "tv");
  const entryIds = readIds(entry, "tv");
  const tmdb = ids.tmdb || entryIds.tmdb;
  if (!tmdb || tmdb.type !== "tv" || tmdb.id <= 0) {
    return { error: "episode entry is missing a valid TMDb tv id" };
  }

  const imdbId = ids.imdb || entryIds.imdb;
  const sceneListId = readExistingSceneListId(rawPayload, relPath);
  const seasonNumber = safePositiveInt(
    rawPayload?.season_number ||
      rawPayload?.episode?.season_number ||
      entry?.season_number,
  );
  const episodeNumber = safePositiveInt(
    rawPayload?.episode_number ||
      rawPayload?.episode?.episode_number ||
      entry?.episode_number,
  );
  if (!seasonNumber || !episodeNumber) {
    return { error: "episode entry is missing season/episode numbers" };
  }

  const seriesTitle = String(rawPayload?.series_title || rawPayload?.series?.title || entry?.series_title || "").trim();
  if (!seriesTitle) {
    return { error: "episode entry is missing a series title" };
  }

  const episodeTitle = String(rawPayload?.episode_title || rawPayload?.episode?.title || entry?.episode_title || "").trim();
  const title =
    String(rawPayload?.title || entry?.title || "").trim() ||
    [seriesTitle, `S${String(seasonNumber).padStart(2, "0")}E${String(episodeNumber).padStart(2, "0")}`, episodeTitle]
      .filter(Boolean)
      .join(" — ");
  const workId = String(rawPayload?.work_id || "").trim() || buildEpisodeWorkId(tmdb.id, seasonNumber, episodeNumber);
  const submittedAt = readSubmittedAt(entry, rawPayload);
  const label = String(rawPayload?.label || entry?.label || entry?.filter_label || "").trim();
  const year = safePositiveInt(rawPayload?.year || entry?.year);
  const videoDurationMs = safePositiveInt(rawPayload?.video_duration_ms || entry?.video_duration_ms);
  const payload = {
    schema_version: 4,
    content_type: "episode",
    scene_list_id: sceneListId,
    work_id: workId,
    ids: {
      tmdb: { type: "tv", id: tmdb.id },
      ...(imdbId ? { imdb: imdbId } : {}),
    },
    title,
    series_title: seriesTitle,
    season_number: seasonNumber,
    episode_number: episodeNumber,
    ...(episodeTitle ? { episode_title: episodeTitle } : {}),
    ...(year ? { year } : {}),
    ...(videoDurationMs ? { video_duration_ms: videoDurationMs } : {}),
    ...(submittedAt ? { submitted_at: submittedAt } : {}),
    ...(label ? { label } : {}),
    ...(rawPayload?.source !== undefined ? { source: rawPayload.source } : {}),
    ...(rawPayload?.source_app && typeof rawPayload.source_app === "object" ? { source_app: rawPayload.source_app } : {}),
    scenes,
  };
  const nextPath = `shows/tmdb_tv_${tmdb.id}/season${String(seasonNumber).padStart(2, "0")}/episode${String(episodeNumber).padStart(2, "0")}/${sceneListId}.json`;
  const indexEntry = {
    scene_list_id: sceneListId,
    work_id: workId,
    content_type: "episode",
    title,
    path: nextPath,
    scene_count: scenes.length,
    ...(submittedAt ? { submitted_at: submittedAt } : {}),
    ...(label ? { label } : {}),
    ids: payload.ids,
    series_title: seriesTitle,
    season_number: seasonNumber,
    episode_number: episodeNumber,
    ...(episodeTitle ? { episode_title: episodeTitle } : {}),
    ...(year ? { year } : {}),
    ...(videoDurationMs ? { video_duration_ms: videoDurationMs } : {}),
  };
  return { payload, indexEntry, nextPath, workId, sceneListId };
}

function readAudiobookPayload(entry, rawPayload, relPath) {
  const scenes = readScenes(rawPayload);
  if (!scenes || scenes.length === 0) {
    return { error: "audiobook scene file has no scenes" };
  }

  const audioMeta = rawPayload?.audiobook && typeof rawPayload.audiobook === "object" ? rawPayload.audiobook : entry?.audiobook;
  const asin = normalizeAsin(audioMeta?.asin);
  if (!asin) {
    return { error: "audiobook entry is missing a valid ASIN" };
  }

  const title = String(rawPayload?.title || entry?.title || "").trim();
  if (!title) {
    return { error: "audiobook entry is missing a title" };
  }

  const sceneListId = readExistingSceneListId(rawPayload, relPath);
  const workId = String(rawPayload?.work_id || "").trim() || buildAudiobookWorkId(asin);
  const submittedAt = readSubmittedAt(entry, rawPayload);
  const label = String(rawPayload?.label || entry?.label || entry?.filter_label || "").trim();
  const year = safePositiveInt(rawPayload?.year || entry?.year);
  const audioDurationMs = safePositiveInt(rawPayload?.audio_duration_ms || entry?.audio_duration_ms);
  const audiobook = {
    asin,
    ...(String(audioMeta?.author || "").trim() ? { author: String(audioMeta.author).trim() } : {}),
    ...(String(audioMeta?.narrator || "").trim() ? { narrator: String(audioMeta.narrator).trim() } : {}),
  };
  const payload = {
    schema_version: 4,
    content_type: "audiobook",
    scene_list_id: sceneListId,
    work_id: workId,
    title,
    audiobook,
    ...(year ? { year } : {}),
    ...(audioDurationMs ? { audio_duration_ms: audioDurationMs } : {}),
    ...(submittedAt ? { submitted_at: submittedAt } : {}),
    ...(label ? { label } : {}),
    ...(rawPayload?.source !== undefined ? { source: rawPayload.source } : {}),
    ...(rawPayload?.source_app && typeof rawPayload.source_app === "object" ? { source_app: rawPayload.source_app } : {}),
    scenes,
  };
  const nextPath = `audiobooks/asin_${asin}/${sceneListId}.json`;
  const indexEntry = {
    scene_list_id: sceneListId,
    work_id: workId,
    content_type: "audiobook",
    title,
    path: nextPath,
    scene_count: scenes.length,
    ...(submittedAt ? { submitted_at: submittedAt } : {}),
    ...(label ? { label } : {}),
    audiobook,
    ...(year ? { year } : {}),
    ...(audioDurationMs ? { audio_duration_ms: audioDurationMs } : {}),
  };
  return { payload, indexEntry, nextPath, workId, sceneListId };
}

function sortCatalog(indexJson) {
  indexJson.movies.sort((a, b) =>
    `${String(a.title || "").toLowerCase()}\u0000${String(a.submitted_at || "")}\u0000${String(a.path || "")}`.localeCompare(
      `${String(b.title || "").toLowerCase()}\u0000${String(b.submitted_at || "")}\u0000${String(b.path || "")}`,
    ),
  );
  indexJson.episodes.sort((a, b) =>
    `${String(a.series_title || "").toLowerCase()}\u0000${String(a.season_number || 0).padStart(4, "0")}\u0000${String(a.episode_number || 0).padStart(4, "0")}\u0000${String(a.submitted_at || "")}\u0000${String(a.path || "")}`.localeCompare(
      `${String(b.series_title || "").toLowerCase()}\u0000${String(b.season_number || 0).padStart(4, "0")}\u0000${String(b.episode_number || 0).padStart(4, "0")}\u0000${String(b.submitted_at || "")}\u0000${String(b.path || "")}`,
    ),
  );
  indexJson.audiobooks.sort((a, b) =>
    `${String(a.title || "").toLowerCase()}\u0000${String(a.submitted_at || "")}\u0000${String(a.path || "")}`.localeCompare(
      `${String(b.title || "").toLowerCase()}\u0000${String(b.submitted_at || "")}\u0000${String(b.path || "")}`,
    ),
  );
}

async function removeEmptyParents(startDir, stopDir) {
  let current = startDir;
  const stop = path.resolve(stopDir);
  while (current && current.startsWith(stop) && current !== stop) {
    try {
      const items = await fs.readdir(current);
      if (items.length > 0) {
        return;
      }
      await fs.rmdir(current);
    } catch {
      return;
    }
    current = path.dirname(current);
  }
}

function buildMarkdownReport(report) {
  const lines = [];
  lines.push("# V4 Migration Report");
  lines.push("");
  lines.push(`- Applied: ${report.applied ? "yes" : "no"}`);
  lines.push(`- Catalog updated at: ${report.catalog_updated_at}`);
  lines.push(`- Movies migrated: ${report.summary.movies_migrated}`);
  lines.push(`- Episodes migrated: ${report.summary.episodes_migrated}`);
  lines.push(`- Audiobooks migrated: ${report.summary.audiobooks_migrated}`);
  lines.push(`- Quarantined entries: ${report.summary.quarantined}`);
  lines.push(`- Path rewrites: ${report.summary.path_rewrites}`);
  lines.push("");
  if (report.quarantine.length) {
    lines.push("## Quarantine");
    lines.push("");
    for (const item of report.quarantine) {
      lines.push(`- ${item.section}: \`${item.path}\` — ${item.reason}`);
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(args.repoRoot || path.join(scriptDir, ".."));
  const indexFile = path.resolve(args.indexFile || path.join(repoRoot, "index.json"));
  const outputDir = path.resolve(args.outputDir || path.join(repoRoot, "reports", "v4-migration"));
  const apply = Boolean(args.apply);
  const now = new Date().toISOString();

  const rawIndex = await readJson(indexFile);
  if (!rawIndex || typeof rawIndex !== "object") {
    throw new Error("index.json must be a JSON object.");
  }

  const sections = [
    { name: "movies", builder: readMoviePayload },
    { name: "episodes", builder: readEpisodePayload },
    { name: "audiobooks", builder: readAudiobookPayload },
  ];

  const nextIndex = {
    schema_version: 4,
    catalog_updated_at: now,
    movies: [],
    episodes: [],
    audiobooks: [],
  };
  const writeOps = [];
  const quarantine = [];
  let pathRewrites = 0;

  for (const section of sections) {
    const entries = Array.isArray(rawIndex[section.name]) ? rawIndex[section.name] : [];
    for (const entry of entries) {
      if (!entry || typeof entry !== "object") {
        quarantine.push({ section: section.name, path: "", reason: "index entry is not an object" });
        continue;
      }
      const relPath = sanitizeRelativePosix(entry.path);
      if (!relPath) {
        quarantine.push({ section: section.name, path: "", reason: "index entry is missing a path" });
        continue;
      }
      const absPath = path.join(repoRoot, relPath);
      if (!(await fileExists(absPath))) {
        quarantine.push({ section: section.name, path: relPath, reason: "referenced file is missing" });
        continue;
      }
      let rawPayload;
      try {
        rawPayload = await readJson(absPath);
      } catch (error) {
        quarantine.push({ section: section.name, path: relPath, reason: `failed to parse JSON: ${error instanceof Error ? error.message : String(error)}` });
        continue;
      }
      if (!rawPayload || typeof rawPayload !== "object") {
        quarantine.push({ section: section.name, path: relPath, reason: "scene file must contain a JSON object" });
        continue;
      }

      const built = section.builder(entry, rawPayload, relPath);
      if (built.error) {
        quarantine.push({ section: section.name, path: relPath, reason: built.error });
        continue;
      }

      const nextAbsPath = path.join(repoRoot, built.nextPath);
      if (sanitizeRelativePosix(relPath) !== sanitizeRelativePosix(built.nextPath)) {
        pathRewrites += 1;
      }
      nextIndex[section.name].push(built.indexEntry);
      writeOps.push({
        section: section.name,
        currentPath: absPath,
        currentRelPath: relPath,
        nextPath: nextAbsPath,
        nextRelPath: built.nextPath,
        payload: built.payload,
      });
    }
  }

  sortCatalog(nextIndex);

  const report = {
    applied: apply,
    generated_at: now,
    catalog_updated_at: now,
    summary: {
      movies_migrated: nextIndex.movies.length,
      episodes_migrated: nextIndex.episodes.length,
      audiobooks_migrated: nextIndex.audiobooks.length,
      quarantined: quarantine.length,
      path_rewrites: pathRewrites,
    },
    quarantine,
    writes: writeOps.map((item) => ({
      section: item.section,
      from: item.currentRelPath,
      to: item.nextRelPath,
      scene_list_id: item.payload.scene_list_id,
      work_id: item.payload.work_id,
    })),
  };

  await fs.mkdir(outputDir, { recursive: true });
  const reportJsonPath = path.join(outputDir, "v4-migration-report.json");
  const reportMdPath = path.join(outputDir, "v4-migration-report.md");
  const quarantinePath = path.join(outputDir, "quarantine-manifest.json");

  if (apply) {
    const backupPath = path.join(outputDir, `index.json.backup.${now.replace(/[:.]/g, "-")}`);
    await fs.copyFile(indexFile, backupPath);

    for (const item of writeOps) {
      await fs.mkdir(path.dirname(item.nextPath), { recursive: true });
      await fs.writeFile(item.nextPath, `${JSON.stringify(item.payload, null, 2)}\n`, "utf8");
      if (path.resolve(item.currentPath) !== path.resolve(item.nextPath)) {
        await fs.unlink(item.currentPath);
        await removeEmptyParents(path.dirname(item.currentPath), repoRoot);
      }
    }

    await fs.writeFile(indexFile, `${JSON.stringify(nextIndex, null, 2)}\n`, "utf8");
    report.index_backup = path.relative(repoRoot, backupPath).replace(/\\/g, "/");
  }

  await fs.writeFile(reportJsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  await fs.writeFile(reportMdPath, buildMarkdownReport(report), "utf8");
  await fs.writeFile(quarantinePath, `${JSON.stringify(quarantine, null, 2)}\n`, "utf8");

  console.log(`Scanned ${writeOps.length + quarantine.length} indexed entries.`);
  console.log(`Migrated movies: ${nextIndex.movies.length}`);
  console.log(`Migrated episodes: ${nextIndex.episodes.length}`);
  console.log(`Migrated audiobooks: ${nextIndex.audiobooks.length}`);
  console.log(`Quarantined: ${quarantine.length}`);
  console.log(`Path rewrites: ${pathRewrites}`);
  console.log(`Applied: ${apply ? "yes" : "no"}`);
  console.log(`Report: ${reportJsonPath}`);
  console.log(`Quarantine: ${quarantinePath}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
