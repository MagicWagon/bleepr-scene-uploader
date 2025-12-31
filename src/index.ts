import { SignJWT, importPKCS8 } from "jose";

type Env = {
  GITHUB_APP_ID: string;
  GITHUB_INSTALLATION_ID: string;
  GITHUB_PRIVATE_KEY_PEM: string;
  BLEEPR_SUBMIT_KEY?: string;
};

const OWNER = "MagicWagon";
const REPO = "scene-lists";

function jsonError(status: number, code: string, message: string, details?: unknown) {
  return Response.json(
    { ok: false, error: { code, message, details: details ?? null } },
    { status, headers: { "Content-Type": "application/json" } },
  );
}

function base64encodeUtf8(input: string): string {
  return btoa(unescape(encodeURIComponent(input)));
}

function normalizeWorkerPath(pathname: string) {
  return pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

function sanitizeScenePath(scenePath: string): string | null {
  const p = (scenePath || "").trim();
  if (!p) return null;
  if (p.startsWith("/") || p.includes("\\") || p.includes("..")) return null;
  if (!p.startsWith("scenejsons/")) return null;
  if (!p.endsWith(".json")) return null;
  if (p.length > 180) return null;
  return p;
}

async function githubFetch(token: string, url: string, init?: RequestInit) {
  const resp = await fetch(url, {
    ...init,
    headers: {
      "User-Agent": "Bleepr-Worker/1.0",
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      ...(init?.headers || {}),
    },
  });
  const text = await resp.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!resp.ok) {
    throw new Error(`GitHub API failed (${resp.status}): ${typeof data === "string" ? data : JSON.stringify(data)}`);
  }
  return data;
}

async function mintAppJwt(env: Env): Promise<string> {
  const appId = String(env.GITHUB_APP_ID || "").trim();
  const pem = String(env.GITHUB_PRIVATE_KEY_PEM || "").trim();
  if (!appId || !pem) throw new Error("Missing GitHub App credentials.");

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };

  const key = await importPKCS8(pem, "RS256");

  return await new SignJWT({})
    .setProtectedHeader(header)
    .setIssuer(appId)
    .setIssuedAt(now)
    .setExpirationTime(now + 9 * 60)
    .sign(key);
}

async function mintInstallationToken(env: Env): Promise<string> {
  const installationId = String(env.GITHUB_INSTALLATION_ID || "").trim();
  if (!installationId) throw new Error("Missing GITHUB_INSTALLATION_ID.");

  const jwt = await mintAppJwt(env);

  const resp = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      "User-Agent": "Bleepr-Worker/1.0",
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${jwt}`,
    },
  });

  const data = await resp.json().catch(() => null);
  if (!resp.ok) throw new Error(`Installation token mint failed (${resp.status}): ${JSON.stringify(data)}`);

  const token = String(data?.token || "").trim();
  if (!token) throw new Error("Installation token response missing token.");
  return token;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = normalizeWorkerPath(url.pathname);

    if (request.method !== "POST" || path !== "/submit-scene") {
      return new Response("not found", { status: 404 });
    }

    // Optional shared-secret protection (recommended).
    const submitKey = String(env.BLEEPR_SUBMIT_KEY || "").trim();
    if (submitKey) {
      const auth = request.headers.get("authorization") || "";
      if (auth !== `Bearer ${submitKey}`) {
        return jsonError(401, "unauthorized", "Missing or invalid Authorization bearer token.");
      }
    }

    let body: any;
    try {
      body = await request.json();
    } catch {
      return jsonError(400, "bad_json", "Body must be valid JSON.");
    }

    const sceneList = body?.scene_list;
    const scenePathRaw = body?.scene_path;

    if (!sceneList || typeof sceneList !== "object") {
      return jsonError(400, "bad_request", "Missing scene_list object.");
    }

    const schemaVersion = Number(sceneList.schema_version || 0);
    if (schemaVersion !== 2) {
      return jsonError(400, "bad_schema", "scene_list.schema_version must be 2.");
    }

    const imdbId = String(sceneList.imdb_id || "").trim().toLowerCase();
    if (!/^tt\d{7,9}$/.test(imdbId)) {
      return jsonError(400, "bad_imdb_id", "scene_list.imdb_id must look like tt1234567.");
    }

    const scenes = sceneList.scenes;
    if (!Array.isArray(scenes) || scenes.length === 0) {
      return jsonError(400, "no_scenes", "scene_list.scenes must be a non-empty array.");
    }
    if (scenes.length > 2500) {
      return jsonError(400, "too_many_scenes", "scene_list.scenes is too large.");
    }

    const scenePath = sanitizeScenePath(String(scenePathRaw || ""));
    if (!scenePath) {
      return jsonError(400, "bad_scene_path", "scene_path must be under scenejsons/ and end with .json.");
    }

    // Size guardrail
    const raw = new TextEncoder().encode(JSON.stringify(body));
    if (raw.byteLength > 900_000) {
      return jsonError(413, "payload_too_large", "Payload too large.");
    }

    let installationToken: string;
    try {
      installationToken = await mintInstallationToken(env);
    } catch (e: any) {
      return jsonError(500, "auth_failed", "Failed to mint GitHub installation token.", String(e?.message || e));
    }

    try {
      const repoInfo = await githubFetch(
        installationToken,
        `https://api.github.com/repos/${OWNER}/${REPO}`,
      );
      const baseBranch = String(repoInfo?.default_branch || "main");

      const refInfo = await githubFetch(
        installationToken,
        `https://api.github.com/repos/${OWNER}/${REPO}/git/ref/heads/${encodeURIComponent(baseBranch)}`,
      );
      const baseSha = String(refInfo?.object?.sha || "");
      if (!baseSha) throw new Error("Missing base SHA.");

      const branch = `bleepr/upload/${imdbId}/${Date.now()}`;

      await githubFetch(installationToken, `https://api.github.com/repos/${OWNER}/${REPO}/git/refs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: baseSha }),
      });

      // Upload scene file
      await githubFetch(installationToken, `https://api.github.com/repos/${OWNER}/${REPO}/contents/${scenePath}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: `Add scene list for ${sceneList.title || imdbId} (${imdbId})`,
          content: base64encodeUtf8(JSON.stringify(sceneList, null, 2)),
          branch,
        }),
      });

      // Update index.json
      const indexResp = await githubFetch(
        installationToken,
        `https://api.github.com/repos/${OWNER}/${REPO}/contents/index.json?ref=${encodeURIComponent(branch)}`,
      );
      const indexSha = String(indexResp?.sha || "");
      const indexContentB64 = String(indexResp?.content || "");
      const indexText = indexContentB64 ? decodeURIComponent(escape(atob(indexContentB64.replace(/\n/g, "")))) : "{}";

      let indexJson: any = {};
      try {
        indexJson = JSON.parse(indexText);
      } catch {
        indexJson = {};
      }
      if (!indexJson || typeof indexJson !== "object") indexJson = {};
      if (!Array.isArray(indexJson.movies)) indexJson.movies = [];

      indexJson.movies.push({
        imdb_id: imdbId,
        title: String(sceneList.title || "").trim(),
        path: scenePath,
        created_at: String(sceneList.created_at || "").trim(),
        video_duration_ms: Number(sceneList.video_duration_ms || 0) || 0,
        label: String(sceneList.label || "").trim(),
      });

      await githubFetch(installationToken, `https://api.github.com/repos/${OWNER}/${REPO}/contents/index.json`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: `Update index for ${sceneList.title || imdbId} (${imdbId})`,
          content: base64encodeUtf8(JSON.stringify(indexJson, null, 2)),
          sha: indexSha,
          branch,
        }),
      });

      const pr = await githubFetch(installationToken, `https://api.github.com/repos/${OWNER}/${REPO}/pulls`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: `Add scene list: ${sceneList.title || imdbId} (${imdbId})`,
          head: `${OWNER}:${branch}`,
          base: baseBranch,
          body: `IMDb: ${imdbId}\nPath: ${scenePath}\nCreated: ${sceneList.created_at || ""}\n`,
        }),
      });

      const prUrl = String(pr?.html_url || "").trim();
      if (!prUrl) throw new Error("PR created but missing html_url.");

      return Response.json({ ok: true, pr_url: prUrl });
    } catch (e: any) {
      return jsonError(500, "github_error", "Failed to create pull request.", String(e?.message || e));
    }
  },
};
