const crypto = require("crypto");

const GITHUB_API = "https://api.github.com";

function send(res, status, data) {
  res
    .status(status)
    .setHeader("Content-Type", "application/json; charset=utf-8")
    .end(JSON.stringify(data));
}

function base64Decode(value) {
  return Buffer.from(value, "base64").toString("utf8");
}

function base64Encode(value) {
  return Buffer.from(value, "utf8").toString("base64");
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a || ""));
  const B = Buffer.from(String(b || ""));

  if (A.length !== B.length) return false;

  return crypto.timingSafeEqual(A, B);
}

function verifyToken(token, secret) {
  try {
    const parts = String(token || "").split(".");

    if (parts.length !== 2) return false;

    const payloadBase64 = parts[0];
    const signature = parts[1];

    const expected = crypto
      .createHmac("sha256", secret)
      .update(payloadBase64)
      .digest("base64url");

    if (!safeEqual(signature, expected)) {
      return false;
    }

    const payload = JSON.parse(
      Buffer.from(payloadBase64, "base64url").toString("utf8")
    );

    if (payload.role !== "admin") return false;

    if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) {
      return false;
    }

    return true;

  } catch (e) {
    return false;
  }
}

function getToken(req) {
  const authorization = req.headers.authorization || "";

  if (authorization.startsWith("Bearer ")) {
    return authorization.substring(7).trim();
  }

  return String(req.headers["x-admin-token"] || "").trim();
}

function normalize(data) {
  return {
    version: Number(data.version || 3),

    servicesWhatsapp: Array.isArray(data.servicesWhatsapp)
      ? data.servicesWhatsapp
      : [],

    services: Array.isArray(data.services)
      ? data.services
      : [],

    connaissances: Array.isArray(data.connaissances)
      ? data.connaissances
      : [],

    regles: Array.isArray(data.regles)
      ? data.regles
      : [],

    recommandations: Array.isArray(data.recommandations)
      ? data.recommandations
      : [],

    medias: Array.isArray(data.medias)
      ? data.medias
      : [],

    annonces: Array.isArray(data.annonces)
      ? data.annonces
      : [],

    statuts: Array.isArray(data.statuts)
      ? data.statuts
      : []
  };
}

function githubHeaders(token) {
  return {
    "Authorization": `Bearer ${token}`,
    "Accept": "application/vnd.github+json",
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "LFG-Assistant-IA"
  };
}

async function getGithubFile({
  token,
  owner,
  repo,
  path,
  branch
}) {
  const url =
    `${GITHUB_API}/repos/${encodeURIComponent(owner)}` +
    `/${encodeURIComponent(repo)}/contents/${path}` +
    `?ref=${encodeURIComponent(branch)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: githubHeaders(token)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(
      data.message || `GitHub HTTP ${response.status}`
    );

    error.status = response.status;

    throw error;
  }

  if (!data.content) {
    throw new Error("Le fichier GitHub ne contient aucune donnée.");
  }

  return {
    sha: data.sha,
    content: base64Decode(data.content.replace(/\n/g, ""))
  };
}

async function saveGithubFile({
  token,
  owner,
  repo,
  path,
  branch,
  sha,
  content
}) {
  const url =
    `${GITHUB_API}/repos/${encodeURIComponent(owner)}` +
    `/${encodeURIComponent(repo)}/contents/${path}`;

  const body = {
    message: "Mise à jour de la mémoire IA LESFACILITATEURS",
    content: base64Encode(content),
    branch: branch
  };

  if (sha) {
    body.sha = sha;
  }

  const response = await fetch(url, {
    method: "PUT",
    headers: githubHeaders(token),
    body: JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(
      data.message || `GitHub HTTP ${response.status}`
    );

    error.status = response.status;

    throw error;
  }

  return data;
}

module.exports = async (req, res) => {

  const token = process.env.GITHUB_TOKEN;
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || "main";
  const path =
    process.env.GITHUB_MEMORY_PATH ||
    "data/ai-memory.json";

  const adminSecret =
    process.env.ADMIN_SESSION_SECRET;

  /*
   * Vérification de la configuration
   */
  if (!token || !owner || !repo) {
    return send(res, 500, {
      error:
        "Configuration GitHub incomplète dans Vercel."
    });
  }

  /*
   * GET
   * Les utilisateurs peuvent récupérer
   * la mémoire publique.
   */
  if (req.method === "GET") {

    try {

      const file = await getGithubFile({
        token,
        owner,
        repo,
        path,
        branch
      });

      let memory;

      try {
        memory = JSON.parse(file.content);
      } catch (e) {
        return send(res, 500, {
          error:
            "Le fichier ai-memory.json contient un JSON invalide."
        });
      }

      return send(res, 200, normalize(memory));

    } catch (e) {

      return send(res, e.status || 500, {
        error:
          "Impossible de lire la mémoire GitHub.",
        detail: e.message
      });

    }
  }

  /*
   * POST
   * Seul l'administrateur connecté
   * peut modifier la mémoire.
   */
  if (req.method === "POST") {

    if (!adminSecret) {
      return send(res, 500, {
        error:
          "ADMIN_SESSION_SECRET manque dans Vercel."
      });
    }

    const adminToken = getToken(req);

    if (!verifyToken(adminToken, adminSecret)) {
      return send(res, 401, {
        error:
          "Session administrateur invalide ou expirée."
      });
    }

    try {

      const body =
        typeof req.body === "string"
          ? JSON.parse(req.body || "{}")
          : (req.body || {});

      const memory = normalize(body);

      const content =
        JSON.stringify(memory, null, 2) + "\n";

      /*
       * On récupère le SHA actuel.
       * GitHub en a besoin pour modifier le fichier.
       */
      let currentFile = null;

      try {

        currentFile = await getGithubFile({
          token,
          owner,
          repo,
          path,
          branch
        });

      } catch (e) {

        /*
         * Si le fichier n'existe pas encore,
         * on pourra le créer sans SHA.
         */
        if (e.status !== 404) {
          throw e;
        }
      }

      const result = await saveGithubFile({
        token,
        owner,
        repo,
        path,
        branch,
        sha: currentFile ? currentFile.sha : undefined,
        content
      });

      return send(res, 200, {
        ok: true,
        message:
          "Mémoire IA publiée sur GitHub.",
        commit:
          result.commit
            ? result.commit.sha
            : null
      });

    } catch (e) {

      return send(res, e.status || 500, {
        error:
          "Impossible de publier la mémoire IA.",
        detail: e.message
      });

    }
  }

  return send(res, 405, {
    error: "Méthode non autorisée"
  });
};
