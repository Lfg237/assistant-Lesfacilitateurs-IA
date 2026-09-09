const crypto = require("crypto");

const GH = "https://api.github.com";

function send(res, status, data) {
  res.status(status)
    .setHeader("Content-Type", "application/json; charset=utf-8")
    .setHeader("Cache-Control", "no-store")
    .end(JSON.stringify(data));
}

function verify(token, secret) {
  try {
    const [body, signature] = String(token || "").split(".");

    if (!body || !signature) return false;

    const expected = crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("base64url");

    if (
      signature.length !== expected.length ||
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return false;
    }

    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    );

    return (
      payload.role === "admin" &&
      Number(payload.exp) > Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

function cfg() {
  return {
    token: process.env.GITHUB_TOKEN,
    owner: process.env.GITHUB_OWNER,
    repo: process.env.GITHUB_REPO,
    branch: process.env.GITHUB_BRANCH || "main",
    path:
      process.env.GITHUB_MEMORY_PATH ||
      "data/ai-memory.json",
    secret: process.env.ADMIN_SESSION_SECRET
  };
}

function ghHeaders(c) {
  return {
    Accept: "application/vnd.github+json",
    Authorization: "Bearer " + c.token,
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json"
  };
}

function githubUrl(c) {
  return (
    GH +
    "/repos/" +
    encodeURIComponent(c.owner) +
    "/" +
    encodeURIComponent(c.repo) +
    "/contents/" +
    c.path
  );
}

async function getFile(c) {
  const url =
    githubUrl(c) +
    "?ref=" +
    encodeURIComponent(c.branch);

  const r = await fetch(url, {
    headers: ghHeaders(c)
  });

  const text = await r.text();

  let data = {};
  try {
    data = JSON.parse(text || "{}");
  } catch {}

  if (r.status === 404) {
    return {
      exists: false,
      status: 404,
      githubMessage: data.message || "Not Found",
      url
    };
  }

  if (!r.ok) {
    throw new Error(
      "GitHub GET " +
        r.status +
        " : " +
        (data.message || text || "Erreur GitHub")
    );
  }

  let decoded;

  try {
    decoded = Buffer.from(
      String(data.content || "").replace(/\n/g, ""),
      "base64"
    ).toString("utf8");
  } catch {
    throw new Error(
      "Le fichier GitHub est illisible."
    );
  }

  let memory;

  try {
    memory = JSON.parse(decoded);
  } catch {
    throw new Error(
      "Le fichier GitHub existe mais son contenu JSON est invalide."
    );
  }

  return {
    exists: true,
    sha: data.sha,
    data: memory,
    url
  };
}

function normalize(m) {
  m = m && typeof m === "object" ? m : {};

  return {
    version: Number(m.version || 4),
    updatedAt:
      m.updatedAt ||
      new Date().toISOString(),

    servicesWhatsapp:
      Array.isArray(m.servicesWhatsapp)
        ? m.servicesWhatsapp
        : [],

    services:
      Array.isArray(m.services)
        ? m.services
        : [],

    connaissances:
      Array.isArray(m.connaissances)
        ? m.connaissances
        : [],

    regles:
      Array.isArray(m.regles)
        ? m.regles
        : [],

    recommandations:
      Array.isArray(m.recommandations)
        ? m.recommandations
        : [],

    medias:
      Array.isArray(m.medias)
        ? m.medias
        : [],

    annonces:
      Array.isArray(m.annonces)
        ? m.annonces
        : [],

    statuts:
      Array.isArray(m.statuts)
        ? m.statuts
        : []
  };
}

function diagnostic404(c, phase, githubMessage) {
  const owner = String(c.owner || "");
  const repo = String(c.repo || "");

  if (!owner || !repo) {
    return {
      error: "Configuration GitHub incomplète.",
      detail:
        "GITHUB_OWNER ou GITHUB_REPO est vide.",
      phase
    };
  }

  if (phase === "lecture") {
    return {
      error:
        "GitHub a répondu 404 pendant la lecture.",
      detail:
        "Vérifiez GITHUB_OWNER, GITHUB_REPO, GITHUB_BRANCH et GITHUB_TOKEN. Un dépôt privé auquel le token n'a pas accès peut également répondre 404.",
      github:
        githubMessage || "Not Found",
      repository:
        owner + "/" + repo,
      branch: c.branch,
      path: c.path,
      phase
    };
  }

  return {
    error:
      "GitHub a répondu 404 pendant la publication.",
    detail:
      "Le dépôt indiqué par GITHUB_OWNER/GITHUB_REPO est introuvable pour le token, ou le token n'a pas les droits nécessaires sur ce dépôt.",
    github:
      githubMessage || "Not Found",
    repository:
      owner + "/" + repo,
    branch: c.branch,
    path: c.path,
    phase
  };
}

module.exports = async (req, res) => {
  const c = cfg();

  const missing = [];

  if (!c.token) missing.push("GITHUB_TOKEN");
  if (!c.owner) missing.push("GITHUB_OWNER");
  if (!c.repo) missing.push("GITHUB_REPO");
  if (!c.secret)
    missing.push("ADMIN_SESSION_SECRET");

  if (missing.length) {
    return send(res, 500, {
      error: "Variables Vercel manquantes.",
      missing
    });
  }

  try {
    /* =========================
       LECTURE DE LA MÉMOIRE
       ========================= */

    if (req.method === "GET") {
      const f = await getFile(c);

      if (!f.exists) {
        return send(
          res,
          404,
          diagnostic404(
            c,
            "lecture",
            f.githubMessage
          )
        );
      }

      return send(
        res,
        200,
        normalize(f.data)
      );
    }

    /* =========================
       PUBLICATION DE LA MÉMOIRE
       ========================= */

    if (req.method === "POST") {
      const authorization =
        req.headers.authorization || "";

      const xAdminToken =
        req.headers["x-admin-token"] || "";

      const sessionToken =
        authorization.startsWith("Bearer ")
          ? authorization.slice(7)
          : xAdminToken;

      if (!verify(sessionToken, c.secret)) {
        return send(res, 401, {
          error:
            "Session administrateur invalide ou expirée."
        });
      }

      const input =
        typeof req.body === "string"
          ? JSON.parse(req.body || "{}")
          : req.body || {};

      const memory = normalize(input);

      const old = await getFile(c);

      const payload = {
        message:
          "Mise à jour de la mémoire IA LESFACILITATEURS",

        content: Buffer.from(
          JSON.stringify(memory, null, 2),
          "utf8"
        ).toString("base64"),

        branch: c.branch
      };

      if (old.exists && old.sha) {
        payload.sha = old.sha;
      }

      const r = await fetch(
        githubUrl(c),
        {
          method: "PUT",
          headers: ghHeaders(c),
          body: JSON.stringify(payload)
        }
      );

      const text = await r.text();

      let data = {};

      try {
        data = JSON.parse(text || "{}");
      } catch {}

      if (!r.ok) {
        if (r.status === 404) {
          return send(
            res,
            404,
            diagnostic404(
              c,
              "publication",
              data.message || text
            )
          );
        }

        return send(res, r.status, {
          error:
            "GitHub HTTP " +
            r.status +
            " : " +
            (data.message ||
              text ||
              "Erreur GitHub"),

          repository:
            c.owner + "/" + c.repo,

          branch: c.branch,
          path: c.path
        });
      }

      return send(res, 200, {
        ok: true,
        message:
          "Mémoire IA publiée à distance.",

        updatedAt: memory.updatedAt,

        repository:
          c.owner + "/" + c.repo,

        branch: c.branch,
        path: c.path
      });
    }

    return send(res, 405, {
      error: "Méthode non autorisée."
    });

  } catch (e) {
    return send(res, 500, {
      error:
        e.message ||
        "Erreur serveur."
    });
  }
};