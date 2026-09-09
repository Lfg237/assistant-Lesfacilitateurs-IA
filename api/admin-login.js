const crypto = require("crypto");

function send(res, status, data) {
  res
    .status(status)
    .setHeader("Content-Type", "application/json; charset=utf-8")
    .end(JSON.stringify(data));
}

function sign(payload, secret) {
  const b = Buffer.from(JSON.stringify(payload)).toString("base64url");

  const s = crypto
    .createHmac("sha256", secret)
    .update(b)
    .digest("base64url");

  return b + "." + s;
}

module.exports = async (req, res) => {

  // Autoriser uniquement POST
  if (req.method !== "POST") {
    return send(res, 405, {
      error: "Méthode non autorisée"
    });
  }

  // Variables secrètes configurées dans Vercel
  const code = process.env.ADMIN_CODE;
  const secret = process.env.ADMIN_SESSION_SECRET;

  if (!code || !secret) {
    return send(res, 500, {
      error: "Variables Vercel manquantes"
    });
  }

  try {

    const body =
      typeof req.body === "string"
        ? JSON.parse(req.body || "{}")
        : (req.body || {});

    // Vérification du code administrateur
    if (String(body.code || "") !== String(code)) {
      return send(res, 401, {
        error: "Code administrateur incorrect"
      });
    }

    // Création d'une session valable 8 heures
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 28800;

    const token = sign(
      {
        role: "admin",
        iat: now,
        exp: exp
      },
      secret
    );

    return send(res, 200, {
      ok: true,
      token: token,
      expiresAt: exp
    });

  } catch (e) {

    return send(res, 400, {
      error: "Requête invalide"
    });

  }
};
