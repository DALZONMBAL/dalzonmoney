const { app, initDb } = require("../server");

module.exports = async function handler(req, res) {
  try {
    await initDb();
    return app(req, res);
  } catch (error) {
    console.error("DALZON API initialization error:", error);
    return res.status(503).json({
      ok: false,
      message: "Base de données indisponible."
    });
  }
};
