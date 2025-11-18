// authMiddleware.js
const jwt = require('jsonwebtoken');
const secret = 'Pjs-loginn';

module.exports = function auth(req, res, next) {
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      status: "error",
      message: "no token",
    });
  }

  try {
    const decoded = jwt.verify(token, secret);
    req.user = decoded;
    next();
  } catch (e) {
    console.error("JWT verify error:", e);
    return res.status(401).json({
      status: "error",
      message: "invalid token",
    });
  }
};
