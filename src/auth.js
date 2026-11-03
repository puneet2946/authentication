const jwt = require("jsonwebtoken");

function authenticateMiddleware(req, res, next) {
  const authorization = req.headers.authorization;
  const match = typeof authorization === "string"
    ? authorization.match(/^Bearer\s+(\S+)$/)
    : null;
  if (!match) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  let decoded;
  try {
    decoded = jwt.verify(match[1], process.env.JWT_SECRET, {
      algorithms: ["HS256"],
    });
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  req.user = decoded;
  return next();
}

module.exports = { authenticateMiddleware };
