require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const { PrismaPg } = require("@prisma/adapter-pg");
const { authenticateMiddleware } = require("./auth");

if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
  throw new Error("DATABASE_URL and JWT_SECRET must be set in .env");
}

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
const prisma = new PrismaClient({ adapter });
const app = express();
app.use(express.json());

// TASK 1: Register a user (TODO)
app.post("/auth/register", async (req, res) => {
  const { email, password } = req.body ?? {};

  if (
    typeof email !== "string" ||
    !email.includes("@") ||
    typeof password !== "string" ||
    password.length < 8
  ) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) {
    return res.status(409).json({ message: "Email is already registered" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { email, password: hashedPassword },
    select: { id: true, email: true },
  });

  return res.status(201).json(user);
});

// TASK 2: Log in and issue a JWT (TODO)
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ message: "Email and password must be strings" });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  const accessToken = jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET,
    { expiresIn: "15m", algorithm: "HS256" },
  );

  return res.status(200).json({ accessToken });
});

// PUBLIC ROUTES: Already implemented; do not modify.
app.get("/public", (req, res) => {
  res.status(200).json({ message: "This is a public route" });
});

app.get("/about", (req, res) => {
  res.status(200).json({ message: "This application demonstrates JWT authentication" });
});

// PROTECTED ROUTES: Already implemented; do not modify.
app.get("/profile", authenticateMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: { id: true, email: true },
    });
    if (!user) return res.status(404).json({ message: "User not found" });
    return res.status(200).json(user);
  } catch (error) {
    console.error("Error loading profile:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/dashboard", authenticateMiddleware, (req, res) => {
  return res.status(200).json({
    message: "Welcome to your dashboard",
    userId: req.user.userId,
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
