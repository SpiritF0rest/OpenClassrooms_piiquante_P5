const express       = require("express");

const app           = express();
const mongoose      = require("mongoose");
const path          = require("path");

const saucesRoutes  = require("./routes/sauces")
const userRoutes    = require("./routes/user")

const helmet        = require("helmet");
const rateLimit     = require("express-rate-limit");

const dotenv        = require('dotenv').config();

// Connection to mongoDB.
mongoose.connect(process.env.DB_URI)
  .then(() => console.log("Connexion à MongoDB réussie !"))
  .catch(() => console.log("Connexion à MongoDB échouée !"));

// Method to parse the incoming requests with JSON payloads. 
app.use(express.json());

// General middleware defining headers.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content, Accept, Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
  next();
});

// Security against brute force attacks.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  standardHeaders: true,
  legacyHeaders: false,
});

// Configure headers for better security.
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }))

// Apply the rate limiting middleware to all requests.
app.use(limiter);

// Method to manage the image resource statically.
app.use("/images", express.static(path.join(__dirname, "images")));

// Add the router to the middleware management path, specifying a path.
app.use("/api/sauces", saucesRoutes);
app.use("/api/auth", userRoutes);

module.exports = app;