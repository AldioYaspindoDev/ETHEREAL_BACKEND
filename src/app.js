import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import hpp from "hpp";
import slowDown from "express-slow-down";
import userCustomerRouter from "./routes/userCustomerRoute.js";
import userAdminRoute from "./routes/userAdminRoute.js";
import articleRoutes from "./routes/articleRoutes.js";
import catalogRoutes from "./routes/catalogRoute.js";
import feedbackRoute from "./routes/feedbackRoutes.js";
import keranjangrouter from "./routes/keranjangRoute.js";
import PortofolioRouter from "./routes/portofolioRoute.js";
import { errorHandler } from "./middleware/errorHandler.js";
import AppError from "./utils/AppError.js";

const app = express();

// ========================================
// TRUST PROXY
// ========================================
app.set("trust proxy", 1);

// ========================================
// SECURITY MIDDLEWARE
// ========================================

// 1. Helmet - Secure HTTP headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:", "res.cloudinary.com"],
        connectSrc: [
          "'self'",
          "http://localhost:3000",
          "http://localhost:5173",
          process.env.CLIENT_URL,
        ],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    frameguard: { action: "deny" },
    xssFilter: true,
    noSniff: true,
  })
);

// ========================================
// STANDARD MIDDLEWARE (Before Rate Limiting)
// ========================================

// Cookie Parser - Must be before CORS
app.use(cookieParser());

// CORS Configuration
const FRONTEND_URL = process.env.CLIENT_URL || "http://localhost:3000";

// Build allowed origins list
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173', // Vite
  'http://localhost:3001', // Alternative port
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
  FRONTEND_URL,
].filter((origin, index, self) => self.indexOf(origin) === index);

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (Postman, mobile apps, etc.)
    if (!origin) {
      console.log('✅ CORS: No origin (Postman/Mobile) - ALLOWED');
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      console.log(`✅ CORS: ${origin} - ALLOWED`);
      callback(null, true);
    } else {
      console.warn(`❌ CORS: ${origin} - BLOCKED`);
      console.warn(`   Allowed: ${allowedOrigins.join(', ')}`);
      callback(new Error(`Not allowed by CORS: ${origin}`));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Accept",
    "Origin"
  ],
  exposedHeaders: ["Set-Cookie"],
  preflightContinue: false,
  optionsSuccessStatus: 200,
  maxAge: 86400,
};

// Apply CORS
app.use(cors(corsOptions));

// Body Parser with size limit
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ========================================
// RATE LIMITING & SECURITY
// ========================================

// 2. Rate Limiting - General
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    success: false,
    message: "Terlalu banyak request dari IP ini, coba lagi dalam 15 menit",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    if (process.env.NODE_ENV === "development") {
      return req.ip === "127.0.0.1" || req.ip === "::1";
    }
    return false;
  },
});

// 3. Rate Limiting - Auth (Stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: {
    success: false,
    message: "Terlalu banyak percobaan login, coba lagi dalam 15 menit",
  },
});

// 4. Rate Limiting - Sensitive APIs
const strictLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    message: "Limit tercapai, coba lagi dalam 1 jam",
  },
});

// 5. Speed Limiter
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: (hits) => hits * 100,
  maxDelayMs: 5000,
});

// Apply global rate limiting
app.use(limiter);
app.use(speedLimiter);

// 6. NoSQL Injection Protection - CUSTOM IMPLEMENTATION (No library)
const sanitizeNoSQL = (req, res, next) => {
  const sanitize = (obj) => {
    if (!obj || typeof obj !== 'object') return;

    Object.keys(obj).forEach((key) => {
      // Remove keys that start with $ or contain dots (MongoDB operators)
      if (key.startsWith('$') || key.includes('.')) {
        console.warn(`⚠️ Sanitized potentially malicious input: ${key}`);
        delete obj[key];
      } 
      // Recursively sanitize nested objects
      else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitize(obj[key]);
      }
      // Also check for $where and other dangerous patterns in strings
      else if (typeof obj[key] === 'string') {
        // Remove potential MongoDB query injections
        const dangerous = ['$where', 'function', 'return'];
        if (dangerous.some(pattern => obj[key].includes(pattern))) {
          console.warn(`⚠️ Sanitized dangerous string pattern in: ${key}`);
          obj[key] = obj[key].replace(/(\$where|function|return)/gi, '');
        }
      }
    });
  };

  // Sanitize all request inputs
  try {
    if (req.body) sanitize(req.body);
    if (req.query) sanitize(req.query);
    if (req.params) sanitize(req.params);
  } catch (error) {
    console.error('❌ Sanitization error:', error);
  }

  next();
};

// Apply custom NoSQL sanitizer
app.use(sanitizeNoSQL);

// 7. HPP - HTTP Parameter Pollution
app.use(hpp());

// ========================================
// ROUTES
// ========================================

// Health Check (No rate limit)
app.get("/test", (req, res) => {
  res.json({
    success: true,
    message: "Server is running",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// Root Route
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "API is running",
    version: "2.0.0",
    endpoints: {
      health: "/test",
      admin: "/api/admin",
      customer: "/customer",
      articles: "/articles",
      catalogs: "/catalogs",
      feedbacks: "/feedbacks",
      cart: "/cart",
      portfolio: "/portofolio"
    }
  });
});

// Apply auth rate limiter to specific endpoints
app.use("/admin/login", authLimiter);
app.use("/admin/register", authLimiter);
app.use("/customer/login", authLimiter);
app.use("/customer/register", authLimiter);

// Main routes
app.use("/api/admin", userAdminRoute);
app.use("/api/customer", userCustomerRouter);
app.use("/articles", articleRoutes);
app.use("/catalogs", catalogRoutes);
app.use("/feedbacks", feedbackRoute);
app.use("/cart", keranjangrouter);
app.use("/portofolio", PortofolioRouter);

// ========================================
// ERROR HANDLERS
// ========================================

// 404 Handler - Must be after all routes
app.use((req, res, next) => {
  next(new AppError(`Route ${req.originalUrl} tidak ditemukan`, 404));
});

// Global Error Handler - Must be last
app.use(errorHandler);

export default app;