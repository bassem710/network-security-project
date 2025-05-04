require("colors");
require("dotenv").config();
const cors = require("cors");
const express = require("express");
const mongoose = require("mongoose");

const Admin = require("./models/admin.model");

const globalError = require("./middlewares/error.middleware");
const adminRoutes = require("./routes/admin.routes");
const { SUPER_ADMIN } = require("./utils/constants");

// Express app
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to MongoDB
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGO_URI, {
    connectTimeoutMS: 30000,
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000
  })
  .then(async (conn) => {
    console.log(`Database Connected: ${conn.connection.host}`.green.bold);
    try {
      // Create default Super Admin
      const admin = await Admin.findOne({ role: SUPER_ADMIN });
      if (!admin) {
        const superAdmin = new Admin({
          fullName: "Super Admin",
          email: process.env.SUPER_ADMIN_EMAIL,
          password: process.env.SUPER_ADMIN_PASSWORD,
          role: SUPER_ADMIN,
          isVerified: true
        });
        console.log("=== Super admin created successfully ===".green);
        await superAdmin.hashNewPassword();
        await superAdmin.save();
      }
    } catch (error) {
      console.error("Error in database connection:", error);
      process.exit(1);
    }
  });

// CORS for security
app.use(cors());
app.options("*", cors());

// Routes
app.use("/admin", adminRoutes);

// Not Found Route
app.all("*", (req, res, next) => {
  res.status(404).json({
    message: `This Route (${req.originalUrl}) is not found`
  });
});

// Global Error Handler
app.use(globalError);

// Port Number
const PORT = process.env.PORT || 8000;

// Server
module.exports = require("http")
  .createServer(app)
  .listen(PORT, (_) => {
    console.log(`Running on port ${PORT}`.blue.bold);
  });
