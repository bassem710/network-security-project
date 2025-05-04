const express = require("express");
const router = express.Router();
const Admin = require("../models/admin.model");
const { protect, allowedTo } = require("../middlewares/auth.middleware");
const { SUPER_ADMIN, ADMIN, MANAGER } = require("../utils/constants");

// @route   POST /api/admin/refresh-token
// @desc    Refresh token
// @access  Public
router.post("/refresh-token", protect, async (req, res) => {
  try {
    const admin = req.user;
    const { token, tokenExpDate } = await admin.generateToken();
    res.json({
      message: "Token refreshed successfully",
      token,
      tokenExpDate
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// @route   POST /api/admin/login
// @desc    Login admin
// @access  Public
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    // Check if admin exists
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    // Validate password
    const isMatch = await admin.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    // Generate token
    const { token, tokenExpDate } = await admin.generateToken();
    res.json({
      token,
      tokenExpDate,
      admin: {
        id: admin._id,
        fullName: admin.fullName,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// @route   POST /api/admin/logout
// @desc    Logout admin
// @access  Private
router.post("/logout", protect, async (req, res) => {
  try {
    req.user.token = null;
    await req.user.save();
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// @route   GET /api/admin
// @desc    Get all admins
// @access  Private (Super Admin, Admin)
router.get("/", protect, allowedTo(SUPER_ADMIN, ADMIN), async (req, res) => {
  try {
    const admins = await Admin.find({ _id: { $ne: req.user._id } }).select(
      "-password"
    );
    res.json(admins);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// @route   GET /api/admin/:id
// @desc    Get admin by ID
// @access  Private (Super Admin, Admin)
router.get("/:id", protect, allowedTo(SUPER_ADMIN, ADMIN), async (req, res) => {
  try {
    const admin = await Admin.findById(req.params.id).select("-password");
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    res.json(admin);
  } catch (err) {
    console.error(err.message);
    if (err.kind === "ObjectId") {
      return res.status(404).json({ message: "Admin not found" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

// @route   POST /api/admin
// @desc    Add new admin
// @access  Private (Super Admin only)
router.post("/", protect, allowedTo(SUPER_ADMIN), async (req, res) => {
  try {
    const { fullName, email, password, role } = req.body;
    // Check if admin already exists
    let admin = await Admin.findOne({ email });
    if (admin) {
      return res.status(400).json({ message: "Admin already exists" });
    }
    // Create new admin
    admin = new Admin({
      fullName,
      email,
      password,
      role: role || ADMIN
    });
    // Hash password
    await admin.hashNewPassword();
    res.status(201).json({
      admin: {
        id: admin._id,
        fullName: admin.fullName,
        email: admin.email,
        role: admin.role
      }
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// @route   DELETE /api/admin/:id
// @desc    Delete admin
// @access  Private (Super Admin only)
router.delete("/:id", protect, allowedTo(SUPER_ADMIN), async (req, res) => {
  try {
    const admin = await Admin.findById(req.params.id);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    await admin.deleteOne();
    res.json({ message: "Admin removed" });
  } catch (err) {
    console.error(err.message);
    if (err.kind === "ObjectId") {
      return res.status(404).json({ message: "Admin not found" });
    }
    res.status(500).json({ message: "Server error" });
  }
});

// @route   GET /api/admin/role/super-admin
// @desc    Get all super admins
// @access  Private (Super Admin, Admin)
router.get(
  "/role/super-admin",
  protect,
  allowedTo(SUPER_ADMIN),
  async (req, res) => {
    try {
      res
        .status(200)
        .json({ message: "Super admins role fetched successfully" });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// @route   GET /api/admin/role/admin
// @desc    Get all admins (excluding managers)
// @access  Private (Super Admin, Admin)
router.get("/role/admin", protect, allowedTo(ADMIN), async (req, res) => {
  try {
    res.status(200).json({ message: "Admins role fetched successfully" });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

// @route   GET /api/admin/role/manager
// @desc    Get all managers
// @access  Private (Super Admin, Admin)
router.get("/role/manager", protect, allowedTo(MANAGER), async (req, res) => {
  try {
    res.status(200).json({ message: "Managers role fetched successfully" });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
