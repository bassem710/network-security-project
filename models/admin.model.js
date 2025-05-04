const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { SUPER_ADMIN, ADMIN, MANAGER } = require("../utils/constants");

const adminSchema = mongoose.Schema(
  {
    fullName: {
      type: String,
      trim: true,
      required: [true, "Full name is required"]
    },
    email: {
      type: String,
      trim: true,
      unique: true,
      lowercase: true,
      required: [true, "Email is required"]
    },
    role: {
      type: String,
      enum: [SUPER_ADMIN, ADMIN, MANAGER],
      default: ADMIN
    },
    isVerified: {
      type: Boolean,
      default: false
    },
    isBlocked: {
      type: Boolean,
      default: false
    },
    password: {
      type: String,
      minLength: [6, "Too short password"],
      required: [true, "Password is required"]
    },
    passwordChangedAt: Date,
    token: String,
    refreshToken: String,
    refreshTokenExpires: Date
  },
  { timestamps: true }
);

adminSchema.methods.generateToken = async function () {
  // Generate access token
  const tokenExpDate = new Date();
  tokenExpDate.setDate(
    tokenExpDate.getDate() +
      parseInt(process.env.JWT_EXPIRATION.toString().slice(0, -1))
  );

  const token = jwt.sign(
    {
      userId: this._id,
      role: this.role
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRATION
    }
  );

  // Save the tokens to the database
  this.token = token;
  await this.save();

  return {
    token,
    tokenExpDate
  };
};

adminSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

adminSchema.methods.hashNewPassword = async function () {
  this.password = await bcrypt.hash(this.password, 12);
  return await this.save();
};

module.exports = mongoose.model("Admin", adminSchema);
