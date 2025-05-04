const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");

const Admin = require("../models/admin.model");
const ApiError = require("../utils/ApiError");

// Constants
const { ROLES } = require("../utils/constants");

// === Check token => verify => Check role is valid => check expiration => check based on role ===
exports.protect = asyncHandler(async (req, res, next) => {
  // check token
  let token;
  if (req.headers.authorization) token = req.headers.authorization;
  if (!token)
    return next(new ApiError("Invalid token, please login again...", 401));

  try {
    // verify token
    const decoded = await jwt.verify(token, process.env.JWT_SECRET);

    // Check token role
    const role = decoded.role;
    if (!ROLES.includes(role))
      return next(
        new ApiError("Invalid token role, please login again...", 401)
      );

    // Check token expiration
    const currentTimestamp = Math.floor(Date.now() / 1000); // in seconds
    if (decoded.exp < currentTimestamp)
      return next(
        new ApiError("Token has expired, please use refresh token...", 401)
      );

    // Check user
    const mongooseQuery = Model.findById(decoded.userId);
    const currentUser = await mongooseQuery;
    if (!currentUser) return next(new ApiError(`Admin not found`, 401));
    // Check if token is valid
    if (currentUser.token !== token)
      return next(new ApiError("Session expired, please login again...", 401));
    // Check if the account is blocked
    if (currentUser.isBlocked)
      return next(
        new ApiError(
          "Your account is blocked, please contact the support team",
          401
        )
      );
    req.role = role;
    req.userId = decoded.userId;
    req.user = currentUser;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return next(
        new ApiError("Token has expired, please use refresh token...", 401)
      );
    }
    return next(new ApiError("Invalid token, please login again...", 401));
  }
});

// === Check for user permission based on role ===
exports.allowedTo = (...roles) =>
  asyncHandler(async (req, res, next) => {
    if (!roles.includes(req.role))
      return next(new ApiError("Not allowed to access this route", 403));
    next();
  });
