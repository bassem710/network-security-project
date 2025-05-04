const ApiError = require("../utils/ApiError");
const capitalizeFirstLetter = require("../utils/capitalizeFirstLetter");
const splitCamelCase = require("../utils/splitCamelCase");

const sendErrorForDev = (err, req, res) => {
  console.log("🚀 ~ sendErrorForDev ~ err:", err);
  res.status(err.statusCode).json({
    success: err.success || false,
    message: err.message || "Something went wrong",
    stack: err.stack
  });
};

const sendErrorForProd = (err, req, res) => {
  if (!err.isOperational) {
    res.status(err.statusCode).json({
      success: false,
      message: "Something went wrong"
    });
  } else {
    // For other status codes
    res.status(err.statusCode).json({
      success: err.success || false,
      message: err.message || "Something went wrong"
    });
  }
};

const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new ApiError(message, 400);
};

const handleDuplicatedFieldsDB = (error) => {
  const duplicateKey = Object.keys(error.keyPattern)[0]; // Extracting the duplicate key field
  let errorMessage;
  if (duplicateKey.includes("Ar")) {
    errorMessage = `Arabic ${splitCamelCase(
      duplicateKey.slice(0, -2)
    )} is already used`;
  } else if (duplicateKey.includes("En")) {
    errorMessage = `English ${splitCamelCase(
      duplicateKey.slice(0, -2)
    )} is already used`;
  } else {
    errorMessage = `${capitalizeFirstLetter(
      splitCamelCase(duplicateKey)
    )} is already used`;
  }
  return new ApiError(errorMessage, 401);
};

const handleValidationError = (err) => {
  const errors = Object.values(err.errors).map((el) => {
    return el.message;
  });
  const message = `Invalid Input Data ${errors.join(". ")}`;
  return new ApiError(message, 400);
};

const handleInvalidJwtSignature = (_) =>
  new ApiError("Invalid token, Please login again ...", 401);

const handleJwtExpired = (_) =>
  new ApiError("Expired token, Please login again ...", 401);

const globalError = (err, req, res, next) => {
  err.success = err.success || false;
  err.statusCode = err.statusCode || 500;
  let error = { ...err };
  error.message = err.message;
  if (err.name === "JsonWebTokenError") error = handleInvalidJwtSignature();
  if (err.name === "TokenExpiredError") error = handleJwtExpired();
  if (err.code === 11000) error = handleDuplicatedFieldsDB(err);
  if (err.name === "CastError") error = handleCastErrorDB(err);
  if (err.name === "ValidationError") error = handleValidationError(err);
  if (process.env.NODE_ENV === "development") {
    sendErrorForDev(error, req, res);
  } else {
    sendErrorForProd(error, req, res);
  }
};

module.exports = globalError;
