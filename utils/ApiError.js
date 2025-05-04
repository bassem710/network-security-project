class ApiError extends Error {
  constructor(message, statusCode, params) {
    super(message);
    this.isOperational = true;
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith(4) ? "Failed" : "Error";
    this.success = false;
    this.params = params;
  }
}

module.exports = ApiError;
