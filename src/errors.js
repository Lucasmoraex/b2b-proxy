export class AppError extends Error {
  constructor(code, status = 500, options = {}) {
    super(code, options);
    this.name = "AppError";
    this.code = code;
    this.status = status;
  }
}

export class ExternalServiceError extends AppError {
  constructor(service, code = `${service}_unavailable`, options = {}) {
    super(code, 503, options);
    this.name = "ExternalServiceError";
    this.service = service;
  }
}

export const publicError = (error) => {
  if (error instanceof AppError) {
    return { status: error.status, code: error.code };
  }
  if (error?.type === "entity.parse.failed") return { status: 400, code: "invalid_json" };
  if (error?.type === "entity.too.large") return { status: 413, code: "payload_too_large" };
  return { status: 500, code: "internal_error" };
};
