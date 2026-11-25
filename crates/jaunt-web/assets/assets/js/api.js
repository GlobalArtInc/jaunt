const CSRF_HEADER = "X-Jaunt-Csrf";
const SESSION_PATH = "/v1/web/session";
const MAX_RETRY_AFTER = 3600;

export class ApiError extends Error {
  constructor(status, code, retryAfter) {
    super("api error " + status);
    this.name = "ApiError";
    this.status = status;
    this.code = code || null;
    this.retryAfter = retryAfter || null;
  }
}

export function queryString(query) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query || {})) {
    const values = Array.isArray(value) ? value : [value];
    for (const item of values) {
      if (item !== null && item !== undefined && item !== "") {
        params.append(key, String(item));
      }
    }
  }
  const text = params.toString();
  return text === "" ? "" : "?" + text;
}

function isUnsafe(method) {
  return method !== "GET" && method !== "HEAD";
}

async function readBody(response) {
  if (response.status === 204) {
    return null;
  }
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function retryAfterOf(response, body) {
  const fromBody = body && typeof body.retry_after === "number" ? body.retry_after : null;
  const header = Number.parseInt(response.headers.get("Retry-After") || "", 10);
  const value = fromBody !== null ? fromBody : Number.isFinite(header) ? header : null;
  if (value === null) {
    return null;
  }
  return Math.min(Math.max(Math.ceil(value), 1), MAX_RETRY_AFTER);
}

export function createApi({ onUnauthorized, onSession }) {
  let csrf = null;

  async function attempt(method, path, options) {
    const headers = { Accept: "application/json" };
    const init = { method, headers, credentials: "same-origin", cache: "no-store" };
    if (isUnsafe(method)) {
      headers[CSRF_HEADER] = csrf;
      if (options.body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(options.body);
      }
    }
    let response;
    try {
      response = await fetch(path + queryString(options.query), init);
    } catch {
      throw new ApiError(0, "network");
    }
    return { response, body: await readBody(response) };
  }

  function fail({ response, body }) {
    const code = body && typeof body.error === "string" ? body.error : null;
    return new ApiError(response.status, code, retryAfterOf(response, body));
  }

  async function readSession() {
    const reply = await attempt("GET", SESSION_PATH, {});
    if (reply.response.status === 401) {
      throw new ApiError(401, "unauthorized");
    }
    if (!reply.response.ok || !reply.body || typeof reply.body.csrf_token !== "string") {
      throw fail(reply);
    }
    csrf = reply.body.csrf_token;
    const { csrf_token: _token, ...session } = reply.body;
    return session;
  }

  async function session() {
    return readSession();
  }

  async function reload() {
    try {
      const loaded = await readSession();
      if (onSession) {
        onSession(loaded);
      }
    } catch (error) {
      if (error.status === 401) {
        onUnauthorized();
      }
      throw error;
    }
  }

  async function request(method, path, options = {}) {
    if (isUnsafe(method) && csrf === null) {
      await reload();
    }
    let reply = await attempt(method, path, options);
    if (reply.response.status === 403 && isUnsafe(method)) {
      await reload();
      reply = await attempt(method, path, options);
    }
    if (reply.response.status === 401) {
      onUnauthorized();
      throw new ApiError(401, "unauthorized");
    }
    if (!reply.response.ok) {
      throw fail(reply);
    }
    return reply.body;
  }

  function forget() {
    csrf = null;
  }

  return {
    session,
    forget,
    get: (path, query) => request("GET", path, { query }),
    post: (path, body) => request("POST", path, { body }),
    del: (path, body) => request("DELETE", path, { body }),
  };
}
