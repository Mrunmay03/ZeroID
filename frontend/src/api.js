const API_BASE = "http://127.0.0.1:8000";

export async function api(url, method = "GET", body = null, auth = true) {
  const headers = {};

  if (auth) {
    const token = localStorage.getItem("access");
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }

  if (body && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(API_BASE + url, {
    method,
    headers,
    body:
      body instanceof FormData
        ? body
        : body
        ? JSON.stringify(body)
        : null,
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(err);
  }

  return response.json();
}
