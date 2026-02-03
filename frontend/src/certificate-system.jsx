import React, { useState, useEffect } from "react";
import {
  Upload, CheckCircle, XCircle, Shield, FileText,
  Eye, AlertTriangle, LogOut
} from "lucide-react";

/* ================= API HELPER ================= */
const API_BASE = "http://127.0.0.1:8000";

async function api(url, method = "GET", body = null, auth = true) {
  const headers = {};

  if (auth) {
    const token = localStorage.getItem("access");
    if (token) headers.Authorization = `Bearer ${token}`;
  }

  if (body && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(API_BASE + url, {
    method,
    headers,
    body: body instanceof FormData ? body : body ? JSON.stringify(body) : null,
  });

  if (!response.ok) {
    throw new Error("API error");
  }

  return response.json();
}

/* ================= MAIN COMPONENT ================= */
export default function CertificateManagementSystem() {
  const [currentUser, setCurrentUser] = useState(null);
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [activeTab, setActiveTab] = useState("dashboard");

  const [certForm, setCertForm] = useState({ holderName: "", title: "", file: null });
  const [verifyID, setVerifyID] = useState("");
  const [verificationResult, setVerificationResult] = useState(null);
  const [revokeForm, setRevokeForm] = useState({ certID: "", reason: "" });
  const [auditLogs, setAuditLogs] = useState([]);
  const [notification, setNotification] = useState(null);

  const showNotification = (message, type = "info") => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 4000);
  };

  /* ================= AUTH ================= */
  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const data = await api("/auth/login/", "POST", loginForm, false);
      localStorage.setItem("access", data.tokens.access);
      localStorage.setItem("refresh", data.tokens.refresh);
      setCurrentUser(data.user);
      showNotification(`Welcome, ${data.user.username}!`, "success");
    } catch {
      showNotification("Login failed", "error");
    }
  };

  const handleLogout = () => {
    localStorage.clear();
    setCurrentUser(null);
    showNotification("Logged out", "info");
  };

  /* ================= CERTIFICATE CREATE ================= */
  const handleCreateCertificate = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();
      formData.append("holder_name", certForm.holderName);
      formData.append("title", certForm.title);
      formData.append("certificate_file", certForm.file);

      await api("/certificates/", "POST", formData);
      showNotification("Certificate issued successfully", "success");
      setCertForm({ holderName: "", title: "", file: null });
    } catch {
      showNotification("Failed to issue certificate", "error");
    }
  };

  /* ================= VERIFY ================= */
  const handleVerify = async (e) => {
    e.preventDefault();
    try {
      const res = await api("/verify/", "POST", { certificate_id: verifyID }, false);
      setVerificationResult({
        valid: res.valid,
        certificate: res.certificate,
        hashMatch: res.hash_match,
        isRevoked: res.is_revoked,
      });
    } catch {
      setVerificationResult({ valid: false, reason: "Certificate not found" });
    }
    setVerifyID("");
  };

  /* ================= REVOKE ================= */
  const handleRevoke = async (e) => {
    e.preventDefault();
    try {
      const res = await api("/revoke/", "POST", {
        certificate_id: revokeForm.certID,
        reason: revokeForm.reason,
      });
      showNotification(res.message, "success");
      setRevokeForm({ certID: "", reason: "" });
    } catch {
      showNotification("Revocation failed", "error");
    }
  };

  /* ================= AUDIT LOGS ================= */
  useEffect(() => {
    if (activeTab === "logs") {
      api("/audit-logs/")
        .then(setAuditLogs)
        .catch(() => showNotification("Failed to load logs", "error"));
    }
  }, [activeTab]);

  /* ================= LOGIN UI ================= */
  if (!currentUser) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-900">
        <form onSubmit={handleLogin} className="bg-white p-6 rounded-xl w-96">
          <h2 className="text-2xl font-bold mb-4">ZeroID Login</h2>
          <input
            className="w-full p-2 border mb-3"
            placeholder="Username"
            value={loginForm.username}
            onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })}
          />
          <input
            className="w-full p-2 border mb-3"
            type="password"
            placeholder="Password"
            value={loginForm.password}
            onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
          />
          <button className="w-full bg-purple-600 text-white py-2 rounded">
            Login
          </button>
        </form>
      </div>
    );
  }

  /* ================= MAIN UI ================= */
  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white p-4 flex justify-between">
        <h1 className="font-bold text-xl">ZeroID</h1>
        <button onClick={handleLogout} className="flex items-center gap-2">
          <LogOut size={16} /> Logout
        </button>
      </header>

      <main className="p-6">
        {activeTab === "verify" && (
          <form onSubmit={handleVerify} className="max-w-md">
            <input
              className="w-full p-2 border mb-3"
              placeholder="Certificate ID"
              value={verifyID}
              onChange={(e) => setVerifyID(e.target.value)}
            />
            <button className="bg-blue-600 text-white px-4 py-2 rounded">
              Verify
            </button>
          </form>
        )}

        {activeTab === "logs" && (
          <div>
            {auditLogs.map((log) => (
              <div key={log.id} className="p-3 bg-white mb-2 rounded">
                <b>{log.action}</b> – {new Date(log.timestamp).toLocaleString()}
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
