import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ShieldCheck,
  Lock,
  KeyRound,
  Plus,
  Search,
  LogOut,
  Eye,
  EyeOff,
  Copy,
  Trash2,
  Cloud,
  Server,
  Mail,
  Database,
  Settings,
  X,
  Sparkles,
  Users,
  UserCheck,
  UserX,
  Shield,
  ArrowLeft,
  RefreshCw,
} from "lucide-react";
import "./styles.css";

type Secret = {
  id: number;
  title: string;
  category: string;
  ciphertext: string;
  iv: string;
  created_at: string;
  updated_at: string;
};

type AdminUser = {
  id: number;
  email: string;
  email_verified: boolean;
  is_active: boolean;
  is_admin: boolean;
  created_at: string;
};

const API =
  import.meta.env.VITE_API_URL || "http://localhost:8000";

/* =========================================================
   ENCRYPTION
   ========================================================= */

const b64 = (u: Uint8Array) =>
  btoa(String.fromCharCode(...u));

const unb64 = (s: string) =>
  Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function derive(
  password: string,
  salt: Uint8Array
) {
  const base = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 250000,
      hash: "SHA-256",
    },
    base,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(
  value: string,
  password: string
) {
  const salt = crypto.getRandomValues(
    new Uint8Array(16)
  );

  const iv = crypto.getRandomValues(
    new Uint8Array(12)
  );

  const key = await derive(password, salt);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    new TextEncoder().encode(value)
  );

  return {
    ciphertext: b64(
      new Uint8Array([
        ...salt,
        ...new Uint8Array(ciphertext),
      ])
    ),
    iv: b64(iv),
  };
}

async function decrypt(
  secret: Secret,
  password: string
) {
  const raw = unb64(secret.ciphertext);

  const salt = raw.slice(0, 16);
  const ciphertext = raw.slice(16);

  const key = await derive(password, salt);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: unb64(secret.iv),
    },
    key,
    ciphertext
  );

  return new TextDecoder().decode(plaintext);
}

/* =========================================================
   API CLIENT
   ========================================================= */

async function api(
  path: string,
  opts: RequestInit = {}
) {
  const token = sessionStorage.getItem("token");

  const headers = new Headers(opts.headers);

  if (!headers.has("Content-Type")) {
    headers.set(
      "Content-Type",
      "application/json"
    );
  }

  if (token) {
    headers.set(
      "Authorization",
      `Bearer ${token}`
    );
  }

  let response: Response;

  try {
    response = await fetch(`${API}${path}`, {
      ...opts,
      headers,
    });
  } catch (error) {
    console.error(
      "VaultNest API connection error:",
      error
    );

    throw new Error(
      "Unable to connect to VaultNest API. Please make sure the backend is running."
    );
  }

  let data: any = {};

  try {
    const contentType =
      response.headers.get("content-type") || "";

    if (
      contentType.includes("application/json")
    ) {
      data = await response.json();
    } else {
      const text = await response.text();

      if (text) {
        data = {
          message: text,
        };
      }
    }
  } catch (error) {
    console.error(
      "Failed to parse API response:",
      error
    );

    data = {};
  }

  if (!response.ok) {
    let message = `Request failed (${response.status})`;

    /*
     * FastAPI:
     * {
     *   "detail": "Invalid credentials"
     * }
     */

    if (typeof data.detail === "string") {
      message = data.detail;
    }

    /*
     * FastAPI validation:
     * {
     *   "detail": [
     *     {
     *       "loc": ["body", "email"],
     *       "msg": "Invalid email"
     *     }
     *   ]
     * }
     */

    else if (Array.isArray(data.detail)) {
      message = data.detail
        .map((item: unknown) => {
          if (typeof item === "string") {
            return item;
          }

          if (
            item &&
            typeof item === "object" &&
            "msg" in item &&
            typeof (item as { msg?: unknown })
              .msg === "string"
          ) {
            return (
              item as { msg: string }
            ).msg;
          }

          return JSON.stringify(item);
        })
        .join(", ");
    }

    /*
     * Object-based error:
     * {
     *   "detail": {
     *      "message": "Admin access required"
     *   }
     * }
     */

    else if (
      data.detail &&
      typeof data.detail === "object"
    ) {
      if (
        "message" in data.detail &&
        typeof data.detail.message ===
          "string"
      ) {
        message = data.detail.message;
      } else if (
        "msg" in data.detail &&
        typeof data.detail.msg === "string"
      ) {
        message = data.detail.msg;
      } else {
        message = JSON.stringify(
          data.detail
        );
      }
    }

    /*
     * Generic API message
     */

    else if (
      typeof data.message === "string"
    ) {
      message = data.message;
    }

    /*
     * Plain text
     */

    else if (
      typeof data === "string" &&
      data.length > 0
    ) {
      message = data;
    }

    throw new Error(message);
  }

  return data;
}

/* =========================================================
   ICONS
   ========================================================= */

const iconFor = (category: string) => {
  switch (category) {
    case "Cloud":
      return Cloud;

    case "Server":
      return Server;

    case "Email":
      return Mail;

    case "Database":
      return Database;

    default:
      return KeyRound;
  }
};

/* =========================================================
   AUTHENTICATION
   ========================================================= */

function Auth({
  onLogin,
}: {
  onLogin: (
    email: string,
    password: string
  ) => void;
}) {
  const [register, setRegister] =
    useState(false);

  const [email, setEmail] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [confirm, setConfirm] =
    useState("");

  const [busy, setBusy] =
    useState(false);

  const [error, setError] =
    useState("");

  const [message, setMessage] =
    useState("");

  const submit = async (
    event: React.FormEvent
  ) => {
    event.preventDefault();

    setError("");
    setMessage("");

    if (
      register &&
      password !== confirm
    ) {
      setError(
        "Passwords do not match."
      );
      return;
    }

    setBusy(true);

    try {
      const data = await api(
        register
          ? "/auth/register"
          : "/auth/login",
        {
          method: "POST",
          body: JSON.stringify({
            email,
            password,
          }),
        }
      );

      if (register) {
        setMessage(
          data.message ||
            "Account created. Please check your email to verify your account."
        );

        setRegister(false);
        setPassword("");
        setConfirm("");
      } else {
        sessionStorage.setItem(
          "token",
          data.token
        );

        sessionStorage.setItem(
          "email",
          data.user.email
        );

        onLogin(
          data.user.email,
          password
        );
      }
    } catch (error: any) {
      setError(
        error?.message ||
          "Unable to complete the request."
      );
    } finally {
      setBusy(false);
    }
  };

  const resend = async () => {
    setError("");
    setMessage("");

    if (!email || !password) {
      setError(
        "Enter your email and password first."
      );
      return;
    }

    try {
      const data = await api(
        "/auth/resend-verification",
        {
          method: "POST",
          body: JSON.stringify({
            email,
            password,
          }),
        }
      );

      setMessage(
        data.message ||
          "Verification email sent."
      );
    } catch (error: any) {
      setError(
        error?.message ||
          "Unable to resend verification email."
      );
    }
  };

  return (
    <div className="auth">
      <div className="auth-card">
        <div className="brand">
          <div className="logo">
            <ShieldCheck />
          </div>

          <div>
            <b>VaultNest</b>
            <span>
              Private secrets vault
            </span>
          </div>
        </div>

        <div className="auth-copy">
          <h1>
            {register
              ? "Create your vault"
              : "Welcome back"}
          </h1>

          <p>
            {register
              ? "Create your account. We will send a verification link before you can sign in."
              : "Unlock your private workspace and keep credentials organized."}
          </p>
        </div>

        <form onSubmit={submit}>
          <label>
            Email

            <input
              type="email"
              required
              value={email}
              onChange={(event) =>
                setEmail(event.target.value)
              }
              placeholder="you@company.com"
            />
          </label>

          <label>
            Password

            <input
              type="password"
              required
              minLength={12}
              value={password}
              onChange={(event) =>
                setPassword(
                  event.target.value
                )
              }
              placeholder="Minimum 12 characters"
            />
          </label>

          {register && (
            <label>
              Confirm password

              <input
                type="password"
                required
                value={confirm}
                onChange={(event) =>
                  setConfirm(
                    event.target.value
                  )
                }
                placeholder="Repeat password"
              />
            </label>
          )}

          {error && (
            <div className="error">
              {error}
            </div>
          )}

          {message && (
            <div className="success">
              {message}
            </div>
          )}

          <button
            className="primary"
            disabled={busy}
          >
            {busy
              ? "Please wait…"
              : register
              ? "Create account"
              : "Sign in"}
          </button>
        </form>

        {!register && (
          <button
            className="secondary full"
            onClick={resend}
          >
            Resend verification email
          </button>
        )}

        <button
          className="switch"
          onClick={() => {
            setRegister(!register);
            setError("");
            setMessage("");
          }}
        >
          {register
            ? "Already have an account? Sign in"
            : "New here? Create an account"}
        </button>

        <button
          className="admin-link"
          onClick={() =>
            (location.href = "/admin")
          }
        >
          <Shield size={14} />
          Admin console
        </button>

        <div className="security-note">
          <Lock size={15} />
          Vault data is encrypted in your
          browser using AES-GCM.
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   EMAIL VERIFICATION
   ========================================================= */

function VerifyPage() {
  const [state, setState] =
    useState<
      "loading" | "success" | "error"
    >("loading");

  const [message, setMessage] =
    useState(
      "Verifying your email…"
    );

  useEffect(() => {
    const token =
      new URLSearchParams(
        location.search
      ).get("token");

    if (!token) {
      setState("error");
      setMessage(
        "Verification token is missing."
      );
      return;
    }

    api(
      "/auth/verify?token=" +
        encodeURIComponent(token)
    )
      .then((data) => {
        setState("success");

        setMessage(
          data.message ||
            "Your email has been verified successfully."
        );
      })
      .catch((error) => {
        setState("error");

        setMessage(
          error?.message ||
            "Email verification failed."
        );
      });
  }, []);

  return (
    <div className="auth">
      <div className="auth-card verify-card">
        <div className="logo">
          <ShieldCheck />
        </div>

        <h1>
          {state === "loading"
            ? "Verifying email"
            : state === "success"
            ? "Email verified"
            : "Verification failed"}
        </h1>

        <p>{message}</p>

        {state !== "loading" && (
          <button
            className="primary"
            onClick={() =>
              (location.href = "/")
            }
          >
            Go to login
          </button>
        )}
      </div>
    </div>
  );
}

/* =========================================================
   ADMIN LOGIN
   ========================================================= */

function AdminLogin() {
  const [email, setEmail] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [error, setError] =
    useState("");

  const [busy, setBusy] =
    useState(false);

  const submit = async (
    event: React.FormEvent
  ) => {
    event.preventDefault();

    setBusy(true);
    setError("");

    try {
      const data = await api(
        "/auth/admin-login",
        {
          method: "POST",
          body: JSON.stringify({
            email,
            password,
          }),
        }
      );

      if (!data?.token) {
        throw new Error(
          "Admin login succeeded but no authentication token was returned."
        );
      }

      sessionStorage.setItem(
        "token",
        data.token
      );

      sessionStorage.setItem(
        "admin",
        "true"
      );

      sessionStorage.setItem(
        "email",
        email
      );

      location.href = "/admin";
    } catch (error: any) {
      setError(
        error?.message ||
          "Admin login failed."
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <div className="auth-card">
        <div className="brand">
          <div className="logo">
            <Shield />
          </div>

          <div>
            <b>VaultNest Admin</b>
            <span>
              User administration
            </span>
          </div>
        </div>

        <div className="auth-copy">
          <h1>Admin console</h1>

          <p>
            Manage account access without
            accessing users' encrypted vault
            contents.
          </p>
        </div>

        <form onSubmit={submit}>
          <label>
            Admin email

            <input
              type="email"
              required
              value={email}
              onChange={(event) =>
                setEmail(
                  event.target.value
                )
              }
              placeholder="admin@vaultnest.local"
            />
          </label>

          <label>
            Admin password

            <input
              type="password"
              required
              value={password}
              onChange={(event) =>
                setPassword(
                  event.target.value
                )
              }
            />
          </label>

          {error && (
            <div className="error">
              {error}
            </div>
          )}

          <button
            className="primary"
            disabled={busy}
          >
            {busy
              ? "Signing in…"
              : "Open admin console"}
          </button>
        </form>

        <button
          className="switch"
          onClick={() =>
            (location.href = "/")
          }
        >
          <ArrowLeft size={13} />
          Back to user login
        </button>
      </div>
    </div>
  );
}

/* =========================================================
   ADMIN PAGE
   ========================================================= */

function AdminPage() {
  const [users, setUsers] =
    useState<AdminUser[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const load = async () => {
    setLoading(true);
    setError("");

    try {
      const data =
        await api("/admin/users");

      setUsers(
        Array.isArray(data)
          ? data
          : []
      );
    } catch (error: any) {
      const message =
        error?.message ||
        "Unable to load users.";

      setError(message);

      if (
        message
          .toLowerCase()
          .includes("admin")
      ) {
        sessionStorage.clear();
        location.href = "/admin";
        return;
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const toggle = async (
    user: AdminUser
  ) => {
    try {
      await api(
        `/admin/users/${user.id}/status?active=${!user.is_active}`,
        {
          method: "PATCH",
        }
      );

      await load();
    } catch (error: any) {
      alert(
        error?.message ||
          "Unable to update user status."
      );
    }
  };

  const remove = async (
    user: AdminUser
  ) => {
    const confirmed = confirm(
      `Permanently delete ${user.email}? This also deletes their encrypted vault records.`
    );

    if (!confirmed) {
      return;
    }

    try {
      await api(
        "/admin/users/" + user.id,
        {
          method: "DELETE",
        }
      );

      await load();
    } catch (error: any) {
      alert(
        error?.message ||
          "Unable to delete user."
      );
    }
  };

  const regularUsers =
    users.filter(
      (user) => !user.is_admin
    );

  const active =
    regularUsers.filter(
      (user) => user.is_active
    ).length;

  const verified =
    regularUsers.filter(
      (user) => user.email_verified
    ).length;

  const inactive =
    regularUsers.filter(
      (user) => !user.is_active
    ).length;

  return (
    <div className="admin-app">
      <header className="admin-header">
        <div className="brand">
          <div className="logo">
            <Shield />
          </div>

          <div>
            <b>VaultNest Admin</b>
            <span>
              User administration
            </span>
          </div>
        </div>

        <div className="admin-actions">
          <button
            className="secondary"
            onClick={load}
          >
            <RefreshCw size={15} />
            Refresh
          </button>

          <button
            className="secondary"
            onClick={() => {
              sessionStorage.clear();
              location.href = "/admin";
            }}
          >
            <LogOut size={15} />
            Logout
          </button>
        </div>
      </header>

      <main className="admin-main">
        <div className="admin-title">
          <div>
            <p className="eyebrow">
              ADMINISTRATION
            </p>

            <h2>User access</h2>

            <p>
              Control account access. User
              vault contents remain encrypted
              and are not exposed to
              administrators.
            </p>
          </div>
        </div>

        <div className="admin-cards">
          <div className="admin-card">
            <Users />

            <span>Total users</span>

            <b>{regularUsers.length}</b>
          </div>

          <div className="admin-card">
            <UserCheck />

            <span>Active users</span>

            <b>{active}</b>
          </div>

          <div className="admin-card">
            <ShieldCheck />

            <span>Verified users</span>

            <b>{verified}</b>
          </div>

          <div className="admin-card">
            <UserX />

            <span>Inactive users</span>

            <b>{inactive}</b>
          </div>
        </div>

        {error && (
          <div className="error">
            {error}
          </div>
        )}

        <section className="users-panel">
          <div className="users-head">
            <span>USER</span>
            <span>VERIFICATION</span>
            <span>STATUS</span>
            <span>CREATED</span>
            <span>ACTIONS</span>
          </div>

          {loading ? (
            <div className="admin-empty">
              Loading users…
            </div>
          ) : (
            regularUsers.map(
              (user) => (
                <div
                  className="user-row"
                  key={user.id}
                >
                  <div>
                    <b>{user.email}</b>

                    <span>
                      User ID #{user.id}
                    </span>
                  </div>

                  <span
                    className={
                      user.email_verified
                        ? "status verified"
                        : "status pending"
                    }
                  >
                    {user.email_verified
                      ? "Verified"
                      : "Pending"}
                  </span>

                  <span
                    className={
                      user.is_active
                        ? "status active"
                        : "status disabled"
                    }
                  >
                    {user.is_active
                      ? "Active"
                      : "Disabled"}
                  </span>

                  <span className="date">
                    {new Date(
                      user.created_at
                    ).toLocaleString()}
                  </span>

                  <div className="user-actions">
                    <button
                      className="secondary"
                      onClick={() =>
                        toggle(user)
                      }
                    >
                      {user.is_active
                        ? "Disable"
                        : "Enable"}
                    </button>

                    <button
                      className="danger"
                      onClick={() =>
                        remove(user)
                      }
                    >
                      Delete
                    </button>
                  </div>
                </div>
              )
            )
          )}

          {!loading &&
            regularUsers.length ===
              0 && (
              <div className="admin-empty">
                No regular users yet.
              </div>
            )}
        </section>
      </main>
    </div>
  );
}

/* =========================================================
   MAIN USER APPLICATION
   ========================================================= */

function App() {
  const path = location.pathname;

  if (path === "/verify-email") {
    return <VerifyPage />;
  }

  if (path === "/admin") {
    return sessionStorage.getItem(
      "admin"
    ) === "true" ? (
      <AdminPage />
    ) : (
      <AdminLogin />
    );
  }

  const [auth, setAuth] =
    useState<{
      email: string;
      password: string;
    } | null>(null);

  const [secrets, setSecrets] =
    useState<Secret[]>([]);

  const [selected, setSelected] =
    useState<Secret | null>(null);

  const [query, setQuery] =
    useState("");

  const [category, setCategory] =
    useState("All");

  const [modal, setModal] =
    useState(false);

  const [loading, setLoading] =
    useState(true);

  const load = async () => {
    try {
      const data =
        await api("/secrets");

      setSecrets(
        Array.isArray(data)
          ? data
          : []
      );
    } catch (error) {
      sessionStorage.removeItem(
        "token"
      );

      sessionStorage.removeItem(
        "email"
      );

      setAuth(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const token =
      sessionStorage.getItem(
        "token"
      );

    const admin =
      sessionStorage.getItem(
        "admin"
      );

    if (
      token &&
      admin !== "true"
    ) {
      const email =
        sessionStorage.getItem(
          "email"
        );

      if (email) {
        setAuth({
          email,
          password: "",
        });
      } else {
        sessionStorage.clear();
      }
    }

    setLoading(false);
  }, []);

  useEffect(() => {
    if (
      auth &&
      auth.password
    ) {
      load();
    }
  }, [auth]);

  if (loading) {
    return (
      <div className="splash">
        Loading VaultNest…
      </div>
    );
  }

  if (!auth) {
    return (
      <Auth
        onLogin={(
          email,
          password
        ) =>
          setAuth({
            email,
            password,
          })
        }
      />
    );
  }

  const categories = [
    "All",
    "Password",
    "Cloud",
    "Server",
    "Database",
    "API Key",
    "Email",
    "GitHub",
  ];

  const filtered = secrets.filter(
    (secret) =>
      (category === "All" ||
        secret.category ===
          category) &&
      secret.title
        .toLowerCase()
        .includes(
          query.toLowerCase()
        )
  );

  const stats =
    categories
      .slice(1)
      .map((categoryName) => ({
        c: categoryName,
        n: secrets.filter(
          (secret) =>
            secret.category ===
            categoryName
        ).length,
      }));

  return (
    <div className="app">
      <aside>
        <div className="brand side">
          <div className="logo">
            <ShieldCheck />
          </div>

          <div>
            <b>VaultNest</b>
            <span>
              Private vault
            </span>
          </div>
        </div>

        <div className="nav-title">
          WORKSPACE
        </div>

        <button
          className={
            category === "All"
              ? "nav active"
              : "nav"
          }
          onClick={() =>
            setCategory("All")
          }
        >
          <span>⌂</span>
          <span>All secrets</span>
          <em>{secrets.length}</em>
        </button>

        <div className="nav-title">
          CATEGORIES
        </div>

        {categories
          .slice(1)
          .map((categoryName) => {
            const Icon =
              iconFor(categoryName);

            const count =
              stats.find(
                (item) =>
                  item.c ===
                  categoryName
              )?.n || 0;

            return (
              <button
                className={
                  category ===
                  categoryName
                    ? "nav active"
                    : "nav"
                }
                key={categoryName}
                onClick={() =>
                  setCategory(
                    categoryName
                  )
                }
              >
                <Icon size={17} />

                <span>
                  {categoryName}
                </span>

                <em>{count}</em>
              </button>
            );
          })}

        <div className="side-bottom">
          <button className="nav">
            <Settings size={17} />
            <span>Settings</span>
          </button>

          <button
            className="nav"
            onClick={() => {
              sessionStorage.clear();
              setAuth(null);
            }}
          >
            <LogOut size={17} />
            <span>
              Lock vault
            </span>
          </button>
        </div>
      </aside>

      <main>
        <header>
          <div>
            <p className="eyebrow">
              SECURE WORKSPACE
            </p>

            <h2>Your Vault</h2>
          </div>

          <div className="profile">
            <div className="avatar">
              {auth.email[0].toUpperCase()}
            </div>

            <div>
              <b>{auth.email}</b>

              <span>
                Personal vault
              </span>
            </div>
          </div>
        </header>

        <section className="hero">
          <div>
            <div className="hero-icon">
              <Sparkles />
            </div>

            <div>
              <p className="eyebrow">
                PROTECTED
              </p>

              <h3>
                Your credentials, under
                your control.
              </h3>

              <p>
                Secrets are encrypted in
                your browser before being
                stored by the API.
              </p>
            </div>
          </div>

          <button
            className="primary compact"
            onClick={() =>
              setModal(true)
            }
          >
            <Plus size={17} />
            Add secret
          </button>
        </section>

        <div className="toolbar">
          <div className="search">
            <Search size={17} />

            <input
              value={query}
              onChange={(event) =>
                setQuery(
                  event.target.value
                )
              }
              placeholder="Search your vault…"
            />
          </div>

          <span>
            {filtered.length} secret
            {filtered.length !== 1
              ? "s"
              : ""}
          </span>
        </div>

        <div className="cards">
          {stats
            .filter(
              (item) => item.n
            )
            .slice(0, 4)
            .map((item) => {
              const Icon =
                iconFor(item.c);

              return (
                <button
                  key={item.c}
                  className="stat"
                  onClick={() =>
                    setCategory(
                      item.c
                    )
                  }
                >
                  <Icon />

                  <div>
                    <span>
                      {item.c}
                    </span>

                    <b>{item.n}</b>
                  </div>
                </button>
              );
            })}
        </div>

        <section className="table">
          <div className="table-head">
            <span>SECRET</span>
            <span>CATEGORY</span>
            <span>UPDATED</span>
            <span></span>
          </div>

          {filtered.length === 0 ? (
            <div className="empty">
              <KeyRound size={32} />

              <h3>
                Your vault is empty
              </h3>

              <p>
                Add your first credential
                to get started.
              </p>

              <button
                className="primary"
                onClick={() =>
                  setModal(true)
                }
              >
                <Plus size={17} />
                Add secret
              </button>
            </div>
          ) : (
            filtered.map((secret) => (
              <SecretRow
                key={secret.id}
                s={secret}
                password={
                  auth.password
                }
                onOpen={() =>
                  setSelected(
                    secret
                  )
                }
                onDelete={async () => {
                  await api(
                    `/secrets/${secret.id}`,
                    {
                      method:
                        "DELETE",
                    }
                  );

                  load();
                }}
              />
            ))
          )}
        </section>
      </main>

      {(modal || selected) && (
        <SecretModal
          initial={selected}
          password={auth.password}
          onClose={() => {
            setModal(false);
            setSelected(null);
          }}
          onSaved={load}
        />
      )}
    </div>
  );
}

/* =========================================================
   SECRET ROW
   ========================================================= */

function SecretRow({
  s,
  password,
  onOpen,
  onDelete,
}: {
  s: Secret;
  password: string;
  onOpen: () => void;
  onDelete: () => void;
}) {
  const [plain, setPlain] =
    useState<any>(null);

  const [show, setShow] =
    useState(false);

  const Icon = iconFor(
    s.category
  );

  const reveal = async () => {
    try {
      const decrypted =
        await decrypt(
          s,
          password
        );

      const parsed =
        JSON.parse(decrypted);

      setPlain(parsed);
      setShow(!show);
    } catch {
      alert(
        "Unable to decrypt this secret. Please sign in again."
      );
    }
  };

  const copySecret = async () => {
    try {
      let data = plain;

      if (!data) {
        const decrypted =
          await decrypt(
            s,
            password
          );

        data =
          JSON.parse(decrypted);

        setPlain(data);
      }

      const value =
        data.password ||
        data.value ||
        "";

      await navigator.clipboard.writeText(
        value
      );
    } catch {
      alert(
        "Unable to copy this secret."
      );
    }
  };

  return (
    <div className="row">
      <div className="secret-name">
        <div className="mini">
          <Icon size={16} />
        </div>

        <div>
          <b>{s.title}</b>

          <span>
            {show && plain
              ? plain.username ||
                plain.value ||
                "Secret"
              : "Encrypted credential"}
          </span>
        </div>
      </div>

      <span className="pill">
        {s.category}
      </span>

      <span className="date">
        {new Date(
          s.updated_at
        ).toLocaleDateString()}
      </span>

      <div className="actions">
        <button
          title="Reveal"
          onClick={reveal}
        >
          {show ? (
            <EyeOff size={17} />
          ) : (
            <Eye size={17} />
          )}
        </button>

        <button
          title="Copy"
          onClick={copySecret}
        >
          <Copy size={17} />
        </button>

        <button
          onClick={onOpen}
        >
          Open
        </button>

        <button
          className="danger-icon"
          onClick={onDelete}
        >
          <Trash2 size={17} />
        </button>
      </div>
    </div>
  );
}

/* =========================================================
   SECRET MODAL
   ========================================================= */

function SecretModal({
  initial,
  password,
  onClose,
  onSaved,
}: {
  initial: Secret | null;
  password: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [title, setTitle] =
    useState(
      initial?.title || ""
    );

  const [category, setCategory] =
    useState(
      initial?.category ||
        "Password"
    );

  const [username, setUsername] =
    useState("");

  const [secret, setSecret] =
    useState("");

  const [notes, setNotes] =
    useState("");

  const [show, setShow] =
    useState(false);

  const [busy, setBusy] =
    useState(false);

  useEffect(() => {
    if (!initial) {
      return;
    }

    decrypt(
      initial,
      password
    )
      .then((value) => {
        const parsed =
          JSON.parse(value);

        setUsername(
          parsed.username || ""
        );

        setSecret(
          parsed.password ||
            parsed.value ||
            ""
        );

        setNotes(
          parsed.notes || ""
        );
      })
      .catch(() => {});
  }, [initial, password]);

  const generate = () => {
    const chars =
      "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";

    const random =
      crypto.getRandomValues(
        new Uint8Array(20)
      );

    setSecret(
      Array.from(
        random,
        (value) =>
          chars[
            value % chars.length
          ]
      ).join("")
    );
  };

  const save = async () => {
    if (!title || !secret) {
      return;
    }

    setBusy(true);

    try {
      const encrypted =
        await encrypt(
          JSON.stringify({
            username,
            password: secret,
            value: secret,
            notes,
          }),
          password
        );

      const body = {
        title,
        category,
        ...encrypted,
      };

      await api(
        initial
          ? `/secrets/${initial.id}`
          : "/secrets",
        {
          method: initial
            ? "PUT"
            : "POST",
          body: JSON.stringify(
            body
          ),
        }
      );

      onSaved();
      onClose();
    } catch (error: any) {
      alert(
        error?.message ||
          "Unable to save secret."
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="overlay">
      <div className="modal">
        <div className="modal-head">
          <div>
            <p className="eyebrow">
              {initial
                ? "EDIT SECRET"
                : "NEW SECRET"}
            </p>

            <h2>
              {initial
                ? "Update credential"
                : "Add a credential"}
            </h2>
          </div>

          <button
            onClick={onClose}
          >
            <X />
          </button>
        </div>

        <div className="form-grid">
          <label>
            Title

            <input
              value={title}
              onChange={(event) =>
                setTitle(
                  event.target.value
                )
              }
              placeholder="Production AWS"
            />
          </label>

          <label>
            Category

            <select
              value={category}
              onChange={(event) =>
                setCategory(
                  event.target.value
                )
              }
            >
              {[
                "Password",
                "Cloud",
                "Server",
                "Database",
                "API Key",
                "Email",
                "GitHub",
              ].map(
                (item) => (
                  <option
                    key={item}
                  >
                    {item}
                  </option>
                )
              )}
            </select>
          </label>
        </div>

        <label>
          Username / email

          <input
            value={username}
            onChange={(event) =>
              setUsername(
                event.target.value
              )
            }
            placeholder="admin@example.com"
          />
        </label>

        <label>
          Password / secret

          <div className="secret-input">
            <input
              type={
                show
                  ? "text"
                  : "password"
              }
              value={secret}
              onChange={(event) =>
                setSecret(
                  event.target.value
                )
              }
              placeholder="••••••••••••"
            />

            <button
              type="button"
              onClick={() =>
                setShow(!show)
              }
            >
              {show ? (
                <EyeOff size={17} />
              ) : (
                <Eye size={17} />
              )}
            </button>

            <button
              type="button"
              onClick={generate}
            >
              Generate
            </button>
          </div>
        </label>

        <label>
          Notes

          <textarea
            value={notes}
            onChange={(event) =>
              setNotes(
                event.target.value
              )
            }
            placeholder="Optional secure notes…"
          />
        </label>

        <div className="modal-foot">
          <span>
            <Lock size={14} />
            encrypted before storage
          </span>

          <div>
            <button
              className="secondary"
              onClick={onClose}
            >
              Cancel
            </button>

            <button
              className="primary"
              disabled={
                busy ||
                !title ||
                !secret
              }
              onClick={save}
            >
              {busy
                ? "Saving…"
                : "Save secret"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   APPLICATION ENTRY
   ========================================================= */

createRoot(
  document.getElementById("root")!
).render(<App />);
