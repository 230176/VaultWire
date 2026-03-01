import React, { useEffect, useMemo, useState } from "react";
import { api } from "../../lib/api";

function normalizeId(v) {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") return String(v._id || v.id || "");
  return String(v);
}

function copyText(text) {
  return navigator.clipboard?.writeText(text);
}

export default function VaultPage() {
  const [list, setList] = useState([]);
  const [friends, setFriends] = useState([]);
  const [file, setFile] = useState(null);
  const [title, setTitle] = useState("");
  const [recipientIds, setRecipientIds] = useState([]);
  const [sharePresetByFile, setSharePresetByFile] = useState({});
  const [editRecipientsByFile, setEditRecipientsByFile] = useState({});
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const friendMap = useMemo(() => {
    const m = new Map();
    friends.forEach((f) => m.set(String(f.id), f.username));
    return m;
  }, [friends]);

  async function load() {
    const [l, f] = await Promise.all([
      api.get("/vault/list"),
      api.get("/friends/list"),
    ]);
    setList(l.data);
    setFriends(f.data);

    const presets = {};
    const edits = {};
    l.data.forEach((v) => {
      presets[v.id] = "1h";
      edits[v.id] = (v.recipients || []).map((r) => String(r));
    });
    setSharePresetByFile(presets);
    setEditRecipientsByFile(edits);
  }

  useEffect(() => {
    load().catch((e) => setErr(e.response?.data?.message || "Load failed"));
  }, []);

  function toggleRecipient(id) {
    setRecipientIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  }

  function toggleEditRecipient(fileId, id) {
    setEditRecipientsByFile((prev) => {
      const cur = prev[fileId] || [];
      const next = cur.includes(id)
        ? cur.filter((x) => x !== id)
        : [...cur, id];
      return { ...prev, [fileId]: next };
    });
  }

  async function upload(e) {
    e.preventDefault();
    setErr("");
    setMsg("");

    if (!file) return setErr("Pick a file");
    if (file.size > 50 * 1024 * 1024) return setErr("Max 50MB");

    const fd = new FormData();
    fd.append("file", file);
    fd.append("title", title || file.name);
    fd.append("recipientIds", JSON.stringify(recipientIds));

    try {
      await api.post("/vault/upload", fd);
      setMsg("Encrypted upload complete.");
      setFile(null);
      setTitle("");
      setRecipientIds([]);
      await load();
    } catch (e2) {
      setErr(e2.response?.data?.message || "Upload failed");
    }
  }

  async function updateRecipients(vaultId) {
    setErr("");
    setMsg("");
    try {
      const ids = editRecipientsByFile[vaultId] || [];
      await api.post(`/vault/${vaultId}/share-recipients`, {
        recipientIds: ids,
      });
      setMsg("Sharing permissions updated.");
      await load();
    } catch (e) {
      setErr(e.response?.data?.message || "Share update failed");
    }
  }

  async function decrypt(id) {
    setErr("");
    setMsg("");
    try {
      const res = await api.post(
        `/vault/${id}/decrypt`,
        {},
        { responseType: "arraybuffer" },
      );
      const blob = new Blob([res.data], {
        type: res.headers["content-type"] || "application/octet-stream",
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      const disposition = res.headers["content-disposition"];
      const match = disposition?.match(/filename="(.+)"/);
      a.href = url;
      a.download = match?.[1] || "vault-file";
      a.click();
      window.URL.revokeObjectURL(url);
      setMsg("Decrypted file downloaded.");
    } catch (e) {
      setErr(e.response?.data?.message || "Decrypt failed");
    }
  }

  async function createShare(vaultId) {
    setErr("");
    setMsg("");
    try {
      const preset = sharePresetByFile[vaultId] || "1h";
      const res = await api.post(`/vault/${vaultId}/share-link`, {
        expiryPreset: preset,
      });
      const token = res.data.token;
      const sharePath = `/api/v1/vault/share/${token}`;
      const abs = `${window.location.origin}${sharePath}`;
      setMsg(
        `Encrypted share link created (expires ${new Date(res.data.expiresAt).toLocaleString()}): ${abs}`,
      );
      await copyText(abs).catch(() => {});
    } catch (e) {
      setErr(e.response?.data?.message || "Share link failed");
    }
  }

  return (
    <div>
      <h1>Vault</h1>
      {msg && (
        <p className="ok" style={{ whiteSpace: "pre-wrap" }}>
          {msg}
        </p>
      )}
      {err && <p className="bad">{err}</p>}

      <form onSubmit={upload} className="card form">
        <h3>Upload encrypted file</h3>
        <input
          placeholder="Title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />
        <small>Max file size: 50MB</small>

        <div>
          <strong>Share with friends at upload time</strong>
          {friends.length === 0 && (
            <div>
              <small>No friends available yet.</small>
            </div>
          )}
          {friends.map((f) => (
            <label key={f.id} className="row">
              <input
                type="checkbox"
                checked={recipientIds.includes(f.id)}
                onChange={() => toggleRecipient(f.id)}
              />
              {f.username}
            </label>
          ))}
        </div>

        <button type="submit">Encrypt & Upload</button>
      </form>

      <div className="card">
        <h3>Your / Shared Vault Files</h3>
        {list.length === 0 && <small>No vault files yet.</small>}

        {list.map((v) => {
          const recipients = (editRecipientsByFile[v.id] || []).map(String);
          const latestHash = v.versions?.[v.versions.length - 1]?.hash || "";

          return (
            <div key={v.id} className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ alignItems: "flex-start" }}>
                <div>
                  <strong>{v.title}</strong>
                  <div>Latest v{v.latestVersion}</div>
                  {latestHash && (
                    <small>latest hash: {latestHash.slice(0, 18)}...</small>
                  )}
                  <div>
                    <small>
                      versions:{" "}
                      {v.versions
                        .map((x) => `v${x.version}:${x.hash.slice(0, 10)}...`)
                        .join(" | ")}
                    </small>
                  </div>
                </div>

                <div className="actions">
                  <button onClick={() => decrypt(v.id)} type="button">
                    Decrypt Download
                  </button>
                </div>
              </div>

              <div style={{ marginTop: 10 }}>
                <strong>Share this file with friends</strong>
                {friends.length === 0 && (
                  <div>
                    <small>Add friends first to share.</small>
                  </div>
                )}
                {friends.map((f) => {
                  const checked = recipients.includes(String(f.id));
                  return (
                    <label key={`${v.id}-${f.id}`} className="row">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleEditRecipient(v.id, String(f.id))}
                      />
                      {f.username}
                    </label>
                  );
                })}

                <div
                  className="actions"
                  style={{ marginTop: 8, flexWrap: "wrap" }}
                >
                  <button type="button" onClick={() => updateRecipients(v.id)}>
                    Save sharing list
                  </button>

                  <select
                    value={sharePresetByFile[v.id] || "1h"}
                    onChange={(e) =>
                      setSharePresetByFile((prev) => ({
                        ...prev,
                        [v.id]: e.target.value,
                      }))
                    }
                    style={{ minWidth: 110 }}
                  >
                    <option value="10m">10m</option>
                    <option value="1h">1h</option>
                    <option value="1d">1d</option>
                    <option value="7d">7d</option>
                  </select>
                  <button onClick={() => createShare(v.id)} type="button">
                    Create encrypted share link
                  </button>
                </div>
                <small>
                  Tip: choose file block above, tick recipients, click{" "}
                  <strong>Save sharing list</strong>, then create share link if
                  needed.
                </small>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
