import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../lib/api";
import { getSocket } from "../../lib/socket";
import { useAuth } from "../../context/AuthContext";

function normalizeId(v) {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") return String(v._id || v.id || "");
  return String(v);
}

function fmt(dt) {
  if (!dt) return "";
  const d = new Date(dt);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

export default function MessagesPage() {
  const { user } = useAuth();

  const [friends, setFriends] = useState([]);
  const [peerId, setPeerId] = useState("");
  const [thread, setThread] = useState([]);
  const [text, setText] = useState("");
  const [preset, setPreset] = useState("1h");
  const [err, setErr] = useState("");

  const threadRef = useRef(null);

  const myId = normalizeId(user?._id || user?.id);
  const myName = user?.username || user?.email || "You";

  const activeFriend = useMemo(
    () => friends.find((f) => String(f.id) === String(peerId)),
    [friends, peerId],
  );
  const peerName = activeFriend?.username || "Friend";

  async function loadFriends() {
    const { data } = await api.get("/friends/list");
    setFriends(data);
    if (!peerId && data.length) setPeerId(data[0].id);
  }

  async function loadThread(pid = peerId) {
    if (!pid) {
      setThread([]);
      return;
    }
    const { data } = await api.get(`/messages/thread/${pid}`);
    setThread(Array.isArray(data) ? data : []);
  }

  useEffect(() => {
    loadFriends().catch((e) =>
      setErr(e.response?.data?.message || "Load failed"),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    loadThread().catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [peerId]);

  useEffect(() => {
    const s = getSocket();
    if (!s) return;
    const onNew = () => loadThread().catch(() => {});
    s.on("message:new", onNew);
    return () => s.off("message:new", onNew);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [peerId]);

  useEffect(() => {
    if (!threadRef.current) return;
    threadRef.current.scrollTop = threadRef.current.scrollHeight;
  }, [thread]);

  async function send(e) {
    e.preventDefault();
    setErr("");
    if (!peerId || !text.trim()) return;

    const now = Date.now();

    try {
      await api.post("/messages/send", {
        toUserId: peerId,
        text: text.trim(),
        expiryPreset: preset,
        messageId: `msg-${now}-${Math.random().toString(36).slice(2)}`,
        nonce: `nonce-${now}-${Math.random().toString(36).slice(2)}`,
      });

      setText("");
      await loadThread();
    } catch (e2) {
      setErr(e2.response?.data?.message || "Send failed");
    }
  }

  function isMine(m) {
    const fromId = normalizeId(m.fromUser);
    return fromId && fromId === myId;
  }

  function senderLabel(m) {
    return isMine(m) ? myName : peerName;
  }

  return (
    <div>
      <h1>Secure Messages</h1>
      {err && <p className="bad">{err}</p>}

      <div className="grid">
        <div className="card">
          <h3>Friends</h3>
          {friends.length === 0 && <small>No friends yet.</small>}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {friends.map((f) => (
              <button
                key={f.id}
                className={peerId === f.id ? "active" : ""}
                onClick={() => setPeerId(f.id)}
                type="button"
              >
                {f.username}
              </button>
            ))}
          </div>
        </div>

        <div className="card">
          <h3>Thread {activeFriend ? `• ${peerName}` : ""}</h3>

          <div
            ref={threadRef}
            style={{
              maxHeight: 420,
              minHeight: 320,
              overflowY: "auto",
              overflowX: "hidden",
              border: "1px dashed var(--line)",
              borderRadius: 10,
              padding: 10,
              marginBottom: 10,
            }}
          >
            {thread.length === 0 ? (
              <small style={{ opacity: 0.8 }}>
                No messages yet. Start the conversation.
              </small>
            ) : (
              thread.map((m) => {
                const mine = isMine(m);
                return (
                  <div
                    key={m.id}
                    style={{
                      display: "flex",
                      justifyContent: mine ? "flex-end" : "flex-start",
                      margin: "8px 0",
                    }}
                  >
                    <div
                      style={{
                        maxWidth: "80%",
                        background: mine
                          ? "rgba(31,58,138,0.35)"
                          : "rgba(255,255,255,0.06)",
                        border: "1px solid var(--line)",
                        borderRadius: 12,
                        padding: "8px 10px",
                      }}
                    >
                      <div
                        style={{
                          fontSize: 12,
                          opacity: 0.9,
                          marginBottom: 6,
                          fontWeight: 600,
                        }}
                      >
                        {senderLabel(m)}
                      </div>

                      <div
                        style={{
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-word",
                        }}
                      >
                        {m.text}
                      </div>

                      <small style={{ display: "block", marginTop: 6 }}>
                        {fmt(m.createdAt)} • expires {fmt(m.expiresAt)}
                      </small>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <form onSubmit={send} className="row">
            <input
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={
                peerId ? `Message ${peerName}` : "Select a friend first"
              }
              disabled={!peerId}
            />

            <select
              value={preset}
              onChange={(e) => setPreset(e.target.value)}
              disabled={!peerId}
            >
              <option value="10s">10s</option>
              <option value="1m">1m</option>
              <option value="10m">10m</option>
              <option value="1h">1h</option>
              <option value="1d">1d</option>
            </select>

            <button type="submit" disabled={!peerId || !text.trim()}>
              Send
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
