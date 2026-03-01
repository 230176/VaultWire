import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function SessionsPage() {
  const [sessions, setSessions] = useState([]);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  async function load() {
    const { data } = await api.get('/sessions/me');
    setSessions(data);
  }
  useEffect(() => { load().catch((e)=>setErr(e.response?.data?.message || 'Failed')); }, []);

  async function revokeOne(id) {
    await api.delete(`/sessions/me/${id}`);
    setMsg('Session revoked');
    await load();
  }
  async function logoutOthers() {
    await api.post('/auth/logout-others');
    setMsg('Other sessions logged out');
    await load();
  }

  return (
    <div>
      <h1>Device / Session Management</h1>
      {msg && <p className="ok">{msg}</p>}
      {err && <p className="bad">{err}</p>}
      <button onClick={logoutOthers}>Logout other sessions</button>
      <div className="card">
        {sessions.map((s)=>(
          <div key={s._id} className="row">
            <div>
              <div>{s.userAgent || 'Unknown agent'}</div>
              <small>{s.ip} - {new Date(s.createdAt).toLocaleString()}</small>
            </div>
            <button onClick={()=>revokeOne(s._id)}>Revoke</button>
          </div>
        ))}
      </div>
    </div>
  );
}
