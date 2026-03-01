import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';
import { getSocket } from '../../lib/socket';

export default function FriendsPage() {
  const [q, setQ] = useState('');
  const [results, setResults] = useState([]);
  const [requests, setRequests] = useState({ incoming: [], outgoing: [] });
  const [friends, setFriends] = useState([]);
  const [msg, setMsg] = useState('');

  async function loadRequests() {
    const [r1, r2] = await Promise.all([api.get('/friends/requests'), api.get('/friends/list')]);
    setRequests(r1.data);
    setFriends(r2.data);
  }
  useEffect(() => {
    loadRequests();
    const s = getSocket();
    if (s) {
      const refresh = () => { loadRequests().catch(()=>{}); if (q) search(q); };
      s.on('friend:request', refresh);
      s.on('friend:updated', refresh);
      s.on('friend:cancelled', refresh);
      return () => {
        s.off('friend:request', refresh);
        s.off('friend:updated', refresh);
        s.off('friend:cancelled', refresh);
      };
    }
  }, []);

  async function search(value) {
    setQ(value);
    if (!value.trim()) { setResults([]); return; }
    const res = await api.get('/friends/search', { params: { q: value } });
    setResults(res.data);
  }

  async function sendRequest(id) {
    await api.post('/friends/request', { toUserId: id });
    setMsg('Request sent');
    await search(q);
    await loadRequests();
  }
  async function cancelRequest(id) {
    await api.post('/friends/cancel', { toUserId: id });
    setMsg('Request cancelled');
    await search(q);
    await loadRequests();
  }
  async function respond(id, action) {
    await api.post('/friends/respond', { fromUserId: id, action });
    setMsg(`Request ${action}ed`);
    await search(q);
    await loadRequests();
  }

  return (
    <div>
      <h1>Friends</h1>
      {msg && <p className="ok">{msg}</p>}
      <div className="card">
        <label>Search users</label>
        <input placeholder="Search by username/email" value={q} onChange={(e)=>search(e.target.value)} />
        {!!results.length && (
          <div className="search-dropdown">
            {results.map((r) => (
              <div className="search-item" key={r.id}>
                <div>
                  <strong>{r.username}</strong>
                  <small>{r.email}</small>
                </div>
                <div className="actions">
                  {r.relation === 'none' && <button onClick={()=>sendRequest(r.id)}>Send request</button>}
                  {r.relation === 'requested' && <button onClick={()=>cancelRequest(r.id)}>Cancel request</button>}
                  {r.relation === 'incoming' && (
                    <>
                      <button onClick={()=>respond(r.id, 'accept')}>Accept</button>
                      <button onClick={()=>respond(r.id, 'reject')}>Reject</button>
                    </>
                  )}
                  {r.relation === 'friends' && <span className="ok">Friends</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid">
        <div className="card">
          <h3>Incoming requests</h3>
          {requests.incoming?.map((r) => (
            <div key={r.id} className="row">
              <span>{r.from.username}</span>
              <button onClick={()=>respond(r.from._id, 'accept')}>Accept</button>
              <button onClick={()=>respond(r.from._id, 'reject')}>Reject</button>
            </div>
          ))}
        </div>
        <div className="card">
          <h3>Friends</h3>
          {friends?.map((f) => <div key={f.id}>{f.username} ({f.email})</div>)}
        </div>
      </div>
    </div>
  );
}
