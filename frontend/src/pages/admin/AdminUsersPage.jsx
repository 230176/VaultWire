import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function AdminUsersPage() {
  const [users,setUsers]=useState([]);
  const [msg,setMsg]=useState('');
  const [err,setErr]=useState('');

  async function load(){ const {data}=await api.get('/admin/users'); setUsers(data); }
  useEffect(()=>{ load().catch((e)=>setErr(e.response?.data?.message || 'Failed')); },[]);

  async function disableUser(id){ await api.post(`/admin/users/${id}/disable`,{}); setMsg('User disabled'); await load(); }
  async function forceLogout(id){ await api.post(`/admin/users/${id}/force-logout`,{}); setMsg('Forced logout done'); }

  return (
    <div>
      <h1>Admin Users</h1>
      {msg && <p className="ok">{msg}</p>}
      {err && <p className="bad">{err}</p>}
      <div className="card">
        {users.map((u)=>(
          <div className="row" key={u._id}>
            <div><strong>{u.username}</strong> ({u.email}) {u.disabled ? '[DISABLED]' : ''}</div>
            <div className="actions">
              <button onClick={()=>disableUser(u._id)}>Disable</button>
              <button onClick={()=>forceLogout(u._id)}>Force logout</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
