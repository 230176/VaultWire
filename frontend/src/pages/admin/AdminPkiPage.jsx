import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function AdminPkiPage() {
  const [users,setUsers]=useState([]);
  const [serial,setSerial]=useState('');
  const [crl,setCrl]=useState([]);
  const [msg,setMsg]=useState('');
  const [err,setErr]=useState('');

  async function load() {
    const [u, c] = await Promise.all([api.get('/admin/users'), api.get('/pki/admin/crl.json')]);
    setUsers(u.data); setCrl(c.data.revoked || []);
  }
  useEffect(()=>{ load().catch((e)=>setErr(e.response?.data?.message || 'Failed')); },[]);

  async function initCA() {
    try { await api.post('/pki/admin/init-ca',{}); setMsg('CA initialized'); } catch(e){setErr(e.response?.data?.message || 'Init CA failed');}
  }
  async function issue(userId) {
    try { await api.post(`/pki/admin/issue/${userId}`,{}); setMsg('Certificate issued'); await load(); } catch(e){setErr(e.response?.data?.message || 'Issue failed');}
  }
  async function renew(userId) {
    try { await api.post(`/pki/admin/renew/${userId}`,{}); setMsg('Certificate renewed'); await load(); } catch(e){setErr(e.response?.data?.message || 'Renew failed');}
  }
  async function revoke() {
    try { await api.post('/pki/admin/revoke',{serial, reason:'admin_action'}); setMsg('Revoked'); setSerial(''); await load(); } catch(e){setErr(e.response?.data?.message || 'Revoke failed');}
  }

  return (
    <div>
      <h1>Admin PKI</h1>
      {msg && <p className="ok">{msg}</p>}
      {err && <p className="bad">{err}</p>}
      <div className="card">
        <button onClick={initCA}>Initialize CA</button>
      </div>
      <div className="grid">
        <div className="card">
          <h3>Issue/Renew certificates</h3>
          {users.map((u)=>(<div key={u._id} className="row"><span>{u.username}</span><div className="actions"><button onClick={()=>issue(u._id)}>Issue</button><button onClick={()=>renew(u._id)}>Renew</button></div></div>))}
        </div>
        <div className="card">
          <h3>Revoke certificate</h3>
          <input placeholder="Serial" value={serial} onChange={(e)=>setSerial(e.target.value)} />
          <button onClick={revoke}>Revoke</button>
          <h4>CRL snapshot</h4>
          <pre>{JSON.stringify(crl, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}
