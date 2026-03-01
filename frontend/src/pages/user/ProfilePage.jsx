import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function ProfilePage() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');

  async function load() {
    const res = await api.get('/profiles/me');
    setData(res.data);
  }
  useEffect(() => { load().catch((e)=>setErr(e.response?.data?.message || 'Failed')); }, []);

  async function save(e) {
    e.preventDefault();
    setErr(''); setMsg('');
    try {
      const res = await api.patch('/profiles/me', data);
      setData(res.data);
      setMsg('Profile updated');
    } catch (e2) {
      setErr(e2.response?.data?.message || 'Update failed');
    }
  }

  if (!data) return <div>Loading...</div>;
  return (
    <form onSubmit={save}>
      <h1>Profile</h1>
      {err && <p className="bad">{err}</p>}
      {msg && <p className="ok">{msg}</p>}
      <div className="card form">
        <label>Username</label>
        <input value={data.username||''} onChange={(e)=>setData({...data,username:e.target.value})} />
        <label>Email</label>
        <input disabled value={data.email||''} />
        <label>Phone</label>
        <input value={data.phone||''} onChange={(e)=>setData({...data,phone:e.target.value})} />
        <label>Bio</label>
        <textarea value={data.bio||''} onChange={(e)=>setData({...data,bio:e.target.value})} />
        <h3>Privacy</h3>
        <label>Global</label>
        <select value={data.privacy?.global || 'public'} onChange={(e)=>setData({...data,privacy:{...data.privacy,global:e.target.value}})}>
          <option value="public">public</option><option value="private">private</option>
        </select>
        <label>Phone</label>
        <select value={data.privacy?.phone || 'private'} onChange={(e)=>setData({...data,privacy:{...data.privacy,phone:e.target.value}})}>
          <option value="public">public</option><option value="private">private</option>
        </select>
        <label>Email</label>
        <select value={data.privacy?.email || 'private'} onChange={(e)=>setData({...data,privacy:{...data.privacy,email:e.target.value}})}>
          <option value="public">public</option><option value="private">private</option>
        </select>
        <label>Bio</label>
        <select value={data.privacy?.bio || 'public'} onChange={(e)=>setData({...data,privacy:{...data.privacy,bio:e.target.value}})}>
          <option value="public">public</option><option value="private">private</option>
        </select>
        <button type="submit">Save profile</button>
      </div>
    </form>
  );
}
