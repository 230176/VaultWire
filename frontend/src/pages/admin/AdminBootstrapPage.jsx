import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

export default function AdminBootstrapPage() {
  const { bootstrapAdmin } = useAuth();
  const nav = useNavigate();
  const [form,setForm]=useState({token:'change-me-bootstrap',username:'admin',email:'admin@vaultwire.local',password:'Str0ng!Pass'});
  const [msg,setMsg]=useState('');
  const [err,setErr]=useState('');

  async function submit(e){
    e.preventDefault();
    setErr(''); setMsg('');
    try{
      await bootstrapAdmin(form);
      setMsg('Admin created. Please login.');
      nav('/admin/login', { replace: true });
    }catch(e2){setErr(e2.response?.data?.message || 'Bootstrap failed');}
  }

  return (
    <div className="auth-wrap">
      <form className="card form" onSubmit={submit}>
        <h1>Admin Bootstrap</h1>
        {msg && <p className="ok">{msg}</p>}
        {err && <p className="bad">{err}</p>}
        <input value={form.token} onChange={(e)=>setForm({...form,token:e.target.value})} placeholder="Bootstrap Token"/>
        <input value={form.username} onChange={(e)=>setForm({...form,username:e.target.value})} placeholder="Username"/>
        <input value={form.email} onChange={(e)=>setForm({...form,email:e.target.value})} placeholder="Email"/>
        <input type="password" value={form.password} onChange={(e)=>setForm({...form,password:e.target.value})} placeholder="Password"/>
        <button type="submit">Create Admin</button>
      </form>
    </div>
  );
}
