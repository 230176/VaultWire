import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

export default function AdminLoginPage() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [email,setEmail]=useState('');
  const [password,setPassword]=useState('');
  const [err,setErr]=useState('');

  async function submit(e){
    e.preventDefault();
    setErr('');
    try {
      const u = await login(email,password);
      if (!['admin','superadmin'].includes(u.role)) {
        setErr('This login is for admins only');
        return;
      }
      nav('/admin', { replace: true });
    } catch(e2) {
      setErr(e2.response?.data?.message || 'Login failed');
    }
  }
  return (
    <div className="auth-wrap">
      <form className="card form" onSubmit={submit}>
        <h1>Admin Login</h1>
        {err && <p className="bad">{err}</p>}
        <input placeholder="Admin email" value={email} onChange={(e)=>setEmail(e.target.value)} />
        <input type="password" placeholder="Password" value={password} onChange={(e)=>setPassword(e.target.value)} />
        <button type="submit">Login</button>
        <p>Need admin access? <Link to="/admin/register">Register as admin (requires superadmin approval)</Link></p>
      </form>
    </div>
  );
}
