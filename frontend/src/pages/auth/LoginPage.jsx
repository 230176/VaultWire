import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

export default function LoginPage() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [err, setErr] = useState('');

  async function submit(e) {
    e.preventDefault();
    setErr('');
    try {
      const u = await login(email, password);
      nav(['admin','superadmin'].includes(u.role) ? '/admin' : '/', { replace: true });
    } catch (e2) {
      setErr(e2.response?.data?.message || 'Login failed');
    }
  }

  return (
    <div className="auth-wrap">
      <form className="card form" onSubmit={submit}>
        <h1>Login</h1>
        {err && <p className="bad">{err}</p>}
        <input placeholder="Email" value={email} onChange={(e)=>setEmail(e.target.value)} />
        <div className="inline">
          <input type={show ? 'text' : 'password'} placeholder="Password" value={password} onChange={(e)=>setPassword(e.target.value)} />
          <button type="button" onClick={()=>setShow(!show)}>{show?'Hide':'Show'}</button>
        </div>
        <button type="submit">Login</button>
        <p>No account? <Link to="/register">Register</Link></p>
        <p>Admin? <Link to="/admin/login">Admin login</Link></p>
      </form>
    </div>
  );
}
