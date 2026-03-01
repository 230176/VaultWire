import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../../lib/api';
import { PasswordStrength, passwordChecks } from '../../components/PasswordStrength';

export default function RegisterPage() {
  const nav = useNavigate();
  const [form, setForm] = useState({ username:'', email:'', password:'', confirmPassword:'', phone:'', bio:'' });
  const [show1, setShow1] = useState(false);
  const [show2, setShow2] = useState(false);
  const [err, setErr] = useState('');
  const checks = passwordChecks(form.password, form.confirmPassword);

  function update(k,v){ setForm((s)=>({ ...s, [k]: v })); }

  async function submit(e){
    e.preventDefault();
    setErr('');
    if (!Object.values(checks).every(Boolean)) return setErr('Password policy not met');
    try {
      await api.post('/auth/register', {
        username: form.username, email: form.email, password: form.password, phone: form.phone, bio: form.bio
      });
      nav(`/otp?email=${encodeURIComponent(form.email)}`, { replace: true });
    } catch(e2) {
      setErr(e2.response?.data?.message || 'Register failed');
    }
  }

  return (
    <div className="auth-wrap">
      <form className="card form" onSubmit={submit}>
        <h1>Register</h1>
        {err && <p className="bad">{err}</p>}
        <input placeholder="Username" value={form.username} onChange={(e)=>update('username', e.target.value)} />
        <input placeholder="Email" value={form.email} onChange={(e)=>update('email', e.target.value)} />
        <div className="inline">
          <input type={show1?'text':'password'} placeholder="Password" value={form.password} onChange={(e)=>update('password', e.target.value)} />
          <button type="button" onClick={()=>setShow1(!show1)}>{show1?'Hide':'Show'}</button>
        </div>
        <div className="inline">
          <input type={show2?'text':'password'} placeholder="Confirm Password" value={form.confirmPassword} onChange={(e)=>update('confirmPassword', e.target.value)} />
          <button type="button" onClick={()=>setShow2(!show2)}>{show2?'Hide':'Show'}</button>
        </div>
        <input placeholder="Phone" value={form.phone} onChange={(e)=>update('phone', e.target.value)} />
        <textarea placeholder="Bio" value={form.bio} onChange={(e)=>update('bio', e.target.value)} />
        <PasswordStrength password={form.password} confirmPassword={form.confirmPassword} />
        <button type="submit">Create account</button>
        <p>Have account? <Link to="/login">Login</Link></p>
      </form>
    </div>
  );
}
