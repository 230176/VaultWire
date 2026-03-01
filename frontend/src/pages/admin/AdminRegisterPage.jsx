import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../lib/api';
import { PasswordStrength, passwordChecks } from '../../components/PasswordStrength';

export default function AdminRegisterPage() {
  const [form, setForm] = useState({ username:'', email:'', password:'', confirmPassword:'' });
  const [show1, setShow1] = useState(false);
  const [show2, setShow2] = useState(false);
  const [err, setErr] = useState('');
  const [ok, setOk] = useState('');
  const checks = passwordChecks(form.password, form.confirmPassword);

  function update(k,v){ setForm((s)=>({ ...s, [k]: v })); }

  async function submit(e){
    e.preventDefault();
    setErr('');
    setOk('');
    if (!Object.values(checks).every(Boolean)) {
      setErr('Password policy not met');
      return;
    }
    try {
      const { data } = await api.post('/auth/admin/register', {
        username: form.username, email: form.email, password: form.password
      });
      setOk(data.message || 'Registration submitted. Wait for superadmin approval.');
      setForm({ username:'', email:'', password:'', confirmPassword:'' });
    } catch (e2) {
      setErr(e2.response?.data?.message || 'Admin registration failed');
    }
  }

  return (
    <div className="auth-wrap">
      <form className="card form" onSubmit={submit}>
        <h1>Admin Registration</h1>
        {err && <p className="bad">{err}</p>}
        {ok && <p className="ok">{ok}</p>}
        <input placeholder="Admin username" value={form.username} onChange={(e)=>update('username', e.target.value)} />
        <input placeholder="Admin email" value={form.email} onChange={(e)=>update('email', e.target.value)} />
        <div className="inline">
          <input type={show1?'text':'password'} placeholder="Password" value={form.password} onChange={(e)=>update('password', e.target.value)} />
          <button type="button" onClick={()=>setShow1(!show1)}>{show1?'Hide':'Show'}</button>
        </div>
        <div className="inline">
          <input type={show2?'text':'password'} placeholder="Confirm Password" value={form.confirmPassword} onChange={(e)=>update('confirmPassword', e.target.value)} />
          <button type="button" onClick={()=>setShow2(!show2)}>{show2?'Hide':'Show'}</button>
        </div>
        <PasswordStrength password={form.password} confirmPassword={form.confirmPassword} />
        <button type="submit">Submit for approval</button>
        <p>Already approved? <Link to="/admin/login">Admin login</Link></p>
      </form>
    </div>
  );
}
