import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../../lib/api';

export default function OtpPage() {
  const nav = useNavigate();
  const loc = useLocation();
  const qs = new URLSearchParams(loc.search);
  const [email, setEmail] = useState(qs.get('email') || '');
  const [otp, setOtp] = useState('');
  const [err, setErr] = useState('');
  const [devOtp, setDevOtp] = useState('');

  async function getDevOtp() {
    try {
      const { data } = await api.get(`/otp/dev/${encodeURIComponent(email)}`);
      setDevOtp(data.otp);
    } catch (e) {
      setErr(e.response?.data?.message || 'Could not fetch dev otp');
    }
  }

  async function verify(e) {
    e.preventDefault();
    setErr('');
    try {
      await api.post('/otp/verify', { email, otp });
      nav('/login', { replace: true });
    } catch (e2) {
      setErr(e2.response?.data?.message || 'OTP verify failed');
    }
  }

  return (
    <div className="auth-wrap">
      <form className="card form" onSubmit={verify}>
        <h1>Verify OTP</h1>
        {err && <p className="bad">{err}</p>}
        <input placeholder="Email" value={email} onChange={(e)=>setEmail(e.target.value)} />
        <input placeholder="OTP" value={otp} onChange={(e)=>setOtp(e.target.value)} />
        <button type="submit">Verify</button>
        <button type="button" onClick={getDevOtp}>Get local dev OTP</button>
        {devOtp && <p className="ok">Dev OTP: {devOtp}</p>}
      </form>
    </div>
  );
}
