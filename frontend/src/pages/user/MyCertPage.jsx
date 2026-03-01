import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function MyCertPage() {
  const [cert,setCert] = useState(null);
  const [ca,setCa] = useState(null);
  const [err,setErr] = useState('');
  const [msg,setMsg] = useState('');

  async function load() {
    setErr('');
    const [c, r] = await Promise.all([api.get('/pki/my-cert'), api.get('/pki/ca')]);
    setCert(c.data);
    setCa(r.data);
  }

  useEffect(() => {
    load().catch((e)=>setErr(e.response?.data?.message || 'Failed'));
  }, []);

  async function rotateKeys() {
    setErr('');
    setMsg('');
    try {
      const res = await api.post('/pki/me/rotate-keys', {});
      setMsg(res.data?.message || 'Keys rotated. Ask admin to issue a new certificate.');
      await load().catch(()=>{});
    } catch (e) {
      setErr(e.response?.data?.message || 'Key rotation failed');
    }
  }

  return (
    <div>
      <h1>My Certificate</h1>
      {err && <p className="bad">{err}</p>}
      {msg && <p className="ok">{msg}</p>}
      <div className="card" style={{ marginBottom: 12 }}>
        <h3>Key Lifecycle</h3>
        <p>Rotate keys when compromised or on scheduled renewal. After rotation, admin must issue a new certificate.</p>
        <button onClick={rotateKeys}>Rotate my keys</button>
      </div>
      {cert && <div className="card"><p>Status: <strong>{cert.status}</strong></p><p>Serial: {cert.serial}</p><textarea rows="8" readOnly value={cert.pem} /></div>}
      {ca && <div className="card"><p>CA fingerprint: {ca.fingerprint}</p><textarea rows="8" readOnly value={ca.certPem} /></div>}
    </div>
  );
}
