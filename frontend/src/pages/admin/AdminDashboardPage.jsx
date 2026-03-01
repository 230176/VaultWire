import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function AdminDashboardPage() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    api.get('/admin/risk/summary').then((r)=>setData(r.data)).catch((e)=>setErr(e.response?.data?.message || 'Failed'));
  }, []);

  return (
    <div>
      <h1>Admin Risk Dashboard</h1>
      {err && <p className="bad">{err}</p>}
      {data && (
        <div className="grid">
          <div className="card"><h3>Failed logins (24h)</h3><p>{data.failedLogins24h}</p></div>
          <div className="card"><h3>Revoked cert count</h3><p>{data.revokedCount}</p></div>
          <div className="card"><h3>Rate-limit hits (24h)</h3><p>{data.rateLimitHits24h}</p></div>
          <div className="card"><h3>Disabled users</h3><p>{data.disabledUsers}</p></div>
        </div>
      )}
    </div>
  );
}
