import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function AdminRateLimitsPage() {
  const [rows, setRows] = useState([]);

  useEffect(() => {
    api.get('/admin/rate-limit/metrics').then((r) => setRows(r.data)).catch(() => {});
  }, []);

  return (
    <div>
      <h1>Rate-limit Visualization</h1>
      <div className="card">
        {rows.map((r) => (
          <div key={r._id} className="bar-row">
            <span>{r._id}</span>
            <div className="bar-wrap"><div className="bar" style={{ width: `${Math.min(100, r.count * 10)}%` }} /></div>
            <strong>{r.count}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
