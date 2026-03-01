import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

function downloadBlob(data, filename, type = 'application/octet-stream') {
  const blob = new Blob([data], { type });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  window.URL.revokeObjectURL(url);
}

export default function AdminAuditPage() {
  const [rows,setRows]=useState([]);
  const [q,setQ]=useState('');

  async function load() {
    const { data } = await api.get('/admin/audit', { params: { q } });
    setRows(data);
  }
  useEffect(()=>{ load(); },[]);

  async function exportCsv() {
    const res = await api.get('/admin/audit/export.csv', { responseType: 'arraybuffer' });
    downloadBlob(res.data, 'audit.csv', 'text/csv');
  }

  async function exportJson() {
    const res = await api.get('/admin/audit/export.json');
    downloadBlob(JSON.stringify(res.data, null, 2), 'audit.json', 'application/json');
  }

  return (
    <div>
      <h1>Audit Logs</h1>
      <div className="card row">
        <input placeholder="Search action/target" value={q} onChange={(e)=>setQ(e.target.value)} />
        <button onClick={load}>Search</button>
        <button onClick={exportCsv}>Export CSV</button>
        <button onClick={exportJson}>Export JSON</button>
      </div>
      <div className="card">
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Outcome</th><th>Correlation</th></tr></thead>
          <tbody>{rows.map((r)=><tr key={r._id}><td>{new Date(r.createdAt).toLocaleString()}</td><td>{r.action}</td><td>{r.target}</td><td>{r.outcome}</td><td>{r.correlationId}</td></tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}
