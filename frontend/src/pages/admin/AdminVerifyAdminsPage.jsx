import React, { useEffect, useState } from 'react';
import { api } from '../../lib/api';

export default function AdminVerifyAdminsPage() {
  const [pending, setPending] = useState([]);
  const [allAdmins, setAllAdmins] = useState([]);
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');

  async function load() {
    setErr('');
    try {
      const [{ data: p }, { data: a }] = await Promise.all([
        api.get('/admin/admins/pending'),
        api.get('/admin/admins')
      ]);
      setPending(p);
      setAllAdmins(a);
    } catch (e) {
      setErr(e.response?.data?.message || 'Failed to load admin registrations');
    }
  }

  useEffect(() => { load(); }, []);

  async function approve(id) {
    setMsg('');
    setErr('');
    try {
      await api.post(`/admin/admins/${id}/approve`);
      setMsg('Admin approved');
      await load();
    } catch (e) {
      setErr(e.response?.data?.message || 'Approve failed');
    }
  }

  async function reject(id) {
    setMsg('');
    setErr('');
    try {
      await api.post(`/admin/admins/${id}/reject`);
      setMsg('Admin rejected and disabled');
      await load();
    } catch (e) {
      setErr(e.response?.data?.message || 'Reject failed');
    }
  }

  return (
    <section>
      <h1>Verify Admin Registrations</h1>
      {err && <p className="bad">{err}</p>}
      {msg && <p className="ok">{msg}</p>}

      <div className="card">
        <h2>Pending Admin Registrations</h2>
        {!pending.length && <p>No pending admin registrations.</p>}
        {pending.length > 0 && (
          <table className="table">
            <thead><tr><th>Username</th><th>Email</th><th>Requested</th><th>Action</th></tr></thead>
            <tbody>
              {pending.map((a) => (
                <tr key={a._id}>
                  <td>{a.username}</td>
                  <td>{a.email}</td>
                  <td>{new Date(a.createdAt).toLocaleString()}</td>
                  <td className="inline">
                    <button onClick={()=>approve(a._id)}>Approve</button>
                    <button onClick={()=>reject(a._id)}>Reject</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h2>All Admin Accounts</h2>
        {!allAdmins.length && <p>No admins found.</p>}
        {allAdmins.length > 0 && (
          <table className="table">
            <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Approved</th><th>Disabled</th></tr></thead>
            <tbody>
              {allAdmins.map((a) => (
                <tr key={a._id}>
                  <td>{a.username}</td>
                  <td>{a.email}</td>
                  <td>{a.role}</td>
                  <td>{a.adminApproved ? 'Yes' : 'No'}</td>
                  <td>{a.disabled ? 'Yes' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
