import React from 'react';
import { Link, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function AdminLayout() {
  const { logout, user } = useAuth();
  const navigate = useNavigate();
  async function onLogout() {
    await logout();
    navigate('/admin/login', { replace: true });
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h2>VaultWire Admin</h2>
        <nav>
          <Link to="/admin">Risk Dashboard</Link>
          <Link to="/admin/pki">CA & Certs</Link>
          <Link to="/admin/users">Users</Link>
          <Link to="/admin/audit">Audit Logs</Link>
          <Link to="/admin/rate-limits">Rate Limits</Link>
          {user?.role === 'superadmin' && <Link to="/admin/verify-admins">Verify Registrations</Link>}
        </nav>
        <div className="sidebar-footer">
          <small>{user?.email}</small>
          <button onClick={onLogout}>Logout</button>
        </div>
      </aside>
      <main className="content"><Outlet /></main>
    </div>
  );
}
