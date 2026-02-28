import React from 'react';
import { Link, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function UserLayout() {
  const { logout, user } = useAuth();
  const navigate = useNavigate();

  async function onLogout() {
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h2>VaultWire</h2>
        <nav>
          <Link to="/">Dashboard</Link>
          <Link to="/profile">Profile</Link>
          <Link to="/friends">Friends</Link>
          <Link to="/vault">Vault</Link>
          <Link to="/messages">Messages</Link>
          <Link to="/signatures">Signatures</Link>
          <Link to="/pki">My Certificate</Link>
          <Link to="/sessions">Sessions</Link>
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
