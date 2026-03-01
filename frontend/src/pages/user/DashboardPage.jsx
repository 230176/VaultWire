import React from 'react';

export default function DashboardPage() {
  return (
    <div>
      <h1>User Dashboard</h1>
      <div className="grid">
        <div className="card">Welcome to VaultWire user portal.</div>
        <div className="card">Modules: Vault, Messaging, Signatures, PKI, Profile, Sessions.</div>
      </div>
    </div>
  );
}
