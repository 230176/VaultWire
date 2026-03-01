import React, { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ProtectedRoute } from './components/ProtectedRoute';
import UserLayout from './layouts/UserLayout';
import AdminLayout from './layouts/AdminLayout';
import { connectSocket, getSocket } from './lib/socket';

import LoginPage from './pages/auth/LoginPage';
import RegisterPage from './pages/auth/RegisterPage';
import OtpPage from './pages/auth/OtpPage';
import AdminLoginPage from './pages/admin/AdminLoginPage';
import AdminRegisterPage from './pages/admin/AdminRegisterPage';
import AdminVerifyAdminsPage from './pages/admin/AdminVerifyAdminsPage';

import DashboardPage from './pages/user/DashboardPage';
import ProfilePage from './pages/user/ProfilePage';
import FriendsPage from './pages/user/FriendsPage';
import VaultPage from './pages/user/VaultPage';
import MessagesPage from './pages/user/MessagesPage';
import SignaturesPage from './pages/user/SignaturesPage';
import MyCertPage from './pages/user/MyCertPage';
import SessionsPage from './pages/user/SessionsPage';

import AdminDashboardPage from './pages/admin/AdminDashboardPage';
import AdminPkiPage from './pages/admin/AdminPkiPage';
import AdminUsersPage from './pages/admin/AdminUsersPage';
import AdminAuditPage from './pages/admin/AdminAuditPage';
import AdminRateLimitsPage from './pages/admin/AdminRateLimitsPage';

function AppInner() {
  const { user, token } = useAuth();

  useEffect(() => {
    if (user && token) {
      const s = connectSocket(token);
      s.on('connect_error', () => {});
      s.on('friend:request', () => {});
      s.on('friend:updated', () => {});
      s.on('message:new', () => {});
      return () => {
        const sock = getSocket();
        if (sock) sock.disconnect();
      };
    }
  }, [user, token]);

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/otp" element={<OtpPage />} />

      <Route path="/admin/login" element={<AdminLoginPage />} />
      <Route path="/admin/register" element={<AdminRegisterPage />} />

      <Route path="/" element={<ProtectedRoute role="user"><UserLayout /></ProtectedRoute>}>
        <Route index element={<DashboardPage />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="friends" element={<FriendsPage />} />
        <Route path="vault" element={<VaultPage />} />
        <Route path="messages" element={<MessagesPage />} />
        <Route path="signatures" element={<SignaturesPage />} />
        <Route path="pki" element={<MyCertPage />} />
        <Route path="sessions" element={<SessionsPage />} />
      </Route>

      <Route path="/admin" element={<ProtectedRoute role="admin"><AdminLayout /></ProtectedRoute>}>
        <Route index element={<AdminDashboardPage />} />
        <Route path="pki" element={<AdminPkiPage />} />
        <Route path="users" element={<AdminUsersPage />} />
        <Route path="audit" element={<AdminAuditPage />} />
        <Route path="rate-limits" element={<AdminRateLimitsPage />} />
        <Route path="verify-admins" element={<ProtectedRoute role="superadmin"><AdminVerifyAdminsPage /></ProtectedRoute>} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  );
}
