import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export function ProtectedRoute({ children, role }) {
  const { user } = useAuth();
  const location = useLocation();
  if (!user) return <Navigate to={location.pathname.startsWith('/admin') ? '/admin/login' : '/login'} replace />;

  if (role) {
    const required = Array.isArray(role) ? role : [role];
    const expanded = new Set(required);
    if (expanded.has('admin')) expanded.add('superadmin');
    if (!expanded.has(user.role)) {
      return <Navigate to={['admin', 'superadmin'].includes(user.role) ? '/admin' : '/'} replace />;
    }
  }
  return children;
}
