import React, { createContext, useContext, useMemo, useState, useEffect } from 'react';
import { api, setAccessToken, setUnauthorizedHandler } from '../lib/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);

  async function login(email, password) {
    const { data } = await api.post('/auth/login', { email, password });
    setToken(data.accessToken);
    setAccessToken(data.accessToken);
    setUser(data.user);
    return data.user;
  }

  async function logout() {
    try { await api.post('/auth/logout'); } catch {}
    setUser(null);
    setToken(null);
    setAccessToken(null);
  }

  async function bootstrapAdmin(payload) {
    return api.post('/auth/admin/bootstrap', payload);
  }

  async function refreshMe() {
    try {
      const { data } = await api.post('/auth/refresh');
      setToken(data.accessToken);
      setAccessToken(data.accessToken);
      setUser(data.user);
      return data.user;
    } catch {
      setUser(null);
      setToken(null);
      setAccessToken(null);
      return null;
    }
  }

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      setToken(null);
      setAccessToken(null);
    });
    refreshMe();
  }, []);

  const value = useMemo(() => ({
    user, token, login, logout, bootstrapAdmin, refreshMe, setUser
  }), [user, token]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
export function useAuth() { return useContext(AuthContext); }
