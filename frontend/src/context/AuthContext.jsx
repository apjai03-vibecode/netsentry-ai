import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('netsentry_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem('netsentry_token');
      if (storedToken) {
        try {
          const res = await api.get('/auth/me');
          setUser(res.data);
        } catch (err) {
          console.warn('Session expired or invalid token', err);
          localStorage.removeItem('netsentry_token');
          setToken(null);
          setUser(null);
        }
      }
      setLoading(false);
    };

    initAuth();
  }, []);

  const login = async (username, password) => {
    const res = await api.post('/auth/login/json', { username, password });
    const { access_token } = res.data;
    localStorage.setItem('netsentry_token', access_token);
    setToken(access_token);

    const userRes = await api.get('/auth/me', {
      headers: { Authorization: Bearer  },
    });
    setUser(userRes.data);
    return userRes.data;
  };

  const register = async (userData) => {
    await api.post('/auth/register', userData);
    return await login(userData.username, userData.password);
  };

  const logout = () => {
    localStorage.removeItem('netsentry_token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
