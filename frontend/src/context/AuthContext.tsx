"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, User } from "@/lib/api";

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  login: (email: string, pass: string) => Promise<void>;
  register: (email: string, pass: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem("gatekeep_token");
    }
    return null;
  });
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(() => {
    if (typeof window !== "undefined") {
      return Boolean(localStorage.getItem("gatekeep_token"));
    }
    return false;
  });
  const router = useRouter();

  useEffect(() => {
    let isMounted = true;
    if (!token) return;

    api
      .getMe(token)
      .then((fetchedUser) => {
        if (isMounted) {
          setUser(fetchedUser);
        }
      })
      .catch(() => {
        if (isMounted) {
          localStorage.removeItem("gatekeep_token");
          setToken(null);
          setUser(null);
        }
      })
      .finally(() => {
        if (isMounted) {
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [token]);

  const login = async (email: string, pass: string) => {
    setIsLoading(true);
    try {
      const resp = await api.login(email, pass);
      localStorage.setItem("gatekeep_token", resp.access_token);
      document.cookie = `gatekeep_token=${resp.access_token}; path=/; max-age=86400; SameSite=Lax`;
      setToken(resp.access_token);
      setUser(resp.user);
      router.push("/dashboard");
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (email: string, pass: string) => {
    setIsLoading(true);
    try {
      const resp = await api.register(email, pass);
      localStorage.setItem("gatekeep_token", resp.access_token);
      document.cookie = `gatekeep_token=${resp.access_token}; path=/; max-age=86400; SameSite=Lax`;
      setToken(resp.access_token);
      setUser(resp.user);
      router.push("/dashboard");
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem("gatekeep_token");
    localStorage.removeItem("gatekeep_active_ws");
    document.cookie = "gatekeep_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    setToken(null);
    setUser(null);
    router.push("/login");
  };

  return (
    <AuthContext.Provider value={{ user, token, isLoading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
