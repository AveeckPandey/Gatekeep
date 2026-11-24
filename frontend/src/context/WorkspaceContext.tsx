"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { api, Workspace } from "@/lib/api";
import { useAuth } from "./AuthContext";

interface WorkspaceContextType {
  workspaces: Workspace[];
  activeWorkspace: Workspace | null;
  isLoading: boolean;
  setActiveWorkspace: (ws: Workspace) => void;
  createWorkspace: (name: string) => Promise<Workspace>;
  refreshWorkspaces: () => Promise<void>;
}

const WorkspaceContext = createContext<WorkspaceContextType | undefined>(undefined);

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const { token } = useAuth();
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [activeWorkspace, setActiveWorkspaceState] = useState<Workspace | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const fetchWorkspaces = useCallback(async () => {
    if (!token) {
      setWorkspaces([]);
      setActiveWorkspaceState(null);
      setIsLoading(false);
      return;
    }

    try {
      setIsLoading(true);
      const list = await api.listWorkspaces(token);
      setWorkspaces(list);

      if (list.length > 0) {
        const savedWsId = localStorage.getItem("gatekeep_active_ws");
        const found = list.find((w) => w.id === savedWsId);
        if (found) {
          setActiveWorkspaceState(found);
        } else {
          setActiveWorkspaceState(list[0]);
          localStorage.setItem("gatekeep_active_ws", list[0].id);
        }
      } else {
        const initialWs = await api.createWorkspace(token, "Default Security Workspace");
        setWorkspaces([initialWs]);
        setActiveWorkspaceState(initialWs);
        localStorage.setItem("gatekeep_active_ws", initialWs.id);
      }
    } catch (err: unknown) {
      console.error("Failed to fetch workspaces:", err);
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    let isMounted = true;
    if (!token) return;

    api
      .listWorkspaces(token)
      .then((list) => {
        if (!isMounted) return;
        setWorkspaces(list);
        if (list.length > 0) {
          const savedWsId = localStorage.getItem("gatekeep_active_ws");
          const found = list.find((w) => w.id === savedWsId);
          if (found) {
            setActiveWorkspaceState(found);
          } else {
            setActiveWorkspaceState(list[0]);
            localStorage.setItem("gatekeep_active_ws", list[0].id);
          }
        } else {
          api.createWorkspace(token, "Default Security Workspace").then((initialWs) => {
            if (!isMounted) return;
            setWorkspaces([initialWs]);
            setActiveWorkspaceState(initialWs);
            localStorage.setItem("gatekeep_active_ws", initialWs.id);
          });
        }
      })
      .catch((err: unknown) => {
        console.error("Failed to fetch workspaces:", err);
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [token]);

  const setActiveWorkspace = (ws: Workspace) => {
    setActiveWorkspaceState(ws);
    localStorage.setItem("gatekeep_active_ws", ws.id);
  };

  const createWorkspace = async (name: string): Promise<Workspace> => {
    if (!token) throw new Error("Unauthenticated");
    const newWs = await api.createWorkspace(token, name);
    setWorkspaces((prev) => [...prev, newWs]);
    setActiveWorkspace(newWs);
    return newWs;
  };

  return (
    <WorkspaceContext.Provider
      value={{
        workspaces,
        activeWorkspace,
        isLoading,
        setActiveWorkspace,
        createWorkspace,
        refreshWorkspaces: fetchWorkspaces,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace() {
  const context = useContext(WorkspaceContext);
  if (!context) {
    throw new Error("useWorkspace must be used within a WorkspaceProvider");
  }
  return context;
}
