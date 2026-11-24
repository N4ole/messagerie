import { createContext, useContext } from "react";
import type { Backend } from "./backend";

export const BackendContext = createContext<Backend | null>(null);

export function useBackend(): Backend {
  const b = useContext(BackendContext);
  if (!b) throw new Error("BackendContext manquant");
  return b;
}
