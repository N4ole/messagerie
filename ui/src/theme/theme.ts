import { useCallback, useEffect, useState } from "react";

export type ThemePref = "system" | "light" | "dark";
const KEY = "messagerie.theme";

function readPref(): ThemePref {
  try {
    const v = window.localStorage.getItem(KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    /* stockage indisponible : préférence par défaut */
  }
  return "system";
}

/** Applique `data-theme` sur <html> (les couleurs sont des variables CSS). */
export function applyTheme(pref: ThemePref): void {
  const root = document.documentElement;
  if (pref === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", pref);
}

export function useTheme(): [ThemePref, () => void] {
  const [pref, setPref] = useState<ThemePref>(readPref);
  useEffect(() => {
    applyTheme(pref);
    try {
      window.localStorage.setItem(KEY, pref);
    } catch {
      /* ignoré */
    }
  }, [pref]);
  const cycle = useCallback(() => {
    setPref((p) => (p === "system" ? "light" : p === "light" ? "dark" : "system"));
  }, []);
  return [pref, cycle];
}

export const themeLabel: Record<ThemePref, string> = {
  system: "Thème : système",
  light: "Thème : clair",
  dark: "Thème : sombre",
};
