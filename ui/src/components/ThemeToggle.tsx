import { themeLabel, useTheme } from "../theme/theme";

export function ThemeToggle() {
  const [pref, cycle] = useTheme();
  return (
    <button type="button" className="ghost" onClick={cycle} aria-label={`${themeLabel[pref]} (changer)`}>
      {pref === "dark" ? "☾" : pref === "light" ? "☀" : "◐"} <span className="sr-only">{themeLabel[pref]}</span>
    </button>
  );
}
