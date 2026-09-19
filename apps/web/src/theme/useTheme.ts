import { useCallback, useEffect, useState } from 'react';

/**
 * Theme preference persisted in localStorage. Values:
 *  - 'light' / 'dark': explicit override via <html data-theme>;
 *  - 'system' (default): follow the OS preference (CSS media query).
 *
 * Persistence uses localStorage — acceptable for a presentation preference,
 * never for credentials or tokens (SECURITY.md s8).
 */

export type Theme = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'jawaker.theme';

function readStoredTheme(): Theme {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    if (value === 'light' || value === 'dark' || value === 'system') {
      return value;
    }
  } catch {
    // Storage unavailable (private mode etc.): fall through to system.
  }
  return 'system';
}

function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === 'system') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', theme);
  }
}

export function useTheme(): { theme: Theme; setTheme: (theme: Theme) => void; cycle: () => void } {
  const [theme, setThemeState] = useState<Theme>(readStoredTheme);

  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Non-fatal: theme still applies for this session.
    }
  }, [theme]);

  const setTheme = useCallback((next: Theme) => setThemeState(next), []);
  const cycle = useCallback(
    () =>
      setThemeState((current) =>
        current === 'system' ? 'light' : current === 'light' ? 'dark' : 'system',
      ),
    [],
  );

  return { theme, setTheme, cycle };
}
