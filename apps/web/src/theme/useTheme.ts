import { useEffect } from 'react';

export type Theme = 'light';

export function useTheme(): { theme: Theme } {
  useEffect(() => {
    document.documentElement.removeAttribute('data-theme');
    try {
      localStorage.removeItem('jawaker.theme');
    } catch {
      // ignore
    }
  }, []);

  return { theme: 'light' };
}
