import React from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export default function ThemeToggle({ variant = 'icon' }) {
  const { theme, resolvedTheme, toggleTheme, setTheme } = useTheme();

  if (variant === 'segmented') {
    return (
      <div className="inline-flex items-center p-0.5 rounded-[7px] bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs font-mono">
        <button
          onClick={() => setTheme('light')}
          title="Enterprise Light Theme"
          className={`px-2 py-1 rounded-[5px] flex items-center gap-1.5 transition-all cursor-pointer ${
            theme === 'light'
              ? 'bg-white dark:bg-slate-700 text-[#0F172A] dark:text-white font-bold shadow-2xs'
              : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          <Sun className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Light</span>
        </button>

        <button
          onClick={() => setTheme('dark')}
          title="SOC Night Ops Dark Theme"
          className={`px-2 py-1 rounded-[5px] flex items-center gap-1.5 transition-all cursor-pointer ${
            theme === 'dark'
              ? 'bg-white dark:bg-slate-700 text-[#0F172A] dark:text-white font-bold shadow-2xs'
              : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          <Moon className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">Dark Ops</span>
        </button>

        <button
          onClick={() => setTheme('system')}
          title="Sync with System OS"
          className={`px-2 py-1 rounded-[5px] flex items-center gap-1.5 transition-all cursor-pointer ${
            theme === 'system'
              ? 'bg-white dark:bg-slate-700 text-[#0F172A] dark:text-white font-bold shadow-2xs'
              : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-200'
          }`}
        >
          <Monitor className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">System</span>
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={toggleTheme}
      title={`Switch to ${resolvedTheme === 'dark' ? 'Enterprise Light' : 'SOC Night Ops'} Theme`}
      className="p-1.5 rounded-[7px] text-[#64748B] hover:text-[#0F172A] dark:text-slate-400 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 border border-[#E2E8F0] dark:border-slate-800 transition-colors cursor-pointer"
      aria-label="Toggle Theme"
    >
      {resolvedTheme === 'dark' ? (
        <Sun className="w-4 h-4 text-amber-400" />
      ) : (
        <Moon className="w-4 h-4 text-slate-600" />
      )}
    </button>
  );
}
