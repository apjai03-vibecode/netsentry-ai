import React from 'react';
import { ShieldCheck, ShieldAlert, Cpu, BookOpen, LogOut, User, Activity, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Navbar({ activeTab, setActiveTab, onOpenAuth, findingsCount = 3 }) {
  const { user, logout } = useAuth();

  return (
    <header className="sticky top-0 z-40 bg-white/90 backdrop-blur-md border-b border-slate-200/90 shadow-[0_1px_3px_rgba(0,0,0,0.03)]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          
          {/* Logo & Product Badge */}
          <div className="flex items-center gap-4">
            <div 
              className="flex items-center gap-2.5 cursor-pointer group" 
              onClick={() => setActiveTab('audit')}
            >
              <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-xs group-hover:bg-indigo-600 transition-colors">
                <ShieldCheck className="w-4.5 h-4.5" />
              </div>
              <div className="flex items-baseline gap-1.5">
                <span className="text-sm font-bold tracking-tight text-slate-900 font-mono">
                  NetSentry<span className="text-indigo-600 font-sans font-extrabold">.ai</span>
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200/70 font-semibold">
                  v1.0
                </span>
              </div>
            </div>

            <div className="hidden lg:flex items-center gap-2 pl-3 border-l border-slate-200 text-xs">
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] font-medium bg-slate-50 text-slate-600 rounded-md border border-slate-200/80">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                SIH26160 • Code Craft
              </span>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono text-emerald-700 bg-emerald-50/80 rounded border border-emerald-200/60">
                <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                RFC 8247 Engine Active
              </span>
            </div>
          </div>

          {/* Segmented Workspace Navigation Tabs */}
          <nav className="flex items-center p-0.5 bg-slate-100/90 rounded-lg border border-slate-200/70 text-xs">
            <button
              onClick={() => setActiveTab('audit')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all cursor-pointer ${
                activeTab === 'audit'
                  ? 'bg-white text-slate-900 shadow-xs border border-slate-200/80 font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-indigo-600" />
              <span>Audit Console</span>
              {findingsCount > 0 && (
                <span className="ml-0.5 px-1.5 py-0.2 text-[10px] font-mono font-bold bg-rose-100 text-rose-700 rounded-full">
                  {findingsCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('ml')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all cursor-pointer ${
                activeTab === 'ml'
                  ? 'bg-white text-slate-900 shadow-xs border border-slate-200/80 font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <Cpu className="w-3.5 h-3.5 text-indigo-600" />
              <span>ML & SHAP Hub</span>
              <span className="ml-0.5 px-1.5 py-0.2 text-[10px] font-mono font-bold bg-emerald-100 text-emerald-700 rounded-full">
                100%
              </span>
            </button>

            <button
              onClick={() => setActiveTab('rules')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all cursor-pointer ${
                activeTab === 'rules'
                  ? 'bg-white text-slate-900 shadow-xs border border-slate-200/80 font-semibold'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5 text-indigo-600" />
              <span>RFC Standards</span>
            </button>
          </nav>

          {/* User Account / Session Profile */}
          <div className="flex items-center gap-3">
            {user ? (
              <div className="flex items-center gap-2.5">
                <div className="hidden sm:flex flex-col items-end leading-tight">
                  <span className="text-xs font-semibold text-slate-800 font-mono">{user.username}</span>
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                    role:{user.role}
                  </span>
                </div>
                <div className="w-7 h-7 rounded-md bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 font-semibold text-xs font-mono">
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <button
                  onClick={logout}
                  title="Sign Out"
                  className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-md transition-colors cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={onOpenAuth}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium rounded-md shadow-xs transition-colors cursor-pointer"
              >
                <User className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </button>
            )}
          </div>

        </div>
      </div>
    </header>
  );
}

