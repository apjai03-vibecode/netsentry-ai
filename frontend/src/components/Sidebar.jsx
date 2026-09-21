import React from 'react';
import { 
  ShieldCheck, 
  LayoutDashboard, 
  FileSearch, 
  UploadCloud, 
  ShieldAlert, 
  Cpu, 
  BookOpen, 
  FileText, 
  Settings, 
  LogOut, 
  User, 
  X,
  Terminal
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import ThemeToggle from './ThemeToggle';

export default function Sidebar({ 
  activeTab, 
  setActiveTab, 
  onOpenAuth, 
  findingsCount = 0,
  isMobileOpen = false,
  onCloseMobile = () => {}
}) {
  const { user, logout } = useAuth();

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'audit', label: 'Audits', icon: FileSearch, count: findingsCount > 0 ? findingsCount : null, countColor: 'bg-rose-100 text-[#DC2626] dark:bg-rose-950/60 dark:text-rose-400' },
    { id: 'captures', label: 'Captures', icon: UploadCloud },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'ml', label: 'ML Intelligence', icon: Cpu, badge: 'XGBoost' },
    { id: 'rules', label: 'RFC Library', icon: BookOpen },
    { id: 'remediation', label: 'Remediation Diffs', icon: Terminal },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div 
          onClick={onCloseMobile}
          className="fixed inset-0 bg-slate-900/50 backdrop-blur-xs z-40 lg:hidden"
        />
      )}

      <aside className={`
        fixed lg:sticky top-0 inset-y-0 left-0 z-50 w-64 bg-white dark:bg-[#111827] border-r border-[#E2E8F0] dark:border-slate-800 
        flex flex-col shrink-0 h-screen select-none transition-all duration-200 ease-in-out
        ${isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        
        {/* Brand & Logo Header */}
        <div className="h-14 px-5 flex items-center justify-between border-b border-[#E2E8F0] dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-[7px] bg-[#0F172A] dark:bg-slate-800 flex items-center justify-center text-white shadow-xs">
              <ShieldCheck className="w-4.5 h-4.5 text-indigo-400" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-1.5">
                <span className="text-sm font-bold font-mono tracking-tight text-[#0F172A] dark:text-white">
                  NetSentry<span className="text-[#4F46E5] dark:text-indigo-400 font-sans font-extrabold">.ai</span>
                </span>
                <span className="text-[9px] font-mono px-1 py-0.2 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 rounded-[4px] border border-slate-200 dark:border-slate-700 font-semibold">
                  SOC
                </span>
              </div>
              <span className="text-[10px] text-[#64748B] dark:text-slate-400 font-mono leading-none">
                IPsec Protocol Analyzer
              </span>
            </div>
          </div>

          {/* Close button for mobile */}
          <button
            onClick={onCloseMobile}
            className="p-1 rounded-[6px] text-slate-400 hover:text-slate-700 dark:hover:text-white lg:hidden cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Main Navigation Links */}
        <div className="flex-1 py-3 px-3 space-y-0.5 overflow-y-auto">
          <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-[#64748B] dark:text-slate-400 font-semibold">
            Security Operations
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id || (activeTab === 'audit' && item.id === 'dashboard');

            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveTab(item.id === 'dashboard' ? 'audit' : item.id);
                  onCloseMobile();
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-[7px] text-xs font-medium transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-slate-100 dark:bg-slate-800 text-[#0F172A] dark:text-white font-semibold border border-slate-200/80 dark:border-slate-700'
                    : 'text-[#64748B] dark:text-slate-400 hover:text-[#0F172A] dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-[#4F46E5] dark:text-indigo-400' : 'text-slate-400 dark:text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>

                {item.count !== null && item.count !== undefined && (
                  <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded-full ${item.countColor}`}>
                    {item.count}
                  </span>
                )}

                {item.badge && (
                  <span className="text-[9px] font-mono text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 px-1 py-0.2 rounded border border-slate-200 dark:border-slate-700">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Engine Status & System Telemetry Footer */}
        <div className="p-3 border-t border-[#E2E8F0] dark:border-slate-800 space-y-2 bg-[#F6F8FB]/50 dark:bg-[#0B0F19]/40">
          
          {/* Theme Selector Strip */}
          <div className="flex items-center justify-between px-1">
            <span className="text-[10px] font-mono uppercase text-[#64748B] dark:text-slate-400 font-semibold">
              Theme
            </span>
            <ThemeToggle variant="segmented" />
          </div>

          {/* Engine Telemetry Pill */}
          <div className="p-2 rounded-[7px] bg-white dark:bg-[#161E2E] border border-[#E2E8F0] dark:border-slate-800 text-[11px] font-mono transition-colors">
            <div className="flex items-center justify-between">
              <span className="text-[#64748B] dark:text-slate-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#059669] animate-pulse" />
                Engine Online
              </span>
              <span className="text-[#0F172A] dark:text-white font-bold">Port 8000</span>
            </div>
            <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 flex items-center justify-between">
              <span>RFC 8247 Enforcer</span>
              <span className="text-[#059669] dark:text-emerald-400">Active</span>
            </div>
          </div>

          {/* User Account / Profile Strip */}
          <div className="pt-1 flex items-center justify-between">
            {user ? (
              <div className="flex items-center justify-between w-full">
                <div className="flex items-center gap-2 min-w-0">
                  <div className="w-7 h-7 rounded-[6px] bg-[#0F172A] dark:bg-slate-800 text-white flex items-center justify-center text-xs font-mono font-bold shrink-0">
                    {user.username.charAt(0).toUpperCase()}
                  </div>
                  <div className="truncate">
                    <span className="text-xs font-semibold text-[#0F172A] dark:text-white font-mono block leading-tight truncate">
                      {user.username}
                    </span>
                    <span className="text-[10px] text-[#64748B] dark:text-slate-400 uppercase font-mono block">
                      {user.role}
                    </span>
                  </div>
                </div>
                <button
                  onClick={logout}
                  title="Sign Out"
                  className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50 rounded-[6px] transition-colors cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={onOpenAuth}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 px-3 bg-[#0F172A] dark:bg-indigo-600 hover:bg-slate-800 dark:hover:bg-indigo-500 text-white rounded-[7px] text-xs font-medium shadow-xs transition-colors cursor-pointer"
              >
                <User className="w-3.5 h-3.5" />
                <span>Sign In Console</span>
              </button>
            )}
          </div>

        </div>

      </aside>
    </>
  );
}
