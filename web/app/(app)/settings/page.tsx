"use client";

import { useEffect, useState } from "react";
import { KeyRound, Loader2, LogOut, Save, Shield } from "lucide-react";
import { toast } from "sonner";

import { Panel } from "@/components/panel";
import { StatusBadge } from "@/components/status-badge";
import {
  adminMe,
  deleteMappings,
  getMappings,
  getSettings,
  listSessions,
  loginAdmin,
  logoutAdmin,
  updateSettings
} from "@/lib/api";
import { getCookie } from "@/lib/session";
import type { AppSettings, MappingItem, Mode } from "@/lib/types";

const modeOptions: Mode[] = ["ml_based", "heuristic_based"];

export default function SettingsPage() {
  const [authenticated, setAuthenticated] = useState(false);
  const [password, setPassword] = useState("");
  const [csrfToken, setCsrfToken] = useState("");

  const [settings, setSettings] = useState<AppSettings>({
    risk_threshold: 0.6,
    default_mode: "ml_based",
    block_high_risk_output: true
  });

  const [sessions, setSessions] = useState<Array<{ session_id: string; event_count: number }>>([]);
  const [selectedSession, setSelectedSession] = useState("");
  const [mappings, setMappings] = useState<MappingItem[]>([]);

  const [loading, setLoading] = useState(false);

  async function loadProtectedData() {
    const [settingsPayload, sessionsPayload] = await Promise.all([getSettings(), listSessions()]);
    const normalizedMode: Mode =
      settingsPayload.settings.default_mode === "heuristic_based" ? "heuristic_based" : "ml_based";
    setSettings({
      ...settingsPayload.settings,
      default_mode: normalizedMode
    });
    setSessions(sessionsPayload);

    if (sessionsPayload.length > 0) {
      const defaultSession = sessionsPayload[0].session_id;
      setSelectedSession(defaultSession);
      const mapPayload = await getMappings(defaultSession, false);
      setMappings(mapPayload);
    }
  }

  useEffect(() => {
    async function bootstrap() {
      try {
        const auth = await adminMe();
        if (auth.authenticated) {
          setAuthenticated(true);
          setCsrfToken(getCookie("ps_csrf"));
          await loadProtectedData();
        }
      } catch {
        setAuthenticated(false);
      }
    }
    bootstrap();
  }, []);

  async function handleLogin() {
    if (!password.trim()) {
      toast.error("Enter admin password.");
      return;
    }
    setLoading(true);
    try {
      const payload = await loginAdmin(password);
      if (!payload.authenticated) {
        toast.error("Invalid admin password");
        return;
      }
      setAuthenticated(true);
      const token = payload.csrf_token || getCookie("ps_csrf");
      setCsrfToken(token);
      await loadProtectedData();
      toast.success("Admin session started");
      setPassword("");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    setLoading(true);
    try {
      await logoutAdmin();
      setAuthenticated(false);
      setCsrfToken("");
      setMappings([]);
      setSessions([]);
      toast.success("Logged out");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Logout failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleSaveSettings() {
    setLoading(true);
    try {
      const token = csrfToken || getCookie("ps_csrf");
      if (!token) {
        throw new Error("CSRF token missing. Log in again.");
      }
      const payload = await updateSettings(settings, token);
      setSettings(payload.settings);
      toast.success("Settings updated");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save settings");
    } finally {
      setLoading(false);
    }
  }

  async function handleLoadMappings(sessionId: string) {
    setSelectedSession(sessionId);
    try {
      const payload = await getMappings(sessionId, false);
      setMappings(payload);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Unable to load mappings");
    }
  }

  async function handleDeleteMappings() {
    if (!selectedSession) {
      toast.error("Select a session first");
      return;
    }
    setLoading(true);
    try {
      const token = csrfToken || getCookie("ps_csrf");
      if (!token) {
        throw new Error("CSRF token missing. Log in again.");
      }
      await deleteMappings(selectedSession, token);
      setMappings([]);
      toast.success("Session mappings deleted");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete mappings");
    } finally {
      setLoading(false);
    }
  }

  if (!authenticated) {
    return (
      <Panel title="Admin Login" subtitle="Required to manage settings and mapping review">
        <div className="max-w-lg space-y-3">
          <div className="rounded-xl border border-amberline/30 bg-amberline/10 p-3 text-sm text-white/80">
            This view is password-protected and uses signed cookies with CSRF checks.
          </div>
          <input
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            type="password"
            placeholder="Admin password"
            className="w-full rounded-xl border border-white/15 bg-ink/70 px-3 py-2 text-sm text-white outline-none"
          />
          <button
            type="button"
            disabled={loading}
            onClick={handleLogin}
            className="inline-flex items-center gap-2 rounded-xl bg-skyline px-4 py-2 text-sm font-medium text-ink disabled:opacity-70"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
            Login as admin
          </button>
        </div>
      </Panel>
    );
  }

  return (
    <div className="space-y-6">
      <Panel
        title="Security Settings"
        subtitle="Runtime controls for output blocking and default shielding mode"
        rightSlot={<StatusBadge value="Admin authenticated" tone="good" />}
      >
        <div className="grid gap-4 md:grid-cols-2">
          <label className="space-y-2 text-sm text-white/80">
            <span>Risk threshold ({settings.risk_threshold.toFixed(2)})</span>
            <input
              type="range"
              min="0.1"
              max="1"
              step="0.05"
              value={settings.risk_threshold}
              onChange={(event) =>
                setSettings((prev) => ({
                  ...prev,
                  risk_threshold: Number(event.target.value)
                }))
              }
              className="w-full"
            />
          </label>

          <label className="space-y-2 text-sm text-white/80">
            <span>Default mode</span>
            <select
              value={settings.default_mode}
              onChange={(event) =>
                setSettings((prev) => ({
                  ...prev,
                  default_mode: event.target.value as Mode
                }))
              }
              className="w-full rounded-xl border border-white/15 bg-ink/70 px-3 py-2 text-sm"
            >
              {modeOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
        </div>

        <label className="mt-4 inline-flex items-center gap-2 text-sm text-white/80">
          <input
            type="checkbox"
            checked={settings.block_high_risk_output}
            onChange={(event) =>
              setSettings((prev) => ({
                ...prev,
                block_high_risk_output: event.target.checked
              }))
            }
          />
          Block high-risk model output
        </label>

        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={loading}
            onClick={handleSaveSettings}
            className="inline-flex items-center gap-2 rounded-xl bg-pulse px-4 py-2 text-sm font-medium text-ink disabled:opacity-70"
          >
            <Save className="h-4 w-4" />
            Save settings
          </button>

          <button
            type="button"
            disabled={loading}
            onClick={handleLogout}
            className="inline-flex items-center gap-2 rounded-xl border border-white/20 bg-white/5 px-4 py-2 text-sm text-white/85 disabled:opacity-70"
          >
            <LogOut className="h-4 w-4" />
            Logout
          </button>
        </div>
      </Panel>

      <Panel title="Session Mapping Review" subtitle="Encrypted mappings are visible here in masked form only">
        <div className="mb-3 flex flex-wrap gap-2">
          <select
            value={selectedSession}
            onChange={(event) => handleLoadMappings(event.target.value)}
            className="rounded-lg border border-white/15 bg-ink/70 px-3 py-2 text-sm text-white"
          >
            <option value="">Select a session</option>
            {sessions.map((item) => (
              <option key={item.session_id} value={item.session_id}>
                {item.session_id.slice(0, 14)}... ({item.event_count} events)
              </option>
            ))}
          </select>

          <button
            type="button"
            disabled={loading || !selectedSession}
            onClick={handleDeleteMappings}
            className="rounded-lg border border-rose-400/40 bg-rose-400/10 px-3 py-2 text-xs text-rose-200"
          >
            Delete mappings for selected session
          </button>
        </div>

        {mappings.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.02] p-4 text-sm text-white/60">
            No mappings found for this session.
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-white/10">
            <table className="w-full text-sm">
              <thead className="bg-white/5 text-left text-xs uppercase tracking-[0.12em] text-white/60">
                <tr>
                  <th className="px-3 py-2">Placeholder</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Masked Preview</th>
                </tr>
              </thead>
              <tbody>
                {mappings.map((mapping) => (
                  <tr key={mapping.id} className="border-t border-white/10 text-white/85">
                    <td className="px-3 py-2 text-skyline">{mapping.placeholder}</td>
                    <td className="px-3 py-2">{mapping.entity_type}</td>
                    <td className="px-3 py-2 text-white/70">{mapping.masked_preview}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <div className="rounded-xl border border-skyline/25 bg-skyline/10 p-4 text-sm text-white/80">
        <p className="inline-flex items-center gap-2 text-skyline">
          <Shield className="h-4 w-4" />
          Security model
        </p>
        <p className="mt-2 text-white/70">
          Raw values are encrypted at rest and never written into audit logs. Admin actions require signed session cookie and CSRF token.
        </p>
      </div>
    </div>
  );
}
