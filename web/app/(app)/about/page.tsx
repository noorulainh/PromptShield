import { Panel } from "@/components/panel";

export default function AboutPage() {
  return (
    <div className="space-y-6">
      <Panel title="About PromptShield" subtitle="Methodology and capstone novelty">
        <p className="text-sm leading-7 text-white/80">
          PromptShield is a runtime privacy layer between users and GenAI systems. It performs multilingual sensitive-entity detection,
          session-consistent pseudonymization, output-side leakage filtering, and secure audit logging without persisting raw PII.
        </p>
      </Panel>

      <section className="grid gap-6 lg:grid-cols-2">
        <Panel title="Multilingual Detection" subtitle="English + Urdu + Roman Urdu">
          <ul className="space-y-2 text-sm text-white/80">
            <li>Hybrid engine combining regex rules, locale-aware heuristics, and obfuscation handling.</li>
            <li>Pakistani context patterns for CNIC, PK IBAN, NTN, local phone numbers, and contextual address detection.</li>
            <li>Prompt injection phrase detection across English and Urdu variants.</li>
          </ul>
        </Panel>

        <Panel title="Conversation Consistency" subtitle="Deterministic placeholders by session">
          <ul className="space-y-2 text-sm text-white/80">
            <li>Stable pseudonyms such as [PERSON_1] and [PHONE_1] persist across chat turns.</li>
            <li>Mappings are reversible in protected admin view and encrypted at rest.</li>
            <li>No plain mappings are exposed through public endpoints or audit exports.</li>
          </ul>
        </Panel>

        <Panel title="Adversarial Exfiltration Lab" subtitle="Injection and extraction stress testing">
          <ul className="space-y-2 text-sm text-white/80">
            <li>Dataset-driven attacks: spaced digits, mixed scripts, Roman Urdu, and leetspeak obfuscation.</li>
            <li>Leakage-rate measurement and pass/fail scoring per attack case.</li>
            <li>Reproducible evaluation flow suitable for capstone demonstration.</li>
          </ul>
        </Panel>

        <Panel title="Privacy-Utility Tradeoff" subtitle="Measurable operational metrics">
          <ul className="space-y-2 text-sm text-white/80">
            <li>Precision, recall, F1, false positive rate, leakage rate, and utility scoring.</li>
            <li>Latency captured with average, p50, and p95 performance indicators.</li>
            <li>Direct comparison between ML-based shielding and heuristic-only shielding.</li>
          </ul>
        </Panel>
      </section>

      <Panel title="Secure Logging Design" subtitle="Auditability without sensitive retention">
        <p className="text-sm leading-7 text-white/80">
          PromptShield logs only safe metadata: event type, risk score, latency, and sanitized summaries. Raw prompts, raw outputs,
          and raw entity values are not persisted in logs. Mapping records are encrypted and accessible only via admin-protected endpoints.
        </p>
      </Panel>
    </div>
  );
}
