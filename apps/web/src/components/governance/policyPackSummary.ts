import type { PolicyPackGuardrailField as PolicyPackField, PolicyPackRules } from '@loose/shared';

export interface RuleLine {
  field: PolicyPackField;
  /** i18n key suffix under `policyPacks.fields`. */
  label: string;
  value: string;
}

const list = (items: readonly string[] | undefined, max = 4): string => {
  if (!items || items.length === 0) return '—';
  const shown = items.slice(0, max).join(', ');
  return items.length > max ? `${shown} (+${items.length - max})` : shown;
};

/** Human-readable one-liners for a pack's rules (the card body; the JSON stays in the editor). */
export function summarizeRules(rules: PolicyPackRules): RuleLine[] {
  const out: RuleLine[] = [];
  if (rules.allowedFilePatterns) {
    out.push({
      field: 'allowedFilePatterns',
      label: 'allowedFilePatterns',
      value: list(rules.allowedFilePatterns),
    });
  }
  if (rules.deniedFilePatterns) {
    out.push({
      field: 'deniedFilePatterns',
      label: 'deniedFilePatterns',
      value: list(rules.deniedFilePatterns),
    });
  }
  if (rules.commandPolicy) {
    const parts: string[] = [];
    if (rules.commandPolicy.allow) parts.push(`allow ${list(rules.commandPolicy.allow, 3)}`);
    if (rules.commandPolicy.deny) parts.push(`deny ${list(rules.commandPolicy.deny, 3)}`);
    out.push({ field: 'commandPolicy', label: 'commandPolicy', value: parts.join('; ') || '—' });
  }
  if (rules.approvalGates) {
    const on = (['dependencies', 'migrations', 'deletes'] as const).filter(
      (g) => rules.approvalGates?.[g] === true,
    );
    out.push({ field: 'approvalGates', label: 'approvalGates', value: on.join(', ') || '—' });
  }
  if (rules.networkAllowlist) {
    out.push({
      field: 'networkAllowlist',
      label: 'networkAllowlist',
      value: list(rules.networkAllowlist),
    });
  }
  if (rules.maxBudgetUsd !== undefined) {
    out.push({ field: 'maxBudgetUsd', label: 'maxBudgetUsd', value: `$${rules.maxBudgetUsd}` });
  }
  if (rules.maxSessionDurationMin !== undefined) {
    out.push({
      field: 'maxSessionDurationMin',
      label: 'maxSessionDurationMin',
      value: `${rules.maxSessionDurationMin} min`,
    });
  }
  if (rules.planMode) {
    out.push({ field: 'planMode', label: 'planMode', value: rules.planMode });
  }
  return out;
}
