import { AlertTriangle, CheckCircle2, Lock } from 'lucide-react';

interface ConsentFormProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
}

export function ConsentForm({ checked, onChange }: ConsentFormProps) {
  return (
    <label
      className="block cursor-pointer rounded-[20px] border p-5 transition-colors"
      style={{
        borderColor: checked ? 'rgba(73,210,140,0.3)' : 'rgba(255,180,84,0.22)',
        background: checked ? 'rgba(73,210,140,0.08)' : 'rgba(255,180,84,0.06)',
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="sr-only"
      />

      <div className="flex items-start gap-4">
        <div
          className="mt-0.5 flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl"
          style={{ background: checked ? 'rgba(73,210,140,0.12)' : 'rgba(255,180,84,0.12)' }}
        >
          {checked ? (
            <CheckCircle2 size={18} style={{ color: 'var(--success)' }} />
          ) : (
            <Lock size={18} style={{ color: 'var(--warning)' }} />
          )}
        </div>

        <div className="flex-1">
          <div className="section-title">
            <AlertTriangle size={16} style={{ color: checked ? 'var(--success)' : 'var(--warning)' }} />
            Mandatory authorization confirmation
          </div>
          <p className="mt-3 text-sm leading-6 text-soft">
            I own this target or I have explicit written authorization to test it. I understand the
            scanner will log my consent timestamp, target, and requesting IP before a scan is accepted.
          </p>
        </div>
      </div>
    </label>
  );
}
