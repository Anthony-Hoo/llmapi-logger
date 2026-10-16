import { cn } from "../../lib/utils";

/** Track of a segmented control (also used by the login tab list). */
export const segmentedTrackClassName = "inline-flex items-center gap-0.5 rounded-md bg-surface-sunken p-0.5";

/** One segment; `active` is the selected one. */
export function segmentedItemClassName(active: boolean, className?: string): string {
  return cn(
    "inline-flex h-7 items-center justify-center whitespace-nowrap rounded-sm px-3 text-body-sm font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50",
    active ? "bg-surface text-foreground shadow-xs" : "text-muted hover:text-foreground",
    className,
  );
}

/** A row of mutually exclusive buttons. */
export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: ReadonlyArray<{ value: T; label: string; title?: string }>;
  onChange: (value: T) => void;
}) {
  return (
    <div role="group" aria-label={label} className={segmentedTrackClassName}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={segmentedItemClassName(option.value === value)}
          aria-pressed={option.value === value}
          title={option.title}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
