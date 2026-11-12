import { useState, type ReactNode } from "react";

import { cn } from "../../lib/utils";

/** One page of the system settings menu. */
export interface SettingsSection {
  id: string;
  label: string;
  /** One line under the label saying what is configured there. */
  hint: string;
  render: () => ReactNode;
}

/**
 * The administrator's settings menu: every configuration page lives behind
 * one entry of the main navigation, with its own section list on the left
 * (a wrapping row on narrow screens). Only the selected section is mounted.
 */
export function SystemSettings({ sections, initial }: { sections: SettingsSection[]; initial?: string }) {
  const [selected, setSelected] = useState(initial ?? sections[0]?.id ?? "");
  const active = sections.find((section) => section.id === selected) ?? sections[0];
  if (!active) {
    return <p className="py-6 text-center text-body-sm text-muted">没有可配置的项目。</p>;
  }
  return (
    <div className="grid items-start gap-section lg:grid-cols-[13rem_minmax(0,1fr)]">
      <nav aria-label="系统配置" className="rounded-md border bg-surface p-2 lg:sticky lg:top-20">
        <h2 className="px-2 pb-1 text-label font-semibold text-muted">系统配置</h2>
        <ul className="flex flex-wrap gap-1 lg:flex-col">
          {sections.map((section) => {
            const current = section.id === active.id;
            return (
              <li key={section.id} className="min-w-0">
                <button
                  type="button"
                  aria-current={current ? "page" : undefined}
                  onClick={() => setSelected(section.id)}
                  className={cn(
                    "w-full rounded-sm px-2 py-1.5 text-left transition-colors",
                    current ? "bg-surface-sunken text-foreground" : "text-muted hover:bg-surface-sunken hover:text-foreground",
                  )}
                >
                  <span className="block text-body-sm font-medium">{section.label}</span>
                  <span className="hidden text-label text-subtle lg:block">{section.hint}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
      <div className="min-w-0 space-y-section">{active.render()}</div>
    </div>
  );
}
