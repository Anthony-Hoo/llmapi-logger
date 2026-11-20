import { useRef, useState } from "react";

import { browserClipboardEnv, copyText, MANUAL_COPY_HINT, type ClipboardEnv } from "../../lib/agent-access/access";
import { cn } from "../../lib/utils";
import { Button } from "../ui/button";
import { controlClassName, Input } from "../ui/input";

/**
 * Read-only text with a "复制" button. Without a usable clipboard API (plain
 * HTTP on a non-local origin) the text is selected for a manual copy.
 */
export function CopyableText({
  id,
  label,
  value,
  multiline = false,
  clipboard,
}: {
  id: string;
  label: string;
  value: string;
  multiline?: boolean;
  clipboard?: ClipboardEnv;
}) {
  const fieldRef = useRef<HTMLInputElement & HTMLTextAreaElement>(null);
  const [note, setNote] = useState<{ tone: "ok" | "manual"; text: string } | null>(null);

  async function copy() {
    const result = await copyText(value, clipboard ?? browserClipboardEnv());
    if (result === "copied") {
      setNote({ tone: "ok", text: "已复制。" });
      return;
    }
    fieldRef.current?.focus();
    fieldRef.current?.select();
    setNote({ tone: "manual", text: MANUAL_COPY_HINT });
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <label htmlFor={id} className="text-label font-medium text-muted">
          {label}
        </label>
        <Button variant="outline" size="sm" onClick={() => void copy()}>
          复制
        </Button>
      </div>
      {multiline ? (
        <textarea
          id={id}
          ref={fieldRef}
          readOnly
          value={value}
          rows={12}
          spellCheck={false}
          onFocus={(event) => event.currentTarget.select()}
          className={cn(controlClassName, "h-auto min-h-48 py-2 font-mono text-label")}
        />
      ) : (
        <Input
          id={id}
          ref={fieldRef}
          readOnly
          value={value}
          spellCheck={false}
          autoComplete="off"
          onFocus={(event) => event.currentTarget.select()}
          className="font-mono"
        />
      )}
      {note ? (
        <p role="status" className={cn("text-label", note.tone === "ok" ? "text-success-fg" : "text-warning-fg")}>
          {note.text}
        </p>
      ) : null}
    </div>
  );
}
