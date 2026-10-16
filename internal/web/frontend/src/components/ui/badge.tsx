import type { HTMLAttributes } from "react";

import { cn } from "../../lib/utils";

export type BadgeVariant = "neutral" | "outline" | "info" | "success" | "warning" | "danger" | LegacyBadgeVariant;
/** Temporary aliases until every call site uses the token-based names. */
type LegacyBadgeVariant = "default" | "secondary" | "destructive";

const variants: Record<BadgeVariant, string> = {
  neutral: "border-transparent bg-surface-sunken text-muted",
  outline: "border-border bg-surface text-muted",
  info: "border-info-border bg-info-bg text-info-fg",
  success: "border-success-border bg-success-bg text-success-fg",
  warning: "border-warning-border bg-warning-bg text-warning-fg",
  danger: "border-danger-border bg-danger-bg text-danger-fg",
  default: "border-info-border bg-info-bg text-info-fg",
  secondary: "border-transparent bg-surface-sunken text-muted",
  destructive: "border-danger-border bg-danger-bg text-danger-fg",
};

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
}

export function Badge({ className, variant = "neutral", ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-label font-medium transition-colors",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}
