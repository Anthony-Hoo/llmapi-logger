import type { HTMLAttributes } from "react";

import { cn } from "../../lib/utils";

export type AlertVariant = "neutral" | "info" | "success" | "warning" | "danger";

const variants: Record<AlertVariant, string> = {
  neutral: "border-border bg-surface-muted text-foreground",
  info: "border-info-border bg-info-bg text-info-fg",
  success: "border-success-border bg-success-bg text-success-fg",
  warning: "border-warning-border bg-warning-bg text-warning-fg",
  danger: "border-danger-border bg-danger-bg text-danger-fg",
};

export function Alert({ className, variant = "neutral", ...props }: HTMLAttributes<HTMLDivElement> & { variant?: AlertVariant }) {
  return (
    <div
      role="alert"
      data-variant={variant}
      className={cn("relative w-full rounded-md border px-3 py-2.5 text-body-sm", variants[variant], className)}
      {...props}
    />
  );
}

export function AlertTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn("mb-0.5 text-body font-semibold", className)} {...props} />;
}

/** Inherits the variant's foreground; the neutral variant uses muted text. */
export function AlertDescription({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("text-body-sm [[data-variant=neutral]_&]:text-muted", className)} {...props} />;
}
