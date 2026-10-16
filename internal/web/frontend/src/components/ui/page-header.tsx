import type { ReactNode } from "react";

import { cn } from "../../lib/utils";

/**
 * The one header pattern of every page and panel: optional leading control
 * (e.g. a back button), title with optional inline badges, a one-line
 * subtitle, and actions on the right. `page` titles a whole view, `panel`
 * titles a card or side panel.
 */
export function PageHeader({
  title,
  description,
  actions,
  leading,
  badges,
  level = "page",
  as: Heading = level === "page" ? "h2" : "h3",
  className,
  descriptionClassName,
  descriptionTitle,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  leading?: ReactNode;
  badges?: ReactNode;
  level?: "page" | "panel";
  as?: "h1" | "h2" | "h3";
  className?: string;
  descriptionClassName?: string;
  descriptionTitle?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-x-4 gap-y-2", className)}>
      <div className="flex min-w-0 items-start gap-3">
        {leading ? <div className="shrink-0">{leading}</div> : null}
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Heading className={cn("font-semibold text-foreground", level === "page" ? "text-heading" : "text-title")}>{title}</Heading>
            {badges}
          </div>
          {description ? (
            <p className={cn("mt-0.5 text-body-sm text-muted", descriptionClassName)} title={descriptionTitle}>
              {description}
            </p>
          ) : null}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
