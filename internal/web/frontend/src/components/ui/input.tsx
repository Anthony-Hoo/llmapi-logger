import { forwardRef, type InputHTMLAttributes } from "react";

import { cn } from "../../lib/utils";

/** Shared look of text inputs and native selects. */
export const controlClassName =
  "h-9 w-full rounded-md border border-border-strong bg-surface px-3 text-body text-foreground shadow-xs outline-hidden transition-colors focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring/40 disabled:cursor-not-allowed disabled:opacity-50 aria-[invalid=true]:border-danger";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(
  { className, type, ...props },
  ref,
) {
  return <input ref={ref} type={type} className={cn("flex py-2 placeholder:text-subtle", controlClassName, className)} {...props} />;
});
