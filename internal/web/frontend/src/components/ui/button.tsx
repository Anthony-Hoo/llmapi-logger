import { forwardRef, type ButtonHTMLAttributes } from "react";

import { cn } from "../../lib/utils";

export type ButtonVariant = "primary" | "secondary" | "outline" | "ghost" | "danger";
type ButtonSize = "default" | "sm" | "lg" | "icon";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const variants: Record<ButtonVariant, string> = {
  primary: "bg-primary text-primary-foreground shadow-xs hover:bg-primary-hover",
  secondary: "bg-surface-sunken text-foreground hover:bg-neutral-200",
  outline: "border border-border-strong bg-surface text-foreground shadow-xs hover:bg-surface-muted",
  ghost: "text-muted hover:bg-surface-sunken hover:text-foreground",
  danger: "bg-danger text-white shadow-xs hover:bg-danger-hover",
};

const sizes: Record<ButtonSize, string> = {
  default: "h-9 px-4 text-body",
  sm: "h-8 px-3 text-body-sm",
  lg: "h-10 px-6 text-body",
  icon: "h-9 w-9",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "primary", size = "default", type = "button", ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cn(
        "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    />
  );
});
