import { forwardRef, type SelectHTMLAttributes } from "react";

import { cn } from "../../lib/utils";
import { controlClassName } from "./input";

/** Native select with the shared control look. */
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(
  { className, ...props },
  ref,
) {
  return <select ref={ref} className={cn(controlClassName, className)} {...props} />;
});
