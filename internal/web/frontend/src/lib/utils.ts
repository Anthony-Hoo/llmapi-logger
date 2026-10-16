import { extendTailwindMerge } from "tailwind-merge";

// Conflict-aware class joining: when a caller overrides a component default
// (e.g. h-10 vs h-9) the later class wins, independent of CSS source order,
// which Tailwind 4 no longer keeps in "last class wins" order.
// "soft" is the project's custom --shadow-soft theme token.
const twMerge = extendTailwindMerge({
  extend: {
    theme: {
      shadow: ["soft"],
    },
  },
});

export function cn(...values: Array<string | false | null | undefined>): string {
  return twMerge(values.filter(Boolean).join(" "));
}