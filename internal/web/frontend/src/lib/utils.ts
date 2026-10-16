import { extendTailwindMerge } from "tailwind-merge";

// Conflict-aware class joining: when a caller overrides a component default
// (e.g. h-10 vs h-9) the later class wins, independent of CSS source order,
// which Tailwind 4 no longer keeps in "last class wins" order.
// The project's named theme tokens (index.css @theme) must be registered here,
// otherwise e.g. `text-body` would be classified as a text color and silently
// dropped next to `text-muted`.
const twMerge = extendTailwindMerge({
  extend: {
    theme: {
      text: ["caption", "label", "body-sm", "body", "title", "heading", "display", "code"],
      spacing: ["gutter", "section", "card", "stack", "header"],
      shadow: ["card", "overlay"],
      container: ["page"],
    },
  },
});

export function cn(...values: Array<string | false | null | undefined>): string {
  return twMerge(values.filter(Boolean).join(" "));
}
