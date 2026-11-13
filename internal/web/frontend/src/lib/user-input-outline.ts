import type { ConversationMessage } from "../types";

/**
 * How many leading characters (code points) are compared against the
 * injected-text prefixes; the same window as the Go vocabulary
 * (insights.Vocabulary.IsInjectedUserText).
 */
const prefixWindow = 64;

/** Longest preview shown for one outline entry, in code points. */
const previewLength = 80;

export type UserInputOutlineEntry = {
  /** Position of the message in conversation.messages. */
  position: number;
  /** 1-based display number shown on the message card. */
  displayIndex: number;
  preview: string;
};

/**
 * Reports whether a user-role text part is client-injected context rather than
 * something a person typed. prefixes are the lower-cased
 * injected_user_text_prefixes from the management session; the rule mirrors
 * the Go vocabulary: drop leading whitespace, take the first 64 characters,
 * lower-case them, and test each prefix.
 */
export function isInjectedUserText(text: string, prefixes: readonly string[]): boolean {
  if (prefixes.length === 0) {
    return false;
  }
  const head = Array.from(text.trimStart()).slice(0, prefixWindow).join("").toLowerCase();
  return prefixes.some((prefix) => prefix !== "" && head.startsWith(prefix));
}

/**
 * Lists the user messages that carry text the person actually typed: user
 * role, with at least one non-empty text part that is not injected context.
 * Tool results and injected context blocks (AGENTS.md, environment context,
 * system reminders, ...) travel as user-role messages too and are skipped.
 */
export function buildUserInputOutline(
  messages: readonly ConversationMessage[],
  injectedPrefixes: readonly string[],
): UserInputOutlineEntry[] {
  const entries: UserInputOutlineEntry[] = [];
  messages.forEach((message, position) => {
    if (message.role !== "user") {
      return;
    }
    let typed: string | undefined;
    for (const part of message.content) {
      const text = part.type === "text" ? part.text : undefined;
      if (text && text.trim() !== "" && !isInjectedUserText(text, injectedPrefixes)) {
        typed = text;
        break;
      }
    }
    if (typed === undefined) {
      return;
    }
    entries.push({ position, displayIndex: position + 1, preview: previewOf(typed) });
  });
  return entries;
}

function previewOf(text: string): string {
  const characters = Array.from(text.replace(/\s+/g, " ").trim());
  return characters.length > previewLength ? `${characters.slice(0, previewLength).join("")}…` : characters.join("");
}
