import { useState, type ReactNode } from "react";

import type { ApiClient } from "../../api";
import type { SessionCard, TreeNode } from "../../types";
import { OverviewPage } from "./overview-page";
import { TreePage } from "./tree-page";
import { TrendPage } from "./trend-page";
import { clientLabel, roleLabel } from "./ui-bits";

type InsightsPage =
  | { kind: "trend"; sessionID: string; title: string }
  | { kind: "tree"; treeID: string };

/**
 * The "用量洞察" view: overview -> session trend -> agent tree, navigated with
 * a small stack instead of a router. The overview stays mounted while a deeper
 * page is shown, so its range, grouping and loaded session cards survive going
 * back.
 */
export function InsightsView({
  client,
  isDeveloper,
  refreshKey,
  renderAuditDetail,
}: {
  client: ApiClient;
  isDeveloper: boolean;
  refreshKey: number;
  renderAuditDetail: (auditID: string) => ReactNode;
}) {
  const [stack, setStack] = useState<InsightsPage[]>([]);
  const current = stack.at(-1) ?? null;

  const push = (page: InsightsPage) => setStack((pages) => [...pages, page]);
  const pop = () => setStack((pages) => pages.slice(0, -1));

  const openSession = (card: SessionCard) =>
    push({ kind: "trend", sessionID: card.session_id, title: `${clientLabel(card.client)} · ${roleLabel(card.role)} · ${card.session_id}` });
  const openTree = (treeID: string) => push({ kind: "tree", treeID });
  const openNode = (node: TreeNode) => {
    if (node.session_id) {
      push({ kind: "trend", sessionID: node.session_id, title: `${clientLabel(node.client)} · ${roleLabel(node.role)} · ${node.session_id}` });
    }
  };

  return (
    <div>
      <div className={current ? "hidden" : undefined}>
        <OverviewPage
          client={client}
          isDeveloper={isDeveloper}
          refreshKey={refreshKey}
          onOpenSession={openSession}
          onOpenTree={openTree}
        />
      </div>
      {current ? (
        // Explicit margin: the overview wrapper above is display:none while a
        // sub-page is open, so a v4 `space-y` margin-bottom on it would not apply.
        <div className="mt-section">
      {current?.kind === "trend" ? (
        <TrendPage
          key={`trend:${current.sessionID}`}
          client={client}
          sessionID={current.sessionID}
          title={current.title}
          refreshKey={refreshKey}
          onBack={pop}
          onOpenTree={openTree}
          renderAuditDetail={renderAuditDetail}
        />
      ) : null}
      {current?.kind === "tree" ? (
        <TreePage key={`tree:${current.treeID}`} client={client} treeID={current.treeID} refreshKey={refreshKey} onBack={pop} onOpenSession={openNode} />
      ) : null}
        </div>
      ) : null}
    </div>
  );
}
