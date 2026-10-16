import type { KeyboardEvent } from "react";

import type { HeatmapDay } from "../../types";
import { buildHeatGrid, WEEKDAY_LABELS, type HeatLevel } from "../../lib/insights/heatmap";
import { chartColors, chartFont, colorVar } from "../../lib/tokens";

export const HEAT_COLORS: Record<HeatLevel, string> = {
  0: colorVar("neutral-200"),
  1: colorVar("primary-200"),
  2: colorVar("primary-400"),
  3: colorVar("primary-600"),
  4: colorVar("primary-800"),
};

const CELL = 16;
const GAP = 3;
const LABEL_WIDTH = 18;

/** 8-week activity heatmap: Sunday-first rows, one column per week. */
export function ActivityHeatmap({
  days,
  today,
  selectedDay,
  onSelectDay,
}: {
  days: readonly HeatmapDay[];
  /** Local `YYYY-MM-DD` of today; the last column ends with this day's week. */
  today: string;
  selectedDay: string | null;
  onSelectDay: (day: string | null) => void;
}) {
  const grid = buildHeatGrid(days, today);
  const width = LABEL_WIDTH + grid.weeks * (CELL + GAP);
  const height = 7 * (CELL + GAP);

  function activate(day: string) {
    onSelectDay(selectedDay === day ? null : day);
  }

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto">
        <svg
          role="group"
          aria-label="近 8 周活动热力图"
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          style={{ display: "block", maxWidth: "100%" }}
        >
          {WEEKDAY_LABELS.map((name, row) => (
            <text
              key={name}
              x={0}
              y={row * (CELL + GAP) + CELL - 4}
              fontSize={chartFont.caption}
              fill={chartColors.textSubtle}
            >
              {row % 2 === 1 ? name : ""}
            </text>
          ))}
          {grid.rows.map((cells, row) =>
            cells.map((cell, week) => {
              if (!cell) {
                return null;
              }
              const selected = selectedDay === cell.day;
              const text = `${cell.day} · ${cell.requests} 次请求 · ${cell.sessions} 个会话`;
              return (
                <rect
                  key={cell.day}
                  role="button"
                  tabIndex={0}
                  aria-label={text}
                  aria-pressed={selected}
                  x={LABEL_WIDTH + week * (CELL + GAP)}
                  y={row * (CELL + GAP)}
                  width={CELL}
                  height={CELL}
                  rx={3}
                  fill={HEAT_COLORS[cell.level]}
                  stroke={selected ? chartColors.text : "none"}
                  strokeWidth={selected ? 2 : 0}
                  style={{ cursor: "pointer" }}
                  onClick={() => activate(cell.day)}
                  onKeyDown={(event: KeyboardEvent<SVGRectElement>) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      activate(cell.day);
                    }
                  }}
                >
                  <title>{text}</title>
                </rect>
              );
            }),
          )}
        </svg>
      </div>
      <div className="flex items-center gap-1.5 text-caption text-subtle">
        <span>少</span>
        {([0, 1, 2, 3, 4] as HeatLevel[]).map((level) => (
          <span key={level} className="inline-block h-3 w-3 rounded-xs" style={{ backgroundColor: HEAT_COLORS[level] }} />
        ))}
        <span>多</span>
        <span className="ml-2">点击某天可筛选当天会话</span>
      </div>
    </div>
  );
}
