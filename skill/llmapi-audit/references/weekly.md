# Project weekly reports: `weekly`

Weekly reports attribute active time, tokens and cost to projects by rules on repository, path and agent project. They need `features.org_reports` in `llmaudit whoami`; otherwise every command answers `MODULE_DISABLED`.

A developer has one view: their own week. Everything else in this group is for administrators (`FORBIDDEN_ROLE` otherwise).

## My week

```
llmaudit weekly me
```

`data.row` is empty for an administrator token, and for a developer whose gateway identity is not known; `next_actions` says which. That is not "no activity".

## Administrators

```
llmaudit weekly report
llmaudit weekly report --week 2026-01-05 --metric tokens
llmaudit weekly trend --weeks 12
llmaudit weekly project 3 --week 2026-01-05
llmaudit weekly project -1
llmaudit weekly unattributed --limit 50
```

- `--week` is the first day of a week, `YYYY-MM-DD`, and it must be the deployment's week start day (Monday or Sunday). A wrong day answers `INVALID_ARGUMENT` with `details.week_start` and a hint naming the right date; use that date. Omitted, it means the current week.
- `--group-id` limits to one project group; `0` means ungrouped. `--metric` is `hours`, `tokens` or `cost`.
- `weekly project <id>` takes a project ID, or `-1` for unattributed activity and `-2` for activity without any project context.
- `weekly unattributed` lists activity that no project rule matched, each with the server's `draft_rule`. To turn one into a rule, see `config.md` (a plan with `--add rules=<kind>:<pattern>`).

### Reading a report

- `final` is true when the week is frozen: its snapshot no longer changes. A week that is not final can still move as late records arrive and rules change; say so when you report numbers for it.
- `meta.complete` false with `incomplete_reason: evidence_pending` means the numbers can still change. On `weekly report` it means the week has not ended, so its records are still coming in. On `weekly project`, `weekly unattributed` and `weekly trend` it means the week is not final (not frozen yet), and a trend is complete only when every week in it is. On `weekly me`, a developer's current week is never complete.
- Durations are in seconds (fields ending in `_seconds`). Project names and unattributed values end in `_untrusted`.

## On the web page instead

Every report view of the page has a command here. The differences:

- The page's previous/next week buttons step through weeks for the user. Here you always name the week with `--week`; take the date from the report you already have, or from the hint of an `INVALID_ARGUMENT` about the week start.
- The page builds a draft project name from an unattributed entry; here you get only the server's `draft_rule`, and the user chooses the name.
- Regenerating a week needs an administrator write token on a deployment that allows agent writes. Without one (`READ_ONLY_TOKEN`, `WRITE_DISABLED`), the administrator does it on the web page.

## Regenerating a frozen week (write)

```
llmaudit weekly regenerate --week 2026-01-05
```

This only creates a plan (`extras.week` says whether the week has ended and is frozen). It needs an administrator write token. Only an ended week can be regenerated, and not one older than the retention period. Show the plan to the user and apply it with `llmaudit apply <plan-id>` only after they agree. Applying can take up to two minutes; on `TIMEOUT`, check with `llmaudit weekly report --week 2026-01-05` before doing anything else.
