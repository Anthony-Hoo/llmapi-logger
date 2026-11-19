# Errors and what to do

A failed command prints `{"ok":false,"error":{"code","message","hint","details"}}` on stderr and exits with the code in the table. `hint` names the next step; `details.field` names the argument at fault. Codes are stable; messages are not, so decide by `code`.

General rules: do not retry a command more than once unless the table says so; never switch identity, path or tool to get around an error; never ask the user for a password, API key or token.

## Errors from the server

| Code | Exit | Meaning | What to do |
|---|---|---|---|
| `FEATURE_DISABLED` | 1 | Agent access is not enabled on this deployment. | Tell the user it is not available here. Do not retry, do not log in again, do not touch the local credentials. |
| `UNAUTHENTICATED` | 4 | No token was sent, or the token is not valid. | Stop and ask the user to run `llmaudit login --server <server>`. |
| `TOKEN_EXPIRED` | 4 | The token has expired. Tokens are never renewed automatically. | Stop and ask the user to run `llmaudit login --server <server>`. |
| `TOKEN_REVOKED` | 4 | The token was revoked, usually by removing this device on the web page. | Tell the user it was revoked, then ask them to run `llmaudit login --server <server>` if they still want access. |
| `ROLE_UNAVAILABLE` | 4 | Developer sign-in has been switched off, so developer tokens no longer work. | Tell the user to contact their administrator. Logging in again will not help. |
| `CLIENT_TOO_OLD` | 1 | This client is older than the server accepts. | Ask the user to reinstall the Skill from the Agent access page of the web UI. |
| `FORBIDDEN_ROLE` | 5 | The command is for administrators only. | Stop and tell the user. Do not try another command to get the same information. |
| `READ_ONLY_TOKEN` | 5 | The token is read-only and the command changes something. | Stop. If the user (an administrator) wants the change, they log in again with `llmaudit login --server <server> --write`. |
| `WRITE_DISABLED` | 5 | This deployment does not accept changes through agents. | Stop and give the user the web page (`web_url` if present) to make the change there. |
| `MODULE_DISABLED` | 1 | The feature behind the command (insights, weekly reports or session analysis) is not enabled. | Tell the user the feature is not enabled. `llmaudit whoami` lists what is. |
| `INVALID_ARGUMENT` | 2 | An argument is not valid; `details.field` says which (for a week, `details.week_start` gives the deployment's week start day). | Check `--help` of the command, fix that argument and run again. |
| `NOT_FOUND` | 1 | The object does not exist, is not visible to this identity, or has not been produced yet (not analysed, no conversation parsed). | Read `hint`. Tell the user the possibilities; do not try another identity or path. |
| `ALREADY_EXISTS` | 1 | A rule with that name already exists; `details.id` is the existing one. | Plan a change of the existing rule instead, or choose another name with the user. |
| `CONFLICT` | 1 | The change conflicts with existing data, for example deleting a project group that still has projects or members. | Read `hint` and tell the user what has to change first. |
| `VERSION_CONFLICT` | 1 | The object changed after the plan was created. | Read it again with `llmaudit config show --kind <kind>`, tell the user what changed, and create a new plan. |
| `PLAN_NOT_FOUND` | 1 | The plan does not exist, was already applied (successfully or not), or belongs to another token. | Create a new plan and show it to the user again. |
| `PLAN_EXPIRED` | 1 | The plan is older than 10 minutes. | Create a new plan and show it to the user again. |
| `LINK_EXPIRED` | 1 | An install download link is past its 30 minutes (only the install prompt's downloads see this). | Stop the install and ask the user to generate a new install prompt on the Agent access page; an old link never works again. |
| `RUN_IN_PROGRESS` | 1 | A session analysis run is already running. | Do not start another; follow it with `llmaudit analysis overview --since 1d`. |
| `NOT_READY` | 1 | The evidence is still being captured, or the reconstruction is not available yet. | Read it again later; tell the user it is not ready yet. |
| `NOT_RETAINED` | 1 | The raw body was released after it was verified against the reconstruction. | Export `request` or `response` (the reconstruction) instead. This is not data loss. |
| `EVIDENCE_UNAVAILABLE` | 1 | The stored evidence failed its integrity check. | Tell the user; do not retry. |
| `RATE_LIMITED` | 1 | Too many requests; `details.retry_after_seconds` says how long to wait. | Wait until then and try once more. Pack and facet reads have a lower limit: do not poll them. |
| `UPSTREAM_UNAVAILABLE` | 1 | A dependency of the server (its database, the gateway) is unavailable, or a view log could not be written. | Try once more a little later; if it fails again, tell the user. |
| `TIMEOUT` | 1 | The server did not finish in time, or the client gave up after the command's own timeout (then `details.source` is `client`; `--help` of the command shows the limit). | For a read, narrow the range or page size and retry once. For `apply`, do not apply again: check with the matching read command whether the change took effect. |
| `INVALID_GRANT` | 4 | The login's one-time code was invalid, expired, already used, or did not match. | Ask the user to run `llmaudit login --server <server>` again. |
| `INTERNAL` | 1 | An unexpected server error. | Tell the user; do not retry. |

## Errors from the client itself

| Code | Exit | Meaning | What to do |
|---|---|---|---|
| `NOT_LOGGED_IN` | 4 | There are no local credentials. | Ask the user to run `llmaudit login --server <server>` with their audit server's address. |
| `NETWORK_ERROR` | 1 | The server could not be reached (address, DNS, TLS, proxy, server down); `details.reason` is `connect` or `tls`. | Tell the user, with the message. With `tls` the certificate could not be verified: the user can point `ca_file` in config.json of the state directory at their CA; you do not edit it, and you never read credentials.json. Do not retry a write; for `apply`, check whether it took effect first. |
| `INVALID_RESPONSE` | 1 | The answer was not a valid envelope, or a read result lacked `meta`. Often a proxy or a wrong server address. | Tell the user; check with them that the server address is the audit server's web UI. |
| `REDIRECT_REFUSED` | 1 | The server answered with a redirect, which the client does not follow (for example http to https). | Tell the user; they log in again with the final address (`llmaudit login --server <server>`). |
| `LOGIN_TIMEOUT` | 4 | Nobody approved in the browser within 5 minutes. | Ask the user whether they want to try again; they can run `llmaudit login --server <server>` themselves. |
| `LOGIN_DENIED` | 4 | The user chose "deny" on the authorization page. | Respect it. Do not start another login unless the user asks. |
| `NO_TTY` | 2 | The command needs an interactive terminal (entering an API key, or pasting a login code). | Ask the user to run that exact command in their own terminal. Do not look for another way to pass the value. |
| `LOCAL_FILE_ERROR` | 1 | A local file could not be read or written (`--out`, `--file`, `--patch-file`, the state directory). | Check the path in `details` (the directory must exist), fix it and run again. |

## Other situations

- **An empty list.** Check `meta.complete` and `next_cursor` first; with `--user-agent` an empty page can have a next page. Only an empty, complete, last page means "none".
- **Install link problems.** A download that answers HTTP 410 (`LINK_EXPIRED`) used an expired link (they last 30 minutes); HTTP 404 means a wrong or incomplete link; HTTP 429 means the link was used too often. In every case the user generates a new install prompt on the Agent access page.
- **The Skill seems to be missing** after installing: most agents load skills when a session starts. Ask the user to start a new session.
