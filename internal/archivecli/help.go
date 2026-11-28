package archivecli

import (
	"fmt"
	"strings"
)

const topDescription = `audit-archive reads the cold archive of the audit proxy: the bundles the
archiver writes under archive.dir. It reads the directory only; it never
connects to a database and needs neither PostgreSQL nor a running proxy.
Bundles are found through their manifests (*.manifest.json), never by file
name; files renamed *.rejected or *.orphan are ignored.

Keys: --key names the proxy's master key file (audit.key, the 32-byte file the
proxy reads). The archive keys are derived from it; it is never created. A
bundle's key fingerprint is compared before anything is decrypted, and a
different key is reported as key_mismatch. Keys and credentials are never
taken as command-line values.

Plaintext: cat and export write decrypted conversation content to standard
output. The archive holds no credential value (Authorization, API keys,
cookies and credential query parameters are kept only as name, length and a
keyed fingerprint), so the output has none either, but conversation content
is not masked. Where the output goes is your responsibility.

Output goes to standard output, diagnostics to standard error as
"audit-archive: <code>: <message>". Exit codes: 0 done; 1 a check failed, a
bundle could not be read or verified, the key does not match, or the output
could not be written; 2 invalid command line; 3 not found, no such export
for the record, or (fpr) no match.`

func topHelp() string {
	var builder strings.Builder
	builder.WriteString("Usage: audit-archive <command> [flags]\n\n")
	builder.WriteString(topDescription)
	builder.WriteString("\n\nCommands:\n")
	for _, cmd := range commands() {
		fmt.Fprintf(&builder, "  %-8s %s\n", cmd.name, cmd.summary)
	}
	builder.WriteString("\nRun \"audit-archive <command> --help\" for the flags of one command.\n")
	builder.WriteString("\nExamples:\n")
	builder.WriteString("  audit-archive list --dir /archive\n")
	builder.WriteString("  audit-archive verify --dir /archive --key /data/audit.key\n")
	builder.WriteString("  audit-archive export --dir /archive --key /data/audit.key --audit <audit_id> --what request\n")
	return builder.String()
}

func commandHelp(cmd command) string {
	return "Usage: audit-archive " + cmd.name + " " + cmd.usage + "\n\n" + strings.TrimLeft(cmd.help, "\n")
}

const listUsage = `--dir <archive> [--key <file>] [--conversation <id> | --audit <id>] [--json]`

const listHelp = `
List the bundles from their manifests: kind (conversation, bucket, gaps),
protocol, time range (UTC), members, conversations, whether encrypted,
format version, and the manifest path relative to --dir. No key is needed;
with --key each manifest's key fingerprint and signature are checked and the
AUTH column says ok, key_mismatch or mac_mismatch (not_checked without a key).
Manifests that do not parse are reported on standard error. Data files are
not read; use verify for that.

Flags:
  --dir <archive>       The archive directory (archive.dir). Required.
  --key <file>          The master key file; checks the manifests' signatures.
  --conversation <id>   Only the bundles holding this conversation.
  --audit <id>          Only the bundles holding a revision of this audit.
  --json                One JSON object per bundle and line instead of a table.

Exit codes: 0, or 3 when a filter matches no bundle.
`

const verifyUsage = `(--dir <archive> | --bundle <manifest>) [--key <file>] [--skip-event-mac] [--json]`

const verifyHelp = `
Verify one bundle (--bundle, the path of its .manifest.json) or every bundle of
the archive directory (--dir). Prints one line per bundle,
"<result> <level> <members> <manifest>", then a summary line with the counts.

Without --key only the keyless layer runs (level "files"), and it is weaker:
the manifest parses and every data file's size and SHA-256 equal the
manifest's. That detects damage, not forgery: the signature and the content
are not checked.

With --key (level "full") every check of the archive that needs no database
runs (design J.2): the key fingerprint and the manifest signature, the data
files' sizes and SHA-256, decryption, every line's shape and record digest
against the manifest, the order and turn context of the lines, the content
addresses of all objects, raw chunk continuity and whole-body SHA-256, the
closure of every reference, and the MACs of the copied integrity events
(those are signed with the integrity key derived from the same master key;
--skip-event-mac leaves this one check out).

Without --key an encrypted bundle is never decrypted: it shows ok at level
files when its files are intact.

Result codes: ok; file_missing, file_mismatch (a file differs from the
manifest), manifest_invalid, mac_mismatch, key_mismatch, decrypt_failed,
decompress_failed, line_invalid, count_mismatch,
member_mismatch, order, context_mismatch, digest_mismatch, object_mismatch,
raw_mismatch, reference_open, event_mac_mismatch, read_failed. With --dir, a
manifest that does not parse counts as a failed bundle; data files without a
manifest and temporary files of an interrupted run are listed as notes on
standard error and do not fail the run.

Flags:
  --dir <archive>       The archive directory: verify every bundle.
  --bundle <manifest>   Verify this one bundle.
  --key <file>          The master key file: run every check.
  --skip-event-mac      With --key, do not check the integrity events' MACs.
  --json                One JSON object per bundle instead of the text lines.

Exit codes: 0 when every bundle passed, 1 when any failed.
`

const catUsage = `--dir <archive> (--key <file> | --unauthenticated) [--conversation <id> | --audit <id>] [--all-revisions] [--with-objects] [--skip-event-mac]`

const catHelp = `
Print the decrypted lines of the archive as JSON Lines, in the archive's own
line format (one "type": "audit" object per audit, "type": "gap" lines of gap
bundles): plaintext conversation content, credentials only as
{"value_omitted": "credential", "length", "value_fpr"}. Each bundle involved
is verified completely first (the checks of verify --key); a bundle that
fails is skipped with its reason on standard error and nothing of it is
printed. The output is plaintext; where it goes is your responsibility.

Without a filter every bundle is printed. With a filter only the matching
audits are printed, and gap bundles are left out. Each audit is printed at its
highest revision unless --all-revisions is given. With --with-objects each
bundle's selected lines are followed by the objects file entries they refer
to (content and binary objects, raw chunks, split parsed_json parts).

Flags:
  --dir <archive>       The archive directory. Required.
  --key <file>          The master key file. Required unless --unauthenticated.
  --unauthenticated     Read bundles written without encryption without a key;
                        their signatures are not checked.
  --conversation <id>   Only the audits of this conversation.
  --audit <id>          Only this audit.
  --all-revisions       Every archived revision, not only the highest.
  --with-objects        Also print the objects the printed lines refer to.
  --skip-event-mac      Do not check the integrity events' MACs.

Exit codes: 0; 1 when a bundle was skipped; 3 when the filter matches nothing.
`

var exportUsage = `--dir <archive> (--key <file> | --unauthenticated) (--audit <id> --what <kind> | --conversation <id>) [--skip-event-mac]`

var exportHelp = `
Export one audit (its highest revision) in one of the forms of the single-audit
export, built only from the bundle that holds it and in the same JSON the
proxy's agent export gives:

  conversation       the conversation of the record (default)
  headers            {"audit_id", "headers": [...]}: every header and trailer
                     of the four stages; a credential has value_omitted,
                     length and value_fpr instead of a value
  request, response  the provider request or response rebuilt from the turn
  raw-request, raw-response
                     the raw body bytes (only when the archive kept them in
                     full); metadata on standard error
  timeline-request, timeline-response
                     the stream timeline
  detail             the whole record detail, request URI, headers and
                     User-Agent in projected form

With --conversation, export the conversation of every audit of the
conversation in turn order, across all bundles that hold it, one JSON object
per line: {"audit_id", "turn_id", "created_at_ns", "conversation"}.

Only the bundle that holds the audit is read; it is verified completely first.
The output is plaintext; where it goes is your responsibility.

Flags:
  --dir <archive>       The archive directory. Required.
  --key <file>          The master key file. Required unless --unauthenticated.
  --unauthenticated     Read bundles written without encryption without a key.
  --audit <id>          The audit to export.
  --conversation <id>   The conversation to export (conversation form only).
  --what <kind>         The form, one of: ` + strings.Join(ExportKinds, ", ") + `.
  --skip-event-mac      Do not check the integrity events' MACs.

Exit codes: 0; 1 a check failed; 3 not in the archive, or the record has no
such export (not_available, not_retained, not_ready, no_turn_graph).
`

const fprUsage = `--key <file> [--known-key-file <file>] [--dir <archive> [--conversation <id> | --audit <id>]] [--skip-event-mac]`

const fprHelp = `
Read a known API key and print its three candidate fingerprints, one per line
as "<form> <hex>":

  raw          the key as sent in X-Api-Key, X-Goog-Api-Key or ?key=
  bearer       "Bearer " followed by the key, as sent in Authorization
  api_key_fpr  the normalised key, as audit_records.api_key_fpr holds it

The key is read from --known-key-file (its first line), or from standard
input: typed without echo when it is a terminal, otherwise its first line. It
is never a command-line value and is never printed. The fingerprints are
keyed with the master key file (--key) and reveal nothing without it.

With --dir every verified bundle is searched (all revisions, or only the
conversation or audit given) and each match is printed as
"match <audit_id> revision <n> <where> <form>", where is header <stage>
<kind> <name>, user_agent, request_uri <name> or api_key_fpr.

Flags:
  --key <file>             The master key file. Required.
  --known-key-file <file>  Read the known key from this file.
  --dir <archive>          Search the archive for the key.
  --conversation <id>      Search only this conversation.
  --audit <id>             Search only this audit.
  --skip-event-mac         Do not check the integrity events' MACs.

Exit codes: 0; 3 when --dir was given and nothing matched.
`
