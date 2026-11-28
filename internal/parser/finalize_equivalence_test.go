package parser_test

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"llmapi-logger/internal/audit"
	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/builtin"
	"llmapi-logger/internal/protofixture"
)

// Design G.3: for every committed audit of the protofixture traffic, the
// Input built from the evidence the session handed over equals, field by
// field and byte for byte, the Input built from the stored rows; and the
// job's identity is the stored one. The traffic includes cut, aborted and
// cancelled streams, error responses, a request body above 1 MiB and an
// upstream that cannot be reached, so partial bodies and a missing response
// stage are covered. SQLite writes capture version 1, PostgreSQL version 2.
func TestInputFromHandedOverEvidenceEqualsTheStoredInput(t *testing.T) {
	if testing.Short() {
		t.Skip("the fixture catalogue through the unified write path")
	}
	for name, open := range finalizeStores(t) {
		t.Run(name, func(t *testing.T) {
			harness := newFinalizeHarness(t, open(t), audit.Options{}, builtin.All())
			unreachable := harness.proxyTo("http://127.0.0.1:1")
			traffic := finalizeTraffic(t)
			withEvidence, partial, withHeaders := 0, 0, 0
			check := func(label string, handler http.Handler, exchange protofixture.Exchange) {
				harness.send(handler, exchange)
				job := harness.next()
				defer job.Release()
				if job.Evidence == nil {
					t.Fatalf("%s: id-only job", label)
				}
				withEvidence++
				ctx := context.Background()
				stored, err := harness.store.LoadParserAudit(ctx, job.Audit.AuditID)
				if err != nil {
					t.Fatal(err)
				}
				if job.Audit != stored {
					t.Fatalf("%s: job audit %+v, stored %+v", label, job.Audit, stored)
				}
				want, wantErr := harness.worker.LoadInputForTest(ctx, stored)
				got, gotErr := harness.worker.InputFromEvidenceForTest(job.Audit, job.Evidence)
				if (wantErr == nil) != (gotErr == nil) {
					t.Fatalf("%s: stored input error %v, handed-over input error %v", label, wantErr, gotErr)
				}
				compareInputs(t, label, want, got)
				if want.Headers.Get("User-Agent") != "" {
					withHeaders++
				}
				if !want.Request.Complete || want.Response.Present && !want.Response.Complete {
					partial++
				}
			}
			for _, exchange := range traffic {
				check(exchangeName(exchange), harness.handler, exchange)
			}
			check("unreachable", unreachable, traffic[0])
			if partial == 0 || withHeaders != withEvidence {
				t.Fatalf("%d audits had a partial body, %d of %d their allowlisted headers", partial, withHeaders, withEvidence)
			}
			t.Logf("%d audits compared, %d with a partial body", withEvidence, partial)
		})
	}
}

func compareInputs(t *testing.T, label string, want, got parser.Input) {
	t.Helper()
	fields := []struct {
		name      string
		want, got any
	}{
		{"AuditID", want.AuditID, got.AuditID},
		{"Protocol", want.Protocol, got.Protocol},
		{"Endpoint", want.Endpoint, got.Endpoint},
		{"Request", want.Request, got.Request},
		{"Response", want.Response, got.Response},
		{"StatusCode", want.StatusCode, got.StatusCode},
		{"Headers", want.Headers, got.Headers},
	}
	for _, field := range fields {
		if !reflect.DeepEqual(field.want, field.got) {
			t.Fatalf("%s: Input.%s differs:\n stored      %s\n handed over %s", label, field.name, describe(field.want), describe(field.got))
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%s: inputs differ", label)
	}
}

func describe(value any) string {
	if body, ok := value.(parser.BodySource); ok {
		return fmt.Sprintf("{Present:%v Complete:%v ContentType:%q ContentEncoding:%q ErrorCode:%q len(Data):%d}",
			body.Present, body.Complete, body.ContentType, body.ContentEncoding, body.ErrorCode, len(body.Data))
	}
	if pointer, ok := value.(*int); ok && pointer != nil {
		return fmt.Sprint(*pointer)
	}
	return fmt.Sprintf("%v", value)
}
