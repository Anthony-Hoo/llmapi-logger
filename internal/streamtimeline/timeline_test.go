package streamtimeline

import (
	"reflect"
	"testing"
)

func TestTimelineRoundTripAndBounds(t *testing.T) {
	t.Parallel()
	want := []Point{{Offset: 12, AtNS: 100}, {Offset: 40, AtNS: 105}, {Offset: 99, AtNS: 105}}
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(encoded, len(want))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded = %+v, want %+v", got, want)
	}
	if _, err := Decode(encoded, len(want)-1); err == nil {
		t.Fatal("expected point limit rejection")
	}
	if _, err := Encode([]Point{{Offset: 1, AtNS: 2}, {Offset: 1, AtNS: 3}}); err == nil {
		t.Fatal("expected non-increasing offset rejection")
	}
}
