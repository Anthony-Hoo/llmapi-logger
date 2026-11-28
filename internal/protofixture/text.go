package protofixture

import (
	"encoding/hex"
	"math/rand/v2"
	"strings"
)

// syllables is the only source of generated prose. Every word is made of
// these, so fixture text can never contain real data, and a scan for any
// real-looking string in a database filled by the fixtures finds nothing.
var syllables = []string{
	"ka", "lo", "mi", "ra", "te", "su", "no", "va", "pe", "di",
	"zo", "fa", "qui", "ber", "lan", "tor", "mes", "vin", "dal", "rok",
}

// textSource is a deterministic generator of synthetic words, identifiers
// and numbers. It is not safe for concurrent use.
type textSource struct {
	rng *rand.Rand
}

func newTextSource(seed, stream uint64) *textSource {
	return &textSource{rng: rand.New(rand.NewPCG(seed, stream))}
}

func (source *textSource) intn(n int) int {
	if n <= 1 {
		return 0
	}
	return source.rng.IntN(n)
}

func (source *textSource) chance(probability float64) bool {
	return source.rng.Float64() < probability
}

func (source *textSource) uint64() uint64 { return source.rng.Uint64() }

func (source *textSource) word() string {
	count := 1 + source.intn(3)
	var builder strings.Builder
	for range count {
		builder.WriteString(syllables[source.intn(len(syllables))])
	}
	return builder.String()
}

// sentence returns about n bytes of words ending with a full stop.
func (source *textSource) sentence(n int) string {
	if n < 8 {
		n = 8
	}
	var builder strings.Builder
	builder.Grow(n + 16)
	capital := true
	for builder.Len() < n-1 {
		word := source.word()
		if capital {
			word = strings.ToUpper(word[:1]) + word[1:]
			capital = false
		}
		if builder.Len() > 0 {
			builder.WriteByte(' ')
		}
		builder.WriteString(word)
		if builder.Len() < n-12 && source.intn(9) == 0 {
			builder.WriteByte('.')
			capital = true
		}
	}
	builder.WriteByte('.')
	return builder.String()
}

// paragraphs returns about n bytes of prose split into lines, the way an
// assistant answer or a pasted file looks.
func (source *textSource) paragraphs(n int) string {
	if n <= 200 {
		return source.sentence(n)
	}
	var builder strings.Builder
	builder.Grow(n + 64)
	for builder.Len() < n {
		remaining := n - builder.Len()
		length := min(remaining, 120+source.intn(280))
		if builder.Len() > 0 {
			builder.WriteString("\n\n")
		}
		builder.WriteString(source.sentence(length))
	}
	return builder.String()
}

func (source *textSource) hex(bytes int) string {
	buffer := make([]byte, bytes)
	for index := range buffer {
		buffer[index] = byte(source.rng.UintN(256))
	}
	return hex.EncodeToString(buffer)
}

// uuid returns a version-4 shaped identifier derived from the seed.
func (source *textSource) uuid() string {
	raw := source.hex(16)
	return raw[0:8] + "-" + raw[8:12] + "-4" + raw[13:16] + "-a" + raw[17:20] + "-" + raw[20:32]
}

// alnum returns n characters from a base62 alphabet, for provider-style ids.
func (source *textSource) alnum(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buffer := make([]byte, n)
	for index := range buffer {
		buffer[index] = alphabet[source.intn(len(alphabet))]
	}
	return string(buffer)
}

// splitDeltas cuts text into pieces of about size bytes on UTF-8 boundaries.
// Generated text is ASCII, so any byte offset is a boundary.
func splitDeltas(text string, size int) []string {
	if size <= 0 {
		size = 16
	}
	if text == "" {
		return nil
	}
	pieces := make([]string, 0, len(text)/size+1)
	for len(text) > size {
		pieces = append(pieces, text[:size])
		text = text[size:]
	}
	return append(pieces, text)
}
