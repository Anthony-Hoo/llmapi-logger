package protofixture

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"math/rand/v2"
)

// TinyPNG returns a valid, deterministic PNG of size x size pixels whose
// colours derive from seed. The encoder output is stable for a given image, so
// the same seed always yields the same bytes.
func TinyPNG(seed uint64, size int) []byte {
	if size <= 0 {
		size = 4
	}
	rng := rand.New(rand.NewPCG(seed, 0x706e67))
	picture := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := range size {
		for x := range size {
			picture.SetNRGBA(x, y, color.NRGBA{
				R: uint8(rng.UintN(256)), G: uint8(rng.UintN(256)), B: uint8(rng.UintN(256)), A: 255,
			})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, picture); err != nil {
		// png.Encode only fails on writer errors; bytes.Buffer never fails.
		panic(err)
	}
	return buffer.Bytes()
}

func base64PNG(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func dataURLPNG(data []byte) string { return "data:image/png;base64," + base64PNG(data) }
