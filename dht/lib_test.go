package main

import (
	"encryption"
	"reflect"
	"testing"
	"tools"
)

func Test1(t *testing.T) {
	a := MessageFormType{
		Nonce:     []uint8{0xf9, 0x3e, 0x27, 0xc5, 0x66, 0xe6, 0x59, 0x61},
		Message:   []uint8{0xf9, 0x3e, 0x27, 0xc5, 0x66, 0xe6, 0x59, 0x61},
		Signature: encryption.Signature{0xc2},
	}

	tools.Benchmark(100000,
		func() {
			a1, _ := tools.Encode(a)
			tools.Decode[MessageFormType](a1)
		},
		func() {
			a1 := MessageFormEncoding(a)
			MessageFormDecoding(a1)
		},
	)
}

func Test2(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := tools.Rand[MessageFormType]()
		if len(a.Nonce) != 8 {
			a.Nonce = []uint8{0xf9, 0x3e, 0x27, 0xc5, 0x66, 0xe6, 0x59, 0x61}
		}
		if a.Message == nil {
			a.Message = []byte{}
		}
		if a.Signature == nil {
			a.Signature = []byte{}
		}
		a1 := MessageFormEncoding(a)
		a2 := MessageFormDecoding(a1)
		tools.Test(false, true, "#v", a, a2)
	}
}

func Test(t *testing.T) {

	for i := 0; i < 100; i++ {

		original := tools.Rand[BatchType]()

		if reflect.DeepEqual(original.Batch, [][]uint8(nil)) {
			continue
		}
		original.Batch = Compact(original.Batch)

		encoded := BatchEncoding(original)
		decoded, err := BatchDecoding(encoded)
		tools.Test(false, true, "v", err, nil)
		tools.Test(false, true, "#v", decoded, original)
	}
}

func Compact(data [][]byte) [][]byte {
	var result [][]byte

	for _, slice := range data {
		if len(slice) == 0 || slice == nil {
			continue // Skip empty slices
		}

		result = append(result, slice)
	}

	return result
}
