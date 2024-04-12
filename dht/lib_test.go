package main

import (
	"fmt"
	"testing"
	"tools"
)

func permute[T any](list []T) [][]T {
	numberOfElements := len(list)
	if numberOfElements == 0 {
		return nil
	}

	var permutations [][]T
	permuteHelper(list, []T{}, &permutations)
	return permutations
}

func permuteHelper[T any](remaining []T, chosen []T, permutations *[][]T) {
	if len(remaining) == 0 {
		*permutations = append(*permutations, append([]T{}, chosen...))
		return
	}

	for i := range remaining {
		chosenCopy := append([]T{}, chosen...)
		chosenCopy = append(chosenCopy, remaining[i])
		remainingCopy := append([]T{}, remaining[:i]...)
		remainingCopy = append(remainingCopy, remaining[i+1:]...)
		permuteHelper(remainingCopy, chosenCopy, permutations)
	}
}

func Test(t *testing.T) {
	elements := []string{}

	for _, v1 := range []string{"get s", "get r", "put s", "put r"} {
		for _, v2 := range []string{"n1", "n2"} {
			for _, v3 := range []string{"s1", "s2"} {
				elements = append(elements, fmt.Sprintf("(%v %v-%v)", v1, v2, v3))
			}
		}
	}

	for _, v := range elements {
		fmt.Println(v)
	}
	// permutations := permute(elements)

	// for i, perm := range permutations {
	// 	fmt.Println("Permutation:", i+1)
	// 	fmt.Println(perm)

	// 	// for i, v := range perm {
	// 	// kkk := true
	// 	// for i1 := i; i1 > -1; i1-- {
	// 	// 	if v[0] < perm[i1][0] && v[1] == perm[i1][1] {
	// 	// 		kkk = false
	// 	// 	}
	// 	// }
	// 	// fmt.Println(v, kkk)
	// 	// }
	// }
}

func subtractUsingBitwise(x, y uint64) uint64 {
	for y != 0 {
		// Step 1: Get the borrow bit
		borrow := ^x & y // Invert x and AND with y to get carry bits

		// Step 2: Get the difference using XOR
		x ^= y // XOR x and y to get the difference without carry

		// Step 3: Left shift borrow by 1
		y = borrow << 1 // Left shift borrow to prepare for next iteration
	}
	return x
}

func subtractUsingBitwise1(x, y [8]byte) [8]byte {
	for y != [8]byte{} {
		borrow := [8]byte{}
		for i := 0; i < 8; i++ {
			// Step 1: Get the borrow bit
			borrow[i] = ^x[i] & y[i] // Invert x and AND with y to get carry bits

			// Step 2: Get the difference using XOR
			x[i] ^= y[i] // XOR x and y to get the difference without carry

			// Step 3: Left shift borrow by 1
			y[i] = borrow[i] << 1 // Left shift borrow to prepare for next iteration
		}

	}
	return x
}

func Test0(t *testing.T) {
	for i := 0; i < 10000; i++ {
		var x uint64 = tools.Rand[uint64]()
		var y uint64 = tools.Rand[uint64]()
		tools.Test(false, true, "08b", x-y, subtractUsingBitwise(x, y))

		x1 := [8]byte(tools.NumberToBytes(x))
		y1 := [8]byte(tools.NumberToBytes(y))
		x2 := subtractUsingBitwise1(x1, y1)
		tools.Test(false, true, "08b", [8]byte(tools.NumberToBytes(x-y)), x2)
	}
}

func Test1(t *testing.T) {
	// a := RequestStruct{
	// 	Message:   []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	// 	Signature: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	// }
	a := tools.Rand[MessageStruct]()
	tools.Benchmark(100000,
		func() {
			// a := tools.Rand[RequestStruct]()
			a1, _ := tools.Encode(a)
			tools.Decode[MessageStruct](a1)
		},
		func() {
			// a := tools.Rand[RequestStruct]()
			a1 := MessageEncoding(a)
			MessageDecoding(a1)
		},
	)
}

func Test2(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := tools.Rand[MessageStruct]()
		if a.KeyValue == nil {
			a.KeyValue = []byte{}
		}
		if a.Signature == nil {
			a.Signature = []byte{}
		}
		a1 := MessageEncoding(a)
		a2 := MessageDecoding(a1)
		tools.Test(false, true, "#v", a, a2)
	}
}
