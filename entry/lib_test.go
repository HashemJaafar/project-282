package entry

import (
	"fmt"
	"math"
	"testing"
	"tools"
)

func Test(t *testing.T) {
	indexSize := 8.0 * 4
	hashSize := 256.0
	hightSize := 8.0
	// merkleProofSize := ((hashSize + indexSize + hightSize) * indexSize) / 8
	// fmt.Println(merkleProofSize)

	merkleSize := 0.0
	for i := 0; i <= int(indexSize); i++ {
		merkleSize += (hashSize + indexSize + hightSize) * math.Pow(2, float64(i))
	}
	merkleSize += 512 * math.Pow(2, indexSize)

	fmt.Printf("%f\n", merkleSize/8000000000000)
	fmt.Printf("%f\n", (256*3)*math.Pow(2, indexSize)/8000000000000)
}

func Test0(t *testing.T) {
	for i := 0; i < 100; i++ {
		{
			a0 := tools.Rand[BalanceStruct]()
			a1 := BalanceEncoding(a0)
			a2 := BalanceDecoding(a1)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[BlockStruct]()
			a1 := BlockEncoding(a0)
			a2 := BlockDecoding(a1)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[EntryLeaveStruct]()
			a1 := EntryLeaveEncoding(a0)
			a2 := EntryLeaveDecoding(a1)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[BlockChainOfLeavesStruct]()
			a1 := BlockChainOfLeavesEncoding(a0)
			a2 := BlockChainOfLeavesDecoding(a1)
			tools.Test(false, true, "#v", a0, a2)
		}
	}
}

func Test1(t *testing.T) {
	for i := 0; i < 1000; i++ {
		x := tools.Rand[int64]()
		x0 := tools.NumberToBytes(x)
		x1 := tools.BytesToNumber[int64](x0)
		tools.Test(false, true, "v", x1, x)
	}
}

func Test2(t *testing.T) {
	for i := 0; i < 100; i++ {
		{
			a0 := tools.Rand[TokenState]()
			a1, err := tools.Encode(a0)
			tools.Test(false, true, "#v", err, nil)
			a2, err := tools.Decode[TokenState](a1)
			tools.Test(false, true, "#v", err, nil)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[TokenIdentity]()
			a1, err := tools.Encode(a0)
			tools.Test(false, true, "#v", err, nil)
			a2, err := tools.Decode[TokenIdentity](a1)
			tools.Test(false, true, "#v", err, nil)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[RobotState]()
			a1, err := tools.Encode(a0)
			tools.Test(false, true, "#v", err, nil)
			a2, err := tools.Decode[RobotState](a1)
			tools.Test(false, true, "#v", err, nil)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[RobotIdentity]()
			a1, err := tools.Encode(a0)
			tools.Test(false, true, "#v", err, nil)
			a2, err := tools.Decode[RobotIdentity](a1)
			tools.Test(false, true, "#v", err, nil)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[PersonState]()
			a1, err := tools.Encode(a0)
			tools.Test(false, true, "#v", err, nil)
			a2, err := tools.Decode[PersonState](a1)
			tools.Test(false, true, "#v", err, nil)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[PersonIdentity]()
			a1, err := tools.Encode(a0)
			tools.Test(false, true, "#v", err, nil)
			a2, err := tools.Decode[PersonIdentity](a1)
			tools.Test(false, true, "#v", err, nil)
			tools.Test(false, true, "#v", a0, a2)
		}
	}
}
