package entry

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"tools"

	"encryption"
)

type (
	Nonce                        uint64 // help to prevent replay attack
	Quantity                     float64
	Value                        float64
	LastUpdate                   int64
	IdentityData                 []byte
	StateData                    []byte
	RobotAndPersonAddress        encryption.Sha256
	LastHashOfBlockChainOfLeaves encryption.Sha256 // hashPair(lastHashOfBlockChainOfLeaves,leave)
	Status                       byte              // help to know if ok or in black list or yellow list
	LastProposal                 uint64            // this help to consenses
	UnixTime                     int64             // time in unix in millisecond
)

type (
	TokenAddress encryption.Sha256

	TokenIdentity struct {
		NeedTheTotalSupply bool // if he dont need the total then the token will be fast and parallel update
		CodeForStateData   []byte
		CodeForContract    []byte
		IdentityData
		Author
	}

	TokenState struct {
		Status
		LastProposal
		LastUpdate
		LastHashOfBlockChainOfLeaves
		Balance []RobotAndPersonAddress
		StateData
	}
)

type (
	RobotAddress encryption.Sha256

	RobotIdentity struct {
		CodeForStateData []byte
		CodeForContract  []byte
		IdentityData
		Author
	}

	RobotState struct {
		Status
		LastProposal
		LastUpdate
		LastHashOfBlockChainOfLeaves
		Balance []TokenAddress
		StateData
	}
)

type (
	PersonAddress encryption.Sha256

	PersonIdentity rsa.PublicKey

	PersonState struct {
		Status
		LastProposal
		LastUpdate
		LastHashOfBlockChainOfLeaves
		Balance []TokenAddress
		Nonce
		DeleyedNonce []Nonce
	}
)

type (
	AccountingSingle struct {
		TokenAddress
		Quantity
		Value
	}

	AccountingDouble struct {
		RobotAndPersonAddress RobotAndPersonAddress
		DoubleEntry           []AccountingSingle
	}

	AccountingTriple []AccountingDouble
)

type (
	EntryContract struct {
		RobotAndPersonAddresses []encryption.Sha256
		AccountingTriple        []AccountingTriple
		Notes                   []byte
		WriterAddress           PersonAddress
		Signatures              []Signature
	}

	EntryStateData struct {
		TokenAndRobotAddresses []encryption.Sha256
		StateData
		WriterAddress PersonAddress
		Signatures    []Signature
	}

	EntryHoldNonce struct {
		Add bool
		Signature
	}
)

type CompletedEntry struct {
	Entry []byte
	Fee   AccountingTriple
	UnixTime
}

type Signature struct {
	Nonce
	PersonAddress
	encryption.Signature
}

type Author struct {
	rsa.PublicKey
	encryption.Signature
}

type Identities struct {
	TokenIdentity  []TokenIdentity
	RobotIdentity  []RobotIdentity
	PersonIdentity []PersonIdentity
}

// ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type (
	BalanceAddress encryption.Sha256 // this is hashPair(RobotAndPersonAddress,TokenAddress) or just TokenAddress if it is the TotalSupply

	BalanceVector [25]byte

	BalanceStruct struct {
		Status
		LastProposal
		Quantity
		Value
	}
)

func BalanceEncoding(i BalanceStruct) BalanceVector {
	return BalanceVector(slices.Concat(
		[]byte{byte(i.Status)},
		tools.NumberToBytes(i.LastProposal),
		tools.NumberToBytes(i.Quantity),
		tools.NumberToBytes(i.Value)))
}

func BalanceDecoding(i BalanceVector) BalanceStruct {
	return BalanceStruct{
		Status:       Status(i[0]),
		LastProposal: LastProposal(binary.BigEndian.Uint64(i[1:9])),
		Quantity:     tools.BytesToNumber[Quantity](i[9:17]),
		Value:        tools.BytesToNumber[Value](i[17:25]),
	}
}

type (
	BlockVector [105]byte

	BlockStruct struct {
		PreviousBlock encryption.Sha256
		TxnRoot       encryption.Sha256
		StateRoot     encryption.Sha256
		UnixTime
		CheckPoint bool
	}
)

func BlockEncoding(i BlockStruct) BlockVector {
	return BlockVector(slices.Concat(
		i.PreviousBlock[:],
		i.TxnRoot[:],
		i.StateRoot[:],
		tools.Uint64ToBytes(uint64(i.UnixTime)),
		[]byte{tools.BoolToByteBitMask(i.CheckPoint)},
	))
}

func BlockDecoding(i BlockVector) BlockStruct {
	return BlockStruct{
		PreviousBlock: encryption.Sha256(i[0:32]),
		TxnRoot:       encryption.Sha256(i[32:64]),
		StateRoot:     encryption.Sha256(i[64:96]),
		UnixTime:      UnixTime(binary.BigEndian.Uint64((i[96:104]))),
		CheckPoint:    tools.ByteToBoolBitMask(i[104]),
	}
}

type (
	EntryLeaveVector [64]byte

	EntryLeaveStruct struct {
		Entry          encryption.Sha256
		ContractAndFee encryption.Sha256
	}
)

func EntryLeaveEncoding(i EntryLeaveStruct) EntryLeaveVector {
	return EntryLeaveVector(append(i.Entry[:], i.ContractAndFee[:]...))
}

func EntryLeaveDecoding(i EntryLeaveVector) EntryLeaveStruct {
	return EntryLeaveStruct{
		Entry:          encryption.Sha256(i[:32]),
		ContractAndFee: encryption.Sha256(i[32:]),
	}
}

type (
	BlockChainOfLeavesVector [64]byte

	BlockChainOfLeavesStruct struct {
		PreviosBlock encryption.Sha256
		Leave        encryption.Sha256
	}
)

func BlockChainOfLeavesEncoding(i BlockChainOfLeavesStruct) BlockChainOfLeavesVector {
	return BlockChainOfLeavesVector(append(i.PreviosBlock[:], i.Leave[:]...))
}

func BlockChainOfLeavesDecoding(i BlockChainOfLeavesVector) BlockChainOfLeavesStruct {
	return BlockChainOfLeavesStruct{
		PreviosBlock: encryption.Sha256(i[:32]),
		Leave:        encryption.Sha256(i[32:]),
	}
}

func CreateAddress(Identity []byte) encryption.Sha256 {
	return sha256.Sum256(Identity)
}

func MakeOfflineAccountingCheck(tripleEntry AccountingTriple) error {
	length := len(tripleEntry)

	if length < 1 || length > 2 {
		return errors.New("should be one or two person")
	}

	var person0 RobotAndPersonAddress
	var person1 RobotAndPersonAddress
	var value0 Value
	var value1 Value
	var absValue0 Value
	var absValue1 Value

	for personIndex, doubleEntry := range tripleEntry {

		tokens := make(map[TokenAddress]bool)

		for _, singleEntry := range doubleEntry.DoubleEntry {
			if tokens[singleEntry.TokenAddress] {
				return errors.New("this token is replayed")
			}

			if singleEntry.Quantity == 0 && singleEntry.Value == 0 {
				return errors.New("both Quantity and Value are zero")
			}

			if (singleEntry.Quantity > 0) != (singleEntry.Value > 0) {
				return errors.New("the sign of Quantity should equal the sign of Value")
			}

			tokens[singleEntry.TokenAddress] = true

			switch personIndex {
			case 0:
				person0 = doubleEntry.RobotAndPersonAddress
				value0 += singleEntry.Value
				absValue0 += Value(math.Abs(float64(singleEntry.Value)))
			case 1:
				person1 = doubleEntry.RobotAndPersonAddress
				value1 += singleEntry.Value
				absValue1 += Value(math.Abs(float64(singleEntry.Value)))
			}
		}
	}

	if value0 != 0 {
		return fmt.Errorf("the RobotAndPersonAddress:%v have total value=%v and this is not equal to zero", person0, value0)
	}

	if value1 != 0 {
		return fmt.Errorf("the RobotAndPersonAddress:%v have total value=%v and this is not equal to zero", person1, value1)
	}

	if length == 2 && absValue0 != absValue1 {
		return fmt.Errorf("the first RobotAndPersonAddress:%v have total absolute value=%v and second RobotAndPersonAddress:%v have total absolute value=%v and the difference is %v and this is not equally", person0, absValue0, person1, absValue1, math.Abs(float64(absValue0-absValue1)))
	}

	return nil
}
