package cmt

import (
	"encryption"
	"fmt"
)

func BitFlip(x byte, bitIndex uint8) byte { return x ^ (1 << bitIndex) }

func BitClear(x byte, bitIndex uint8) byte { return x &^ (1 << bitIndex) }

func BitGet(x byte, bitIndex uint8) bool { return x&(1<<bitIndex) != 0 }

func BitFlip1[t idx](x t, bitIndex uint8) t {
	byteIndex, bitIndexInTheByte := ByteAndBitIndex(bitIndex)
	x[byteIndex] = BitFlip(x[byteIndex], bitIndexInTheByte)
	return x
}

func BitClear1[t idx](x t, bitIndex uint8) t {
	byteIndex, bitIndexInTheByte := ByteAndBitIndex(bitIndex)
	x[byteIndex] = BitClear(x[byteIndex], bitIndexInTheByte)
	return x
}

func BitGet1[t idx](x t, bitIndex uint8) bool {
	byteIndex, bitIndexInTheByte := ByteAndBitIndex(bitIndex)
	return BitGet(x[byteIndex], bitIndexInTheByte)
}

func ByteAndBitIndex(bitIndex uint8) (uint8, uint8) {
	return bitIndex / 8, bitIndex % 8
}

// ////////////////////////////////////////////////////////////

type kv interface {
	Update(key KeyVector, value encryption.Sha256)
	Get(key KeyVector) (encryption.Sha256, bool)
	Delete(key KeyVector)
	GetAll() ([]KeyVector, []encryption.Sha256)
}

type idx interface {
	[1]byte | [2]byte | [3]byte | [4]byte | [5]byte | [6]byte | [7]byte | [8]byte | [9]byte | [10]byte | [11]byte | [12]byte | [13]byte | [14]byte | [15]byte | [16]byte | [17]byte | [18]byte | [19]byte | [20]byte | [21]byte | [22]byte | [23]byte | [24]byte | [25]byte | [26]byte | [27]byte | [28]byte | [29]byte | [30]byte | [31]byte
}

type (
	KeyVector []byte

	KeyStruct[t idx] struct {
		Hight uint8
		Index t
	}
)

func keySet[t idx](hight uint8, index t) KeyStruct[t] {
	return KeyStruct[t]{
		Hight: hight,
		Index: index,
	}
}

func keyEncoding[t idx](key KeyStruct[t]) KeyVector {
	h := len(key.Index)

	keyVector := make(KeyVector, h+1)
	keyVector[0] = key.Hight

	for i := 0; i < h; i++ {
		keyVector[i+1] = key.Index[i]
	}
	return keyVector
}

func keyDecoding[t idx](key KeyVector) KeyStruct[t] {
	return KeyStruct[t]{
		Hight: key[0],
		Index: t(key[1:]),
	}
}

func keyIsRight[t idx](key KeyStruct[t]) bool {
	return BitGet1(key.Index, key.Hight)
}

func keyGetChildKey[t idx](key KeyStruct[t]) (KeyStruct[t], KeyStruct[t]) {
	key.Hight--

	rightChild := key
	rightChild.Index = BitFlip1(rightChild.Index, rightChild.Hight)
	return key, rightChild
}

func keyGetSibleKey[t idx](key KeyStruct[t]) KeyStruct[t] {
	key.Index = BitFlip1(key.Index, key.Hight)
	return key
}

func keyGetParentKey[t idx](key KeyStruct[t]) KeyStruct[t] {
	key.Index = BitClear1(key.Index, key.Hight)
	key.Hight++
	return key
}

func keyGetSibleIfThere[t idx](kvf kv, key KeyStruct[t]) (encryption.Sha256, bool) {
	hash, ok := kvf.Get(keyEncoding(keyGetSibleKey(key)))
	if !ok {
		return encryption.Sha256{}, ok
	}
	return hash, ok
}

// ////////////////////////////////////////////////////////////

type (
	LeaveVector []byte

	LeaveStruct[t idx] struct {
		KeyStruct KeyStruct[t]
		Hash      encryption.Sha256
	}
)

func leaveEncoding[t idx](leave LeaveStruct[t]) LeaveVector {

	var leaveVector LeaveVector
	leaveVector = append(leaveVector, leave.Hash[:]...)
	leaveVector = append(leaveVector, leave.KeyStruct.Hight)

	var jj t
	x := len(jj)
	for i := 0; i < x; i++ {
		x := leave.KeyStruct.Index[i]
		leaveVector = append(leaveVector, x)
	}

	return leaveVector
}

func leaveDecoding[t idx](leave LeaveVector) LeaveStruct[t] {
	return LeaveStruct[t]{
		KeyStruct: KeyStruct[t]{
			Hight: leave[32],
			Index: t(leave[33:]),
		},
		Hash: encryption.Sha256(leave[0:32]),
	}
}

// ////////////////////////////////////////////////////////////

func merkleHight[t idx](index t) uint8 {
	return uint8(len(index)) * 8
}

func MerkleUpdate[t idx](kvf kv, index t, currentHash encryption.Sha256) {

	currentStruct := keySet(0, index)
	hight := merkleHight(index)
	for currentStruct.Hight < hight {

		// fmt.Printf("hight:%v\tindex:%08b\tleaf:%x\n", key.hight, key.index, leave)
		kvf.Update(keyEncoding(currentStruct), currentHash)

		currentHash = computeParentHash(kvf, currentStruct, currentHash)
		currentStruct = keyGetParentKey(currentStruct)
	}
	// fmt.Printf("hight:%v\tindex:%08b\tleaf:%x\n", key.hight, key.index, leave)
	kvf.Update(keyEncoding(currentStruct), currentHash)
}

func computeParentHash[t idx](kvf kv, currentStruct KeyStruct[t], currentHash encryption.Sha256) encryption.Sha256 {
	sibleHash, haveSible := keyGetSibleIfThere(kvf, currentStruct)
	isRight := keyIsRight(currentStruct)
	switch {
	case isRight && haveSible:
		return encryption.HashPair(sibleHash, currentHash)
	case isRight && !haveSible:
		return encryption.HashPair(currentHash, currentHash)
	case !isRight && haveSible:
		return encryption.HashPair(currentHash, sibleHash)
	case !isRight && !haveSible:
		return encryption.HashPair(currentHash, currentHash)
	}
	return encryption.Sha256{}
}

func MerkleDelete[t idx](kvf kv, index t) {

	currentStruct := keySet(0, index)
	kvf.Delete(keyEncoding(currentStruct))

	hight := merkleHight(index)
	for currentStruct.Hight < hight {
		currentStruct = keyGetParentKey(currentStruct)
		updateParent(kvf, currentStruct)
	}
}

func updateParent[t idx](kvf kv, parentStruct KeyStruct[t]) {
	parentVector := keyEncoding(parentStruct)

	leftStruct, rightStruct := keyGetChildKey(parentStruct)

	leftVector := keyEncoding(leftStruct)
	rightVector := keyEncoding(rightStruct)

	leftHash, haveLeftChild := kvf.Get(leftVector)
	rightHash, haveRightChild := kvf.Get(rightVector)

	switch {
	case haveLeftChild && haveRightChild:
		kvf.Update(parentVector, encryption.HashPair(leftHash, rightHash))
	case haveLeftChild && !haveRightChild:
		kvf.Update(parentVector, encryption.HashPair(leftHash, leftHash))
	case !haveLeftChild && haveRightChild:
		kvf.Update(parentVector, encryption.HashPair(rightHash, rightHash))
	case !haveLeftChild && !haveRightChild:
		kvf.Delete(parentVector)
	}
}

func MerkleRootKey[t idx]() KeyStruct[t] {
	var index t
	return keySet(merkleHight(index), index)
}

func MerkleRootGet[t idx](kvf kv) encryption.Sha256 {
	rootHash, ok := kvf.Get(keyEncoding(MerkleRootKey[t]()))
	if ok {
		return rootHash
	}
	return encryption.Sha256{}
}

func MerkleRootSet[t idx](kvf kv, rootHash encryption.Sha256) {
	kvf.Update(keyEncoding(MerkleRootKey[t]()), rootHash)
}

func MerkleProof[t idx](kvf kv, index t) ([]LeaveStruct[t], error) {

	var merkleProof []LeaveStruct[t]
	currentStruct := keySet(0, index)

	hight := merkleHight(index)
	for currentStruct.Hight < hight {

		if currentStruct.Hight == 0 {
			currentHash, ok := kvf.Get(keyEncoding(currentStruct))

			if !ok {
				return nil, fmt.Errorf("this %v index is not in merkle tree", currentStruct.Index)
			}

			merkleProof = append(merkleProof, LeaveStruct[t]{currentStruct, currentHash})
		}

		sibleStruct := keyGetSibleKey(currentStruct)
		sibleHash, ok := keyGetSibleIfThere(kvf, currentStruct)

		if !ok {
			currentHash, ok := kvf.Get(keyEncoding(currentStruct))

			if !ok {
				return nil, fmt.Errorf("this %v index is not in merkle tree", currentStruct.Index)
			}

			merkleProof = append(merkleProof, LeaveStruct[t]{sibleStruct, currentHash})
		} else {
			merkleProof = append(merkleProof, LeaveStruct[t]{sibleStruct, sibleHash})
		}

		// fmt.Printf("hight:%v\tindex:%08b\tleaf:%x\n", currentKey.hight, currentKey.index, sibleHash)
		currentStruct = keyGetParentKey(currentStruct)
	}

	return merkleProof, nil
}

func MerkleVerifi[t idx](proof []LeaveStruct[t], rootHash encryption.Sha256) bool {

	var currentStruct KeyStruct[t]
	var currentHash encryption.Sha256

	for i, v := range proof {

		switch i {
		case 0:
			currentStruct = v.KeyStruct
			currentHash = v.Hash
			continue
		default:
			sibleStruct := keyGetSibleKey(currentStruct)
			if sibleStruct.Hight != v.KeyStruct.Hight || sibleStruct.Index != v.KeyStruct.Index {
				return false
			}
		}
		// fmt.Printf("hight:%v\tindex:%08b\tleaf:%x\n", key.hight, key.index, leave)

		switch keyIsRight(currentStruct) {
		case true:
			currentHash = encryption.HashPair(v.Hash, currentHash)
		case false:
			currentHash = encryption.HashPair(currentHash, v.Hash)
		}

		if i != 0 {
			currentStruct = keyGetParentKey(currentStruct)
		}
	}

	// fmt.Printf("%x\t%x", leave, root)
	return currentHash == rootHash
}

func MerkleVerifiLeave[t idx](kvf kv, index t) bool {

	currentStruct := keySet(0, index)
	hight := merkleHight(index)

	currentHash, isExist := kvf.Get(keyEncoding(currentStruct))
	if !isExist {
		return false
	}

	for currentStruct.Hight < hight {

		parentHash1 := computeParentHash(kvf, currentStruct, currentHash)

		parentStruct := keyGetParentKey(currentStruct)
		parentHash2, isExist := kvf.Get(keyEncoding(parentStruct))

		if !isExist {
			return false
		}

		if parentHash1 != parentHash2 {
			return false
		}

		currentHash = parentHash1
		currentStruct = parentStruct
	}

	return true
}

func MerkleBullid[t idx](kvf kv, proof []LeaveStruct[t], rootHash encryption.Sha256) {
	if MerkleVerifi(proof, rootHash) {
		for _, i := range proof {
			kvf.Update(keyEncoding(i.KeyStruct), i.Hash)
		}
	}
}

func MerkleLeafKey[t idx](hash encryption.Sha256) KeyStruct[t] {
	return keySet(0, t(hash[:]))
}

func MerkleIsThisLeafExist[t idx](kvf kv, key KeyStruct[t]) bool {
	_, ok := kvf.Get(keyEncoding(key))
	return ok
}

func MerkleUpdateBatch[t idx](kvf kv, batch map[t]encryption.Sha256) {

	currentBatch := make(map[KeyStruct[t]]encryption.Sha256)
	nextBatch := make(map[KeyStruct[t]]encryption.Sha256)

	for index, currentHash := range batch {
		currentStruct := keySet(0, index)
		currentBatch[currentStruct] = currentHash
	}

	var index t
	hight := merkleHight(index)
	for i := uint8(0); i < hight; i++ {

		for currentStruct, currentHash := range currentBatch {
			kvf.Update(keyEncoding(currentStruct), currentHash)
		}

		for currentStruct, currentHash := range currentBatch {

			// fmt.Printf("hight:%v\n", key.Hight)

			currentHash = computeParentHash(kvf, currentStruct, currentHash)

			currentStruct = keyGetParentKey(currentStruct)
			nextBatch[currentStruct] = currentHash
		}

		currentBatch = nextBatch
		nextBatch = make(map[KeyStruct[t]]encryption.Sha256)
	}

	rootStruct := keySet(hight, index)
	kvf.Update(keyEncoding(rootStruct), currentBatch[rootStruct])
}

func MerkleDeleteBatch[t idx](kvf kv, batch map[t]bool) {
}
