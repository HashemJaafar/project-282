package cmt

import (
	"crypto/rand"
	"determinants"
	"encryption"
	database "my_database"
	"testing"
	"tools"
)

var db database.DB

type s struct{}

func (s) Update(key KeyVector, value encryption.Sha256) {
	database.Update(db, key, value[:])
}

func (s) Get(key KeyVector) (encryption.Sha256, bool) {
	hash, err := database.Get(db, key[:])
	if err != nil {
		return encryption.Sha256{}, false
	}
	return encryption.Sha256(hash), true
}

func (s) Delete(key KeyVector) {
	database.Delete(db, key)
}

func (s) GetAll() ([]KeyVector, []encryption.Sha256) {
	return nil, nil
}

func Test0(t *testing.T) {
	database.Open(&db, determinants.DBPath("merkleTree"))
	defer db.Close()
	db.DropAll()

	type myType = [31]byte

	indexList := make(map[myType]encryption.Sha256)

	for i := 0; i < 100; i++ {
		index := myType{}
		rand.Read(index[:])

		hash := encryption.Sha256{}
		rand.Read(hash[:])

		indexList[index] = hash
	}

	for index, hash := range indexList {
		merkleroot := MerkleRootGet[myType](s{})

		MerkleUpdate(s{}, index, hash)

		merkleProof, err := MerkleProof(s{}, index)
		tools.Test(false, true, "#v", err, nil)

		merkleroot1 := MerkleRootGet[myType](s{})
		isCorrect := MerkleVerifi(merkleProof, merkleroot1)
		tools.Test(false, true, "#v", isCorrect, true)

		MerkleDelete(s{}, index)
		merkleroot2 := MerkleRootGet[myType](s{})
		tools.Test(false, true, "x", merkleroot, merkleroot2)

		MerkleUpdate(s{}, index, hash)
	}

	for index, _ := range indexList {
		tools.Test(false, true, "v", MerkleVerifiLeave(s{}, index), true)
	}

	lastRoot := MerkleRootGet[myType](s{})

	db.DropAll()

	MerkleUpdateBatch(s{}, indexList)
	tools.Test(false, true, "x", MerkleRootGet[myType](s{}), lastRoot)

	for index, _ := range indexList {
		tools.Test(false, true, "v", MerkleVerifiLeave(s{}, index), true)
	}

}

func Test1(t *testing.T) {
	for i := 0; i < 100; i++ {
		{
			a0 := tools.Rand[KeyStruct[[16]byte]]()
			a1 := keyEncoding(a0)
			a2 := keyDecoding[[16]byte](a1)
			tools.Test(false, true, "#v", a0, a2)
		}
		{
			a0 := tools.Rand[LeaveStruct[[16]byte]]()
			a1 := leaveEncoding(a0)
			a2 := leaveDecoding[[16]byte](a1)
			tools.Test(false, true, "#v", a0, a2)
		}
	}
}

func Test2(t *testing.T) {
	for i := 0; i < 100; i++ {
		x := keySet(0, tools.Rand[[31]byte]())

		for x.Hight < merkleHight(x.Index) {

			x1 := keyGetSibleKey(x)
			tools.Test(false, true, "08b", keyGetParentKey(x), keyGetParentKey(x1))

			x = keyGetParentKey(x)
		}
	}
}

func Test3(t *testing.T) {
	for i := 0; i < 50; i++ {
		x := keySet(0, tools.Rand[[31]byte]())

		for x.Hight < merkleHight(x.Index) {
			x = keyGetParentKey(x)

			left, right := keyGetChildKey(x)

			tools.Test(false, true, "v", false, keyIsRight(left))
			tools.Test(false, true, "v", true, keyIsRight(right))

			tools.Test(false, true, "08b", x, keyGetParentKey(left))
			tools.Test(false, true, "08b", x, keyGetParentKey(right))
			tools.Test(false, true, "08b", left, keyGetSibleKey(right))

		}
	}
}

type myType0 = [5]byte

var db0 = make(map[myType0]encryption.Sha256)

type s0 struct{}

func (s0) Update(key KeyVector, value encryption.Sha256) {
	db0[myType0(key)] = value
}

func (s0) Get(key KeyVector) (encryption.Sha256, bool) {
	hash, ok := db0[myType0(key)]
	if !ok {
		return encryption.Sha256{}, false
	}
	return encryption.Sha256(hash), true
}

func (s0) Delete(key KeyVector) {
	delete(db0, myType0(key))
}

func (s0) GetAll() ([]KeyVector, []encryption.Sha256) {
	return nil, nil
}

func Test4(t *testing.T) {
	indexList := make(map[myType0]encryption.Sha256)

	for i := 0; i < 500000; i++ {
		hash := encryption.Sha256{}
		rand.Read(hash[:])

		indexList[myType0(hash[:])] = hash
	}

	tools.Benchmark(1, func() {
		MerkleUpdateBatch(s0{}, indexList)
	})
}
