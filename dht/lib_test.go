package main

import (
	"ht"
	"net/http"
	"testing"
	"tools"
)

func Test(t *testing.T) {
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

var ma1 map[string]string

type m1 struct{}

func (m1) Open() error {
	ma1 = make(map[string]string)
	return nil
}

func (m1) Close() error {
	return nil
}

func (m1) Loop(i func(key Key, value valueLineVector)) error {
	for k, v := range ma1 {
		i(Key(k), valueLineVector(v))
	}
	return nil
}

func (m1) Put(key []byte, value []byte) error {
	ma1[string(key)] = string(value)
	return nil
}

func (m1) Get(key []byte) ([]byte, bool, error) {
	value, ok := ma1[string(key)]
	return []byte(value), ok, nil
}

func (m1) Delete(key []byte) error {
	delete(ma1, string(key))
	return nil
}

func Test1(t *testing.T) {
	a := DHT{
		methodes:         m1{},
		dbName:           "hi",
		isValueUpdatable: true,
	}

	mux := http.NewServeMux()
	Open(a, mux)
	ht.ListenAndServe(mux)
}
