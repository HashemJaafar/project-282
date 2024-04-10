package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encryption"
	"errors"
	"fmt"
	"ht"
	"io"
	"math/big"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"
	"tools"
)

type (
	valueVector []byte

	valueStruct struct {
		NodeIdLockedForHim uint16
		Proposal           uint64
		value              []byte
	}
)

func valueEncoding(i valueStruct) valueVector {
	return valueVector(slices.Concat(
		tools.NumberToBytes(i.NodeIdLockedForHim),
		tools.NumberToBytes(i.Proposal),
		i.value))
}

func valueDecoding(i valueVector) valueStruct {
	return valueStruct{
		NodeIdLockedForHim: tools.BytesToNumber[uint16](i[0:2]),
		Proposal:           tools.BytesToNumber[uint64](i[2:10]),
		value:              i[10:],
	}
}

type (
	RequestVector []byte

	RequestStruct struct {
		Message   []byte
		Signature encryption.Signature
	}
)

func RequestEncoding(i RequestStruct) RequestVector {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(i.Message)))

	return RequestVector(slices.Concat(b, i.Message, i.Signature))
}

func RequestDecoding(i RequestVector) RequestStruct {
	theStartOfSig := binary.BigEndian.Uint32(i[:4]) + 4

	return RequestStruct{
		Message:   i[4:theStartOfSig],
		Signature: encryption.Signature(i[theStartOfSig:]),
	}
}

type nodeInfo struct {
	IPAddress            string
	NodeId               uint16 //no node his id is 0
	NumberOfVirtualNodes uint8
	PublicKey            rsa.PublicKey
	IsLive               bool
}

type nodeInfo1 struct {
	NodeId       uint16 //no node his id is 0
	VirtualNodes []big.Int
	PublicKey    rsa.PublicKey
	IsLive       bool
}

var maxNumberOfVirtualNodes uint8
var routingTable = make(map[string]nodeInfo1)
var myPrivetKey *rsa.PrivateKey

var leader = struct {
	IPAddress string
	PublicKey rsa.PublicKey
}{
	IPAddress: "",
	PublicKey: rsa.PublicKey{},
}

type DHT struct {
	methodes       methodes
	dbName         string
	isValueDynamic bool
	isKeyHashed    bool
}

type methodes interface {
	Open() error
	Close() error
	MessageEncoding(key []byte, value []byte) ([]byte, error)
	MessageDecoding(Message []byte) ([]byte, []byte, error)
	Put(key []byte, value []byte) error
	Get(key []byte) ([]byte, bool, error)
	Delete(key []byte) error
}

func UpdateRoutingTable(mux *http.ServeMux) {

	table, err := extractTheRoutingTable()
	tools.PanicIfErr(err)
	setRoutingTable(table)

	mux.HandleFunc("/update routing table", func(w http.ResponseWriter, req *http.Request) {

		if req.RemoteAddr != leader.IPAddress {
			http.Error(w, "you are not the leader", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		Request := RequestDecoding(req1)

		err = encryption.VerifiSignature(&leader.PublicKey, Request.Message, Request.Signature)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		table, err := tools.Decode[[]nodeInfo](Request.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = storeTheRoutingTable(table)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		setRoutingTable(table)
	})
}

func (s DHT) Open(mux *http.ServeMux) error {
	err := s.methodes.Open()
	if err != nil {
		return err
	}

	pattern := func(functionName string) string {
		return "/" + s.dbName + "/" + functionName
	}

	//////////////////////////////////////////////////////////////////////////////////
	if s.isValueDynamic {
		mux.HandleFunc(pattern("Unlock"), func(w http.ResponseWriter, req *http.Request) {

			IPAddress := req.RemoteAddr
			nodeInfo, ok := routingTable[IPAddress]

			if !ok {
				http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
				return
			}

			req1, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			Request := RequestDecoding(req1)

			err = encryption.VerifiSignature(&nodeInfo.PublicKey, Request.Message, Request.Signature)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			key, _, err := s.methodes.MessageDecoding(Request.Message)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			givenValueVector, isThere, err := s.methodes.Get(key)

			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if !isThere {
				http.Error(w, "the value is not exist", http.StatusBadRequest)
				return
			}

			givenValueStruct := valueDecoding(givenValueVector)

			if givenValueStruct.NodeIdLockedForHim != nodeInfo.NodeId {
				http.Error(w, "your nodeId is not same", http.StatusBadRequest)
				return
			}

			newGivenValueVector := valueEncoding(valueStruct{
				NodeIdLockedForHim: 0,
				Proposal:           givenValueStruct.Proposal,
				value:              givenValueStruct.value,
			})

			err = s.methodes.Put(key, newGivenValueVector)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		})
	}

	//////////////////////////////////////////////////////////////////////////////////
	mux.HandleFunc(pattern("Copy"), func(w http.ResponseWriter, req *http.Request) {})

	//////////////////////////////////////////////////////////////////////////////////
	mux.HandleFunc(pattern("Put"), func(w http.ResponseWriter, req *http.Request) {

		IPAddress := req.RemoteAddr
		nodeInfo, ok := routingTable[IPAddress]

		if !ok {
			http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		Request := RequestDecoding(req1)

		err = encryption.VerifiSignature(&nodeInfo.PublicKey, Request.Message, Request.Signature)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		key, receivedValueVector, err := s.methodes.MessageDecoding(Request.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if s.isValueDynamic {
			givenValueVector, isThere, err := s.methodes.Get(key)

			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if !isThere {
				goto l
			}

			givenValueStruct := valueDecoding(givenValueVector)
			receivedValueStruct := valueDecoding(receivedValueVector)

			if givenValueStruct.Proposal > receivedValueStruct.Proposal {
				http.Error(w, "your proposal is old", http.StatusBadRequest)
				return
			}
		}

	l:
		err = s.methodes.Put(key, receivedValueVector)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	//////////////////////////////////////////////////////////////////////////////////
	mux.HandleFunc(pattern("Get"), func(w http.ResponseWriter, req *http.Request) {

		IPAddress := req.RemoteAddr
		nodeInfo, ok := routingTable[IPAddress]

		if !ok {
			http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		Request := RequestDecoding(req1)

		err = encryption.VerifiSignature(&nodeInfo.PublicKey, Request.Message, Request.Signature)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		key, _, err := s.methodes.MessageDecoding(Request.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		givenValueVector, isThere, err := s.methodes.Get(key)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !isThere {
			http.Error(w, "the value is not exist", http.StatusBadRequest)
			return
		}

		if s.isValueDynamic {

			givenValueStruct := valueDecoding(givenValueVector)

			if givenValueStruct.NodeIdLockedForHim > nodeInfo.NodeId {
				http.Error(w, "your nodeId is smaller", http.StatusBadRequest)
				return
			}

			newGivenValueVector := valueEncoding(valueStruct{
				NodeIdLockedForHim: nodeInfo.NodeId,
				Proposal:           givenValueStruct.Proposal,
				value:              givenValueStruct.value,
			})

			err = s.methodes.Put(key, newGivenValueVector)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		w.Write(givenValueVector)
	})

	//////////////////////////////////////////////////////////////////////////////////
	mux.HandleFunc(pattern("Get What ever it takes"), func(w http.ResponseWriter, req *http.Request) {

		IPAddress := req.RemoteAddr
		nodeInfo, ok := routingTable[IPAddress]

		if !ok {
			http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		Request := RequestDecoding(req1)

		err = encryption.VerifiSignature(&nodeInfo.PublicKey, Request.Message, Request.Signature)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		key, _, err := s.methodes.MessageDecoding(Request.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		givenValueVector, isThere, err := s.methodes.Get(key)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if !isThere {
			http.Error(w, "the value is not exist", http.StatusBadRequest)
			return
		}

		w.Write(givenValueVector)
	})

	return nil
}

func (s DHT) Close() error {
	return nil
}

func (s DHT) Copy() error {
	return nil
}

// var Unlock = create(IPAddress, Port,)
// var Put = create(IPAddress, Port,)
// var Get = create(IPAddress, Port,)
// var Delete = create(IPAddress, Port,)

func FindNearestNodes(key []byte) []string {
	var address []string
	keyAsInt := big.NewInt(256)
	keyAsInt.SetBytes(key)

	for i := 0; i < int(maxNumberOfVirtualNodes); i++ {

		var closestIPAddress string
		diff := big.NewInt(256)

		for IPAddress, info := range routingTable {
			if len(info.VirtualNodes) < i+1 {
				currentDiff := big.NewInt(256)
				currentDiff.Sub(&info.VirtualNodes[i], keyAsInt)
				currentDiff.Abs(currentDiff)

				if currentDiff.Cmp(diff) == -1 {
					closestIPAddress = IPAddress
					diff = currentDiff
				}
			}
		}

		address = append(address, closestIPAddress)
	}
	return address
}

func VerifiIfITheNearest(nodeId uint16, key []byte) bool {
	return false
}

func setRoutingTable(table []nodeInfo) {
	routingTable = make(map[string]nodeInfo1, len(table))
	for _, v := range table {

		if v.NumberOfVirtualNodes > maxNumberOfVirtualNodes {
			maxNumberOfVirtualNodes = v.NumberOfVirtualNodes
		}

		VirtualNodes := make([]big.Int, v.NumberOfVirtualNodes)

		numberAsBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(numberAsBytes, v.NodeId)

		for i := uint8(0); i < v.NumberOfVirtualNodes; i++ {

			numberAsHash := sha256.Sum256(numberAsBytes)
			numberAsBytes = numberAsHash[:]

			numberAsInt := big.NewInt(256)
			numberAsInt.SetBytes(numberAsBytes)
			VirtualNodes[i].Abs(numberAsInt)
		}

		info := nodeInfo1{
			NodeId:       v.NodeId,
			VirtualNodes: VirtualNodes,
			PublicKey:    v.PublicKey,
			IsLive:       v.IsLive,
		}

		routingTable[v.IPAddress] = info
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////

func storeStructToJSON(data any, filename string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Write the JSON data to a file
	err = os.WriteFile(filename, jsonData, 0644) // Adjust permissions as needed
	if err != nil {
		return err
	}

	return nil
}

func readJSONFile[t any](filename string) (t, error) {
	var myType t

	data, err := os.ReadFile(filename) // Use os.ReadFile instead of ioutil.ReadFile
	if err != nil {
		return myType, err
	}

	err = json.Unmarshal(data, &myType) // Pass address of the struct
	if err != nil {
		return myType, err
	}

	return myType, nil
}

func storeTheRoutingTable(table []nodeInfo) error {
	return storeStructToJSON(table, "RoutingTable")
}

func extractTheRoutingTable() ([]nodeInfo, error) {
	return readJSONFile[[]nodeInfo]("RoutingTable")
}

/////////////////////////////////////////////////////////////////////////////////////////////

func (s DHT) NewRequest(key []byte, value []byte) *bytes.Reader {
	message, err := s.methodes.MessageEncoding(key, value)
	tools.PanicIfErr(err)

	Signature, err := encryption.CreateSignature(myPrivetKey, message)
	tools.PanicIfErr(err)

	return bytes.NewReader(RequestEncoding(RequestStruct{message, Signature}))
}

func DoRequestToIP(IPAddress string, body *bytes.Reader) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, IPAddress, body)
	if err != nil {
		return nil, err
	}

	client := http.Client{Timeout: 60 * time.Second}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	resBodyByte, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s%v", resBodyByte, res.Status)
	}

	return resBodyByte, nil
}

type ssssssssss struct {
	hundle     func(mux *http.ServeMux)
	requestAll func(key []byte, value []byte) ([][]byte, error)
}

func create(s DHT, IPAddress string, port uint, pattern string, process func(w http.ResponseWriter, req *http.Request, nodeInfo nodeInfo1, key []byte, value []byte)) ssssssssss {
	jj := ssssssssss{}

	url := ht.Url(IPAddress, port, s.dbName, pattern)

	jj.hundle = func(mux *http.ServeMux) {
		mux.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
			nodeInfo, ok := routingTable[r.RemoteAddr]

			if !ok {
				http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
				return
			}

			req1, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			Request := RequestDecoding(req1)

			err = encryption.VerifiSignature(&nodeInfo.PublicKey, Request.Message, Request.Signature)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			key, value, err := s.methodes.MessageDecoding(Request.Message)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			process(w, r, nodeInfo, key, value)
		})
	}

	jj.requestAll = func(key []byte, value []byte) ([][]byte, error) {
		body := s.NewRequest(key, value)
		allIPAddress := FindNearestNodes(key)

		var AllError error
		var value1 []byte

		var wait sync.WaitGroup
		for _, v := range allIPAddress {
			wait.Add(1)
			go func() {
				var err error
				value1, err = DoRequestToIP(ht.Url(v, port, s.dbName, pattern), body)
				errors.Join(AllError, err)

				if err == nil {

				}
				wait.Done()
			}()
		}
		wait.Wait()
		return nil, AllError
	}

	return jj
}

type (
	IPAddress            string
	NodeId               uint16 //no node his id is 0
	NumberOfVirtualNodes uint8
	Key                  []byte
	Value                []byte
	Message              []byte
	KeyHash              [32]byte
)
