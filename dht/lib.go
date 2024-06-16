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
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"slices"
	"time"
	"tools"
)

type (
	Proposal             uint64
	IPAddress            string
	NodeId               uint16 // should not use 0
	NumberOfVirtualNodes uint8
	Key                  []byte
	Value                []byte
	Message              []byte
	KeyHash              [32]byte
)

type (
	valueLineVector []byte

	valueLineType struct {
		NodeIdLockedForHim NodeId // 0 mean not locked
		Proposal           Proposal
		value              Value
	}
)

func valueLineEncoding(i valueLineType) valueLineVector {
	return valueLineVector(slices.Concat(
		tools.NumberToBytes(i.NodeIdLockedForHim),
		tools.NumberToBytes(i.Proposal),
		i.value))
}

func valueLineDecoding(i valueLineVector) valueLineType {
	return valueLineType{
		NodeIdLockedForHim: tools.BytesToNumber[NodeId](i[0:2]),
		Proposal:           tools.BytesToNumber[Proposal](i[2:10]),
		value:              Value(i[10:]),
	}
}

type (
	KeyValueLineVector []byte

	KeyValueLineType struct {
		Key   Key
		Value valueLineVector
	}
)

func KeyValueLineEncoding(i KeyValueLineType) KeyValueLineVector {
	KeySize := make([]byte, 4)
	binary.BigEndian.PutUint32(KeySize, uint32(len(i.Key)))

	return KeyValueLineVector(slices.Concat(KeySize, i.Key, []byte(i.Value)))
}

func KeyValueLineDecoding(i KeyValueLineVector) KeyValueLineType {
	KeySize := binary.BigEndian.Uint32(i[:4])

	return KeyValueLineType{
		Key:   Key(i[4 : 4+KeySize]),
		Value: valueLineVector(i[4+KeySize:]),
	}
}

type (
	MessageFormVector []byte

	MessageFormType struct {
		Nonce     []byte //8 byte
		Message   Message
		Signature encryption.Signature
	}
)

func MessageFormEncoding(i MessageFormType) MessageFormVector {
	KeySize := make([]byte, 4)
	binary.BigEndian.PutUint32(KeySize, uint32(len(i.Message)))

	return MessageFormVector(slices.Concat(KeySize, i.Nonce, []byte(i.Message), i.Signature))
}

func MessageFormDecoding(i MessageFormVector) MessageFormType {
	MessageSize := binary.BigEndian.Uint32(i[:4])

	const prefix uint32 = 4

	var (
		NonceByte     []byte = i[prefix:12]
		MessageByte   []byte = i[prefix+8 : prefix+8+MessageSize]
		SignatureByte []byte = i[prefix+8+MessageSize:]
	)

	return MessageFormType{
		Nonce:     NonceByte,
		Message:   MessageByte,
		Signature: encryption.Signature(SignatureByte),
	}
}

func MessageFormSign(privateKey *rsa.PrivateKey, i MessageFormType) MessageFormType {
	Signature, err := encryption.CreateSignature(privateKey, append(i.Nonce, i.Message...))
	tools.PanicIfErr(err)

	i.Signature = Signature
	return i
}

func MessageFormVerifi(publicKey *rsa.PublicKey, i MessageFormType) error {
	err := encryption.VerifiSignature(publicKey, append(i.Nonce, i.Message...), i.Signature)
	if err != nil {
		return err
	}
	return nil
}

type nodeInfo struct {
	IPAddress            IPAddress
	NodeId               NodeId // should not use 0
	NumberOfVirtualNodes uint8
	PublicKey            rsa.PublicKey
	IsLive               bool
}

type nodeInfo1 struct {
	NodeId       NodeId // should not use 0
	VirtualNodes []big.Int
	PublicKey    rsa.PublicKey
	IsLive       bool
}

var maxNumberOfVirtualNodes uint8
var routingTable = make(map[IPAddress]nodeInfo1)
var myPrivetKey *rsa.PrivateKey
var leaderIPAddress IPAddress
var leaderPublicKey rsa.PublicKey

type DHT struct {
	methodes         methodes
	dbName           string
	isValueUpdatable bool // if no that mean key==hash(value)
}

type methodes interface {
	Open() error
	Close() error
	Loop(func(key Key, value valueLineVector)) error
	Put(key []byte, value []byte) error
	Get(key []byte) ([]byte, bool, error)
	Delete(key []byte) error
}

func UpdateRoutingTable(mux *http.ServeMux) {

	table, err := readTheRoutingTable()
	tools.PanicIfErr(err)
	setRoutingTable(table)

	mux.HandleFunc("/UpdateRoutingTable", func(w http.ResponseWriter, req *http.Request) {

		if IPAddress(req.RemoteAddr) != leaderIPAddress {
			http.Error(w, "you are not the leader", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		message := MessageFormDecoding(body)

		err = MessageFormVerifi(&leaderPublicKey, message)
		if err != nil {
			httpError(w, message, err.Error())
			return
		}

		table, err := tools.Decode[[]nodeInfo](message.Message)
		if err != nil {
			httpError(w, message, err.Error())
			return
		}

		err = storeTheRoutingTable(table)
		if err != nil {
			httpError(w, message, err.Error())
			return
		}

		setRoutingTable(table)

		write(w, message, []byte("done"))
	})
}

func Open(s DHT, mux *http.ServeMux) error {
	err := s.methodes.Open()
	if err != nil {
		return err
	}

	pattern := func(functionName string) string {
		return "/" + s.dbName + "/" + functionName
	}

	//share data
	go func() {
		// Create a log file
		file, err := os.OpenFile("log.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %s", err)
		}
		defer file.Close()

		// Set output of logs to the file
		log.SetOutput(file)
		for {
			s.methodes.Loop(func(key Key, value valueLineVector) {
				_, err := requestAll("share", key, value)
				if err != nil {
					log.Println(err)
				}
			})
		}
	}()

	mux.HandleFunc(pattern("share"), func(w http.ResponseWriter, req *http.Request) {

		nodeInfo, ok := routingTable[IPAddress(req.RemoteAddr)]
		if !ok {
			http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		message := MessageFormDecoding(req1)

		err = MessageFormVerifi(&nodeInfo.PublicKey, message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		KeyValueLineType := KeyValueLineDecoding(KeyValueLineVector(message.Message))

		if s.isValueUpdatable {
			ValueLineVector1, isThere, err := s.methodes.Get(KeyValueLineType.Key)

			if err != nil {
				httpError(w, message, err.Error())
				return
			}

			if !isThere {
				goto l
			}

			ValueLineType1 := valueLineDecoding(ValueLineVector1)
			receivedValueType := valueLineDecoding(KeyValueLineType.Value)

			if ValueLineType1.Proposal > receivedValueType.Proposal {
				httpError(w, message, "your proposal is old")
				return
			}
		} else {
			x := sha256.Sum256(KeyValueLineType.Value)
			KeyValueLineType.Key = x[:]
		}

	l:
		err = s.methodes.Put(KeyValueLineType.Key, KeyValueLineType.Value)
		if err != nil {
			httpError(w, message, err.Error())
			return
		}
	})

	if s.isValueUpdatable {
		mux.HandleFunc(pattern("Unlock"), func(w http.ResponseWriter, req *http.Request) {

			nodeInfo, ok := routingTable[IPAddress(req.RemoteAddr)]
			if !ok {
				http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
				return
			}

			req1, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			message := MessageFormDecoding(req1)

			err = MessageFormVerifi(&nodeInfo.PublicKey, message)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			KeyValueLineType := KeyValueLineDecoding(KeyValueLineVector(message.Message))
			ValueLineVector1, isThere, err := s.methodes.Get(KeyValueLineType.Key)

			if err != nil {
				httpError(w, message, err.Error())
				return
			}

			if !isThere {
				httpError(w, message, "the value is not exist")
				return
			}

			ValueLineType1 := valueLineDecoding(ValueLineVector1)

			if ValueLineType1.NodeIdLockedForHim != nodeInfo.NodeId {
				httpError(w, message, "your nodeId is not same")
				return
			}

			ValueLineVector2 := valueLineEncoding(valueLineType{
				NodeIdLockedForHim: 0,
				Proposal:           ValueLineType1.Proposal,
				value:              ValueLineType1.value,
			})

			err = s.methodes.Put(KeyValueLineType.Key, ValueLineVector2)
			if err != nil {
				httpError(w, message, err.Error())
				return
			}

			write(w, message, []byte("done"))
		})
	}

	mux.HandleFunc(pattern("Put"), func(w http.ResponseWriter, req *http.Request) {

		nodeInfo, ok := routingTable[IPAddress(req.RemoteAddr)]
		if !ok {
			http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		message := MessageFormDecoding(req1)

		err = MessageFormVerifi(&nodeInfo.PublicKey, message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		KeyValueLineType := KeyValueLineDecoding(KeyValueLineVector(message.Message))

		if s.isValueUpdatable {
			ValueLineVector1, isThere, err := s.methodes.Get(KeyValueLineType.Key)

			if err != nil {
				httpError(w, message, err.Error())
				return
			}

			if !isThere {
				goto l
			}

			ValueLineType1 := valueLineDecoding(ValueLineVector1)
			receivedValueType := valueLineDecoding(KeyValueLineType.Value)

			if ValueLineType1.Proposal > receivedValueType.Proposal {
				httpError(w, message, "your proposal is old")
				return
			}
		} else {
			x := sha256.Sum256(KeyValueLineType.Value)
			KeyValueLineType.Key = x[:]
		}

	l:
		err = s.methodes.Put(KeyValueLineType.Key, KeyValueLineType.Value)
		if err != nil {
			httpError(w, message, err.Error())
			return
		}

		write(w, message, []byte("done"))
	})

	mux.HandleFunc(pattern("GetAndLock"), func(w http.ResponseWriter, req *http.Request) {

		nodeInfo, ok := routingTable[IPAddress(req.RemoteAddr)]
		if !ok {
			http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		message := MessageFormDecoding(req1)

		err = MessageFormVerifi(&nodeInfo.PublicKey, message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		KeyValueLineType := KeyValueLineDecoding(KeyValueLineVector(message.Message))

		ValueLineVector1, isThere, err := s.methodes.Get(KeyValueLineType.Key)

		if err != nil {
			httpError(w, message, err.Error())
			return
		}

		if !isThere {
			httpError(w, message, "the value is not exist")
			return
		}

		ValueLineType1 := valueLineDecoding(ValueLineVector1)

		if s.isValueUpdatable {

			if ValueLineType1.NodeIdLockedForHim > nodeInfo.NodeId {
				httpError(w, message, "your nodeId is smaller")
				return
			}

			ValueLineVector2 := valueLineEncoding(valueLineType{
				NodeIdLockedForHim: nodeInfo.NodeId,
				Proposal:           ValueLineType1.Proposal,
				value:              ValueLineType1.value,
			})

			err = s.methodes.Put(KeyValueLineType.Key, ValueLineVector2)
			if err != nil {
				httpError(w, message, err.Error())
				return
			}
		}

		write(w, message, ValueLineVector1)
	})

	mux.HandleFunc(pattern("Get"), func(w http.ResponseWriter, req *http.Request) {

		nodeInfo, ok := routingTable[IPAddress(req.RemoteAddr)]
		if !ok {
			http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		message := MessageFormDecoding(req1)

		err = MessageFormVerifi(&nodeInfo.PublicKey, message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		KeyValueLineType := KeyValueLineDecoding(KeyValueLineVector(message.Message))

		ValueLineVector1, isThere, err := s.methodes.Get(KeyValueLineType.Key)

		if err != nil {
			httpError(w, message, err.Error())
			return
		}

		if !isThere {
			httpError(w, message, "the value is not exist")
			return
		}

		ValueLineType1 := valueLineDecoding(ValueLineVector1)

		write(w, message, ValueLineType1.value)
	})

	mux.HandleFunc(pattern("Delete"), func(w http.ResponseWriter, req *http.Request) {

		nodeInfo, ok := routingTable[IPAddress(req.RemoteAddr)]
		if !ok {
			http.Error(w, "you are not authorized to access the system", http.StatusBadRequest)
			return
		}

		req1, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		message := MessageFormDecoding(req1)

		err = MessageFormVerifi(&nodeInfo.PublicKey, message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		KeyValueLineType := KeyValueLineDecoding(KeyValueLineVector(message.Message))

		err = s.methodes.Delete(KeyValueLineType.Key)

		if err != nil {
			httpError(w, message, err.Error())
			return
		}

		write(w, message, []byte("done"))
	})

	return nil
}

func httpError(w http.ResponseWriter, message MessageFormType, theError string) {
	message.Message = []byte(theError)
	message = MessageFormSign(myPrivetKey, message)
	message1 := MessageFormEncoding(message)
	http.Error(w, string(message1), http.StatusBadRequest)
}

func write(w http.ResponseWriter, message MessageFormType, theMessage []byte) {
	message.Message = theMessage
	message = MessageFormSign(myPrivetKey, message)
	message1 := MessageFormEncoding(message)
	w.Write(message1)
}

func Close(s DHT) error {
	return s.methodes.Close()
}

func Unlock(key Key) error {
	_, err := requestAll("Unlock", key, nil)
	return err
}

func Put(key Key, value valueLineVector) error {
	_, err := requestAll("Put", key, value)
	return err
}

func GetAndLock(key Key) (Value, error) {
	m, err := requestAll("GetAndLock", key, nil)
	if err != nil {
		return nil, err
	}
	return Value(m), nil
}

func Get(key Key) (Value, error) {
	m, err := requestAll("Get", key, nil)
	if err != nil {
		return nil, err
	}
	return Value(m), nil
}

func Delete(key Key) error {
	_, err := requestAll("Delete", key, nil)
	return err
}

func request(url string, publicKey *rsa.PublicKey, nonce []byte, body io.Reader) (Message, error) {

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}

	client := http.Client{Timeout: 120 * time.Second}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	resBodyByte, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	message := MessageFormDecoding(resBodyByte)
	if slices.Equal(message.Nonce, nonce) {
		return nil, errors.New("the nonce is not correct")
	}

	err = MessageFormVerifi(publicKey, message)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s%v", message.Message, res.Status)
	}

	return message.Message, nil
}

func requestAll(port uint, pattern string, keyValueLineType KeyValueLineType) (Message, error) {
	KeyValueLineType := KeyValueLineEncoding(keyValueLineType)

	var nonce []byte
	binary.BigEndian.PutUint64(nonce, rand.Uint64())

	m := bytes.NewReader(MessageFormEncoding(MessageFormSign(myPrivetKey, MessageFormType{
		Nonce:     nonce,
		Message:   Message(KeyValueLineType),
		Signature: []byte{},
	})))

	var message Message
	var err error
	ipAddresses := FindNearestNodes(sha256.Sum256(keyValueLineType.Key))
	for _, ipAddress := range ipAddresses {
		publicKey := routingTable[IPAddress(ipAddress)].PublicKey
		message, err = request(ht.Url(string(ipAddress), port, pattern), &publicKey, nonce, m)
		if err != nil {
			return nil, err
		}
	}

	return message, nil
}

func FindNearestNodes(key KeyHash) []IPAddress {
	var address []IPAddress
	keyAsInt := big.NewInt(256)
	keyAsInt.SetBytes(key[:])

	for i := 0; i < int(maxNumberOfVirtualNodes); i++ {

		var closestIPAddress IPAddress
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

func setRoutingTable(table []nodeInfo) {
	routingTable = make(map[IPAddress]nodeInfo1, len(table))
	for _, v := range table {

		if v.NumberOfVirtualNodes > maxNumberOfVirtualNodes {
			maxNumberOfVirtualNodes = v.NumberOfVirtualNodes
		}

		VirtualNodes := make([]big.Int, v.NumberOfVirtualNodes)

		NodeIdAsBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(NodeIdAsBytes, uint16(v.NodeId))

		for i := uint8(0); i < v.NumberOfVirtualNodes; i++ {

			NodeIdAsHash := sha256.Sum256(NodeIdAsBytes)
			NodeIdAsBytes = NodeIdAsHash[:]

			NodeIdAsInt := big.NewInt(256)
			NodeIdAsInt.SetBytes(NodeIdAsBytes)
			VirtualNodes[i].Abs(NodeIdAsInt)
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

const RoutingTable = "RoutingTable"

func storeTheRoutingTable(table []nodeInfo) error {
	return storeStructToJSON(table, RoutingTable)
}

func readTheRoutingTable() ([]nodeInfo, error) {
	return readJSONFile[[]nodeInfo](RoutingTable)
}
