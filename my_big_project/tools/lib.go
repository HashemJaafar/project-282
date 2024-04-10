package tools

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"math"
	"os"
	"reflect"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	fuzz "github.com/google/gofuzz"
)

func DeleteAtIndex[t any](slice []t, index int) []t {
	return append(slice[:index], slice[index+1:]...)
}

func removeElement(slice *[]any, valuesToRemove ...any) {
	slice1 := *slice
loop:
	for i := 0; i < len(slice1); i++ {
		url := slice1[i]
		for _, rem := range valuesToRemove {
			if url == rem {
				slice1 = append(slice1[:i], slice1[i+1:]...)
				i-- // Important: decrease index
				continue loop
			}
		}
	}
	*slice = slice1
}

func IsSameSign(number1, number2 float64) bool {
	if number1 == 0 || number2 == 0 {
		return true
	}
	return (number1 > 0) == (number2 > 0)
}

func ChangeSign(number1 float64, number2 float64) float64 {
	switch {
	case number1 > 0:
		return math.Abs(number2)
	case number1 < 0:
		return -math.Abs(number2)
	}
	return number2
}

func Find[t comparable](element t, elements []t) (int, bool) {
	for k1, v1 := range elements {
		if v1 == element {
			return k1, true
		}
	}
	return 0, false
}

func Hash64Bit(b []byte) [8]byte {
	s := sha256.Sum256(b)
	s1 := [8]byte(s[:9])
	return s1
}

func PanicIfErr(err error) {
	if err != nil {
		panic(err)
	}
}

func errorPrefix(packageName string, errorIndex uint) string {
	return fmt.Sprintf("package (%v) error index (%v) ", packageName, errorIndex)
}

func Errorf(packageName string, errorIndex uint, format string, a ...any) error {
	if packageName == "" {
		panic("dont pass zero value to packageName")
	}
	if errorIndex == 0 {
		panic("dont pass zero value to errorIndex")
	}
	return fmt.Errorf(errorPrefix(packageName, errorIndex)+format, a...)
}

func ErrorHandler(packageName string, errorIndex uint, err error) bool {
	if err == nil {
		return false
	}
	errString := err.Error()
	prefix := errorPrefix(packageName, errorIndex)
	if len(errString) < len(prefix) {
		return false
	}
	for i, v := range prefix {
		if v != rune(errString[i]) {
			return false
		}
	}
	return true
}

func Encode(decoded any) ([]byte, error) {
	var network bytes.Buffer
	enc := gob.NewEncoder(&network)
	err := enc.Encode(decoded)
	return network.Bytes(), err
}

func Decode[t any](encoded []byte) (t, error) {
	var decoded t
	network := bytes.NewReader(encoded)
	dec := gob.NewDecoder(network)
	err := dec.Decode(&decoded)
	return decoded, err
}

func NumberToBytes[t comparable](number t) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, number)
	PanicIfErr(err)
	return buff.Bytes()
}

func BytesToNumber[t comparable](byteArray []byte) t {
	var number t
	err := binary.Read(bytes.NewReader(byteArray), binary.BigEndian, &number)
	PanicIfErr(err)
	return number
}

func Uint64ToBytes(value uint64) []byte {
	b := make([]byte, 8) // Allocate 8 bytes for a uint64
	binary.BigEndian.PutUint64(b, value)
	return b
}

func BoolToByteBitMask(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func ByteToBoolBitMask(b byte) bool {
	return b == 1
}

//////////////////////////////////////////////////////////////////////////////////////////////////test tools

func Rand[t any]() t {
	var result t
	fuzz.New().Fuzz(&result)
	time.Sleep(1 * time.Microsecond)
	return result
}

const (
	ColorReset = "\033[0m"

	ColorBlack   = "\033[30m"
	ColorRed     = "\033[31m" //for fail
	ColorGreen   = "\033[32m" //for success
	ColorYellow  = "\033[33m" //for expected
	ColorBlue    = "\033[34m" //for actual
	ColorMagenta = "\033[35m" //for Debug
	ColorCyan    = "\033[36m" //for Benchmark
	ColorWhite   = "\033[37m"
)

func Stack() string {
	stack := string(debug.Stack())
	stack = strings.Split(stack, "\n")[8]
	stack = strings.TrimSpace(strings.ReplaceAll(stack, "\t", ""))

	return stack
}

func getLineFromFile(filePath string, lineNumber int) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error reading file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	if lineNumber < 1 || lineNumber > len(lines) {
		return "", fmt.Errorf("invalid line number: %d", lineNumber)
	}

	return lines[lineNumber-1], nil // Adjust for 0-based indexing
}

func parseLocation(location string) (string, int, error) {
	parts := strings.SplitN(location, ".go:", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid location format: %s", location)
	}

	filePath := parts[0] + ".go"
	filePath = strings.TrimSpace(strings.ReplaceAll(filePath, " ", ""))

	var numberString string
	for _, v := range parts[1] {
		if v == ' ' {
			break
		}
		numberString += string(v)
	}

	lineNumber, err := strconv.Atoi(numberString)
	if err != nil {
		return "", 0, fmt.Errorf("invalid line number: %s", err)
	}

	return filePath, lineNumber, nil
}

func getLineFromStack(stack string) string {
	filePath, lineNumber, err := parseLocation(stack)
	PanicIfErr(err)
	s, err := getLineFromFile(filePath, lineNumber)
	PanicIfErr(err)
	return s
}

func Debug(format string, a any) {
	stack := Stack()
	fmt.Println(ColorMagenta, stack, ColorReset)
	line := getLineFromStack(stack)

	parts := strings.SplitN(line, ", ", 2)
	variableName := parts[1][0 : len(parts[1])-1]

	fmt.Printf("%v%v:%v%"+format+"\n", ColorYellow, variableName, ColorReset, a)
	fmt.Println("________________________________________________________________________________")
}

func Test[t any](print, isEqual bool, format string, actual, expected t) {
	stack := Stack()

	printStack := func(color string) {
		fmt.Println(color, stack, ColorReset)
	}
	printActual := func() {
		fmt.Printf("%v%"+format+"%v\n", ColorYellow, actual, ColorReset)
	}
	printExpected := func() {
		fmt.Printf("%v%"+format+"%v\n", ColorBlue, expected, ColorReset)
	}

	if !reflect.DeepEqual(actual, expected) == isEqual {
		printStack(ColorRed)

		if isEqual {
			fmt.Println("this should equal to each other")
		} else {
			fmt.Println("this should not equal to each other")
		}

		printActual()
		printExpected()
		fmt.Println("________________________________________________________________________________")

		os.Exit(1)
	}
	printStack(ColorGreen)

	if print {
		if isEqual {
			fmt.Println("this is equal to each other")
		} else {
			fmt.Println("this is not equal to each other")
		}

		printActual()
		if !isEqual {
			printExpected()
		}
		fmt.Println("________________________________________________________________________________")
	}
}

func Benchmark(loops uint, codesBlock ...func()) {
	type element struct {
		blockIndex int
		duration   time.Duration
	}

	var list []element

	for blockIndex, codeBlock := range codesBlock {
		start := time.Now()

		for i := uint(0); i < loops; i++ {
			codeBlock()
		}

		duration := time.Since(time.Time(start))

		list = append(list, element{
			blockIndex: blockIndex,
			duration:   duration,
		})

	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].duration < list[j].duration
	})

	fmt.Println(ColorCyan, Stack(), ColorReset)

	for _, v := range list {
		fmt.Printf("block index %v: it takes %v and %v for each loop\n", v.blockIndex, v.duration, v.duration/time.Duration(loops))
	}

	fmt.Println("________________________________________________________________________________")
}
