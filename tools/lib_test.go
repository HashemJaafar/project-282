package tools

import (
	"errors"
	"testing"
	"time"

	"github.com/samber/lo"
)

func Test_hash64Bit(t *testing.T) {
	got := Hash64Bit([]byte{88})
	Debug("v", got)
}

func Test_isSameSign(t *testing.T) {
	type args struct {
		number1 float64
		number2 float64
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"", args{1, 1}, true},
		{"", args{1, -1}, false},
		{"", args{-1, 1}, false},
		{"", args{-1, -1}, true},
		{"", args{1, 0}, true},
		{"", args{0, 1}, true},
		{"", args{0, 0}, true},
		{"", args{-1, 0}, true},
		{"", args{0, -1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSameSign(tt.args.number1, tt.args.number2); got != tt.want {
				t.Errorf("IsSameSign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Test(t *testing.T) {
	Test(false, true, "#v", 1, 1)
	Test(true, true, "#v", 1, 1)
	Test(false, false, "#v", 1, 2)
	Test(true, false, "#v", 1, 2)
	Test(false, true, "#v", 1, 2)
}

func Test_standardError(t *testing.T) {
	a := errorPrefix("at", 0)
	Test(false, true, "#v", a, "package (at) error index (0) ")
	a = errorPrefix("a", 1)
	Test(false, true, "#v", a, "package (a) error index (1) ")

	err := Errorf("at", 0, "the password is uncorrect for encryption %v", 0)
	Test(false, true, "#v", err.Error(), "package (at) error index (0) the password is uncorrect for encryption 0")

	a1 := ErrorHandler("at", 0, err)
	Test(false, true, "#v", a1, true)
	a1 = ErrorHandler("at", 1, err)
	Test(false, true, "#v", a1, false)
}

func TestEncode(t *testing.T) {
	{
		s := []int{1, 1, 1, 1}
		e, err := Encode(s)
		Test(false, true, "#v", err, nil)
		a, err := Decode[[]int](e)
		Test(false, true, "#v", a, s)
		Test(false, true, "#v", err, nil)
	}
	{
		s := []string{"1, 1, 1, 1", "ksoso"}
		e, err := Encode(s)
		Test(false, true, "#v", err, nil)
		a, err := Decode[[]string](e)
		Test(false, true, "#v", a, s)
		Test(false, true, "#v", err, nil)
	}
	{
		s := "1, 1, 1, 1"
		e, err := Encode(s)
		Test(false, true, "#v", err, nil)
		a, err := Decode[string](e)
		Test(false, true, "#v", a, s)
		Test(false, true, "#v", err, nil)
	}
	{
		type t struct {
			A int
			B string
		}
		s := t{A: 1, B: "lol"}
		e, err := Encode(s)
		Test(false, true, "#v", err, nil)
		a, err := Decode[t](e)
		Test(false, true, "#v", a, s)
		Test(false, true, "#v", err, nil)
	}
	{
		var s error
		e, err := Encode(s)
		Test(false, true, "#v", err.Error(), "gob: cannot encode nil value")
		a, err := Decode[error](e)
		Test(false, true, "#v", a, s)
		Test(false, true, "#v", err.Error(), "EOF")
	}
	{
		s := errors.New("lol")
		e, err := Encode(s)
		Test(false, true, "#v", err.Error(), "gob: type errors.errorString has no exported fields")
		a, err := Decode[error](e)
		Test(false, true, "#v", a, nil)
		Test(false, true, "#v", err.Error(), "unexpected EOF")
	}
}

func Test1(t *testing.T) {
	names := lo.Uniq[string]([]string{"Samuel", "John", "Samuel"})
	Debug("v", names)
	Debug("x", names)
}

func Test2(t *testing.T) {
	for i := 0; i < 400; i++ {
		type t struct {
			A int
			B string
		}
		s := Rand[t]()
		e, err := Encode(s)
		Test(false, true, "#v", err, nil)
		a, err := Decode[t](e)
		Test(false, true, "#v", a, s)
		Test(false, true, "#v", err, nil)
	}
}

func Test3(t *testing.T) {
	for i := 0; i < 1000; i++ {
		println(Rand[int]())
	}
}

func Test4(t *testing.T) {
	Benchmark(10,
		func() {
			time.Sleep(50 * time.Millisecond)
		},
		func() {
			time.Sleep(100 * time.Millisecond)
		},
		func() {
			time.Sleep(500 * time.Millisecond)
		},
		func() {
			time.Sleep(10 * time.Millisecond)
		},
	)
}

func Test7(t *testing.T) {
	age := 10
	Debug("v", age)
	Debug("v", Stack())
	Debug("v", Rand[int]())
}

// // AnyFunc accepts any function as input, generates random arguments, and calls it.
// func AnyFunc(fn interface{}) []interface{} {
// 	fnType := reflect.TypeOf(fn)

// 	// Generate random arguments for the function
// 	in := make([]reflect.Value, fnType.NumIn())
// 	for i := 0; i < fnType.NumIn(); i++ {
// 		argType := fnType.In(i)
// 		argValue := reflect.New(argType).Elem()

// 		// Handle different types of arguments
// 		switch argType.Kind() {
// 		case reflect.Interface:
// 			if argType.Implements(reflect.TypeOf((*error)(nil)).Elem()) {
// 				// For other interfaces, set to a nil value of the interface type
// 				argValue.Set(reflect.Zero(argType))
// 			}
// 		case reflect.Chan:
// 			// Create a channel with a buffer of 1
// 			argValue.Set(reflect.MakeChan(argType, 1))
// 		case reflect.Func:
// 			// Create a function that matches the type
// 			argValue.Set(reflect.MakeFunc(argType, func(args []reflect.Value) []reflect.Value {
// 				// Just return zero values for the function's return types
// 				results := make([]reflect.Value, argType.NumOut())
// 				for i := 0; i < argType.NumOut(); i++ {
// 					results[i] = reflect.Zero(argType.Out(i))
// 				}
// 				return results
// 			}))
// 		default:
// 			// Default fuzzing for other types
// 			fuzz.New().Fuzz(argValue.Addr().Interface())
// 		}

// 		time.Sleep(1 * time.Microsecond) // Prevents collisions

// 		in[i] = argValue
// 	}

// 	// Call the function using reflection
// 	fnValue := reflect.ValueOf(fn)
// 	results := fnValue.Call(in)

// 	// Convert results from reflect.Values to interfaces
// 	out := make([]interface{}, len(results))
// 	for i, result := range results {
// 		out[i] = result.Interface()
// 	}

// 	return out
// }

// func add(a, b int) int {
// 	return a + b
// }

// func greet(name string) string {
// 	return "Hello, " + name
// }

// func Test8(t *testing.T) {
// 	fmt.Println(AnyFunc(add))
// 	fmt.Println(AnyFunc(greet))
// 	fmt.Println(AnyFunc(Errorf))
// }

// // CallFunction takes a function and its arguments, then calls the function and returns the result
// func CallFunction(fn interface{}, args ...interface{}) []interface{} {
// 	fnValue := reflect.ValueOf(fn)

// 	// Ensure that the provided argument is actually a function
// 	if fnValue.Kind() != reflect.Func {
// 		log.Fatal("provided argument is not a function")
// 	}

// 	if reflect.TypeOf(fn).NumIn() != len(args) {
// 		log.Fatal("the number of input is not same")
// 	}

// 	// Prepare reflect.Value arguments for the function call
// 	fnArgs := make([]reflect.Value, len(args))
// 	for i, arg := range args {
// 		// TODO here i want you to edit the arg and make it random put the type is same

// 		argValue := reflect.New(reflect.TypeOf(arg)).Elem()

// 		fuzz.New().Fuzz(argValue.Addr().Interface())
// 		time.Sleep(1 * time.Microsecond)
// 		fnArgs[i] = argValue

// 		// a := reflect.ValueOf(arg)
// 		// fnArgs[i] = a.Call(nil)[0]
// 		// fnArgs[i] = reflect.ValueOf(arg)
// 	}

// 	// Call the function and get the results
// 	results := fnValue.Call(fnArgs)

// 	out := make([]interface{}, len(results))
// 	for i, result := range results {
// 		out[i] = result.Interface()
// 	}
// 	fmt.Println(fnArgs, out)

// 	return out
// }

// func Test9(t *testing.T) {
// 	// Example usage
// 	fmt.Println(CallFunction(add, int(3), int(2)))
// 	fmt.Println(CallFunction(add, int(9), int(8)))
// 	fmt.Println(CallFunction(greet, ""))
// 	fmt.Println(CallFunction(Errorf, "hashem"))
// }

// func generateTest(rounds int, fn func() ([]any, []any)) {
// 	for i := 0; i < rounds; i++ {
// 		input, output := fn()

// 	}
// }
// func printTest(print bool, isEqual bool, format string, actual string, expected any) {

// 	fmt.Printf("tools.Test(%v, %v, %s, %s, %#v)", print, true, format, actual, expected)
// }
