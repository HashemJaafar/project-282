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
