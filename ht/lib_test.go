package ht

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
	"tools"
)

func TestUrl(t *testing.T) {
	url := Url("localhost", 3333, "/work")
	tools.Test(false, true, "#v", url, "http://localhost:3333/work")
}

const (
	IPAddress = "localhost"
	port      = 8000
)

func TestCreate(t *testing.T) {
	f1 := Create(IPAddress, port, "/f1", func(req int) (string, error) { return fmt.Sprint(req), nil })
	f2 := Create(IPAddress, port, "/f2", func(req string) (string, error) { return fmt.Sprint(req), nil })
	f3 := Create(IPAddress, port, "/f3", func(req string) (error, error) { return fmt.Errorf(req), nil })
	f4 := Create(IPAddress, port, "/f4", func(req error) (string, error) { return req.Error(), nil })
	f5 := Create(IPAddress, port, "/f5", func(req int) (any, error) { return nil, nil })
	f6 := Create(IPAddress, port, "/f6", func(req any) (int, error) { return 10, nil })
	f7 := Create(IPAddress, port, "/f7", func(req any) (string, error) { return fmt.Sprint(req), nil })
	f8 := Create(IPAddress, port, "/f8", func(req bool) (Useless, error) { return struct{}{}, nil })

	go func() {
		mux := http.NewServeMux()
		f1.Handle(mux)
		f2.Handle(mux)
		f3.Handle(mux)
		f4.Handle(mux)
		f5.Handle(mux)
		f6.Handle(mux)
		f7.Handle(mux)
		f8.Handle(mux)
		ListenAndServe(mux, IPAddress, port)
	}()

	time.Sleep(1000 * time.Millisecond)

	{
		r, err := f1.Request(1)
		tools.Test(false, true, "#v", r, "1")
		tools.Test(false, true, "#v", err, nil)
	}
	{
		r, err := f2.Request("yes")
		tools.Test(false, true, "#v", r, "yes")
		tools.Test(false, true, "#v", err, nil)
	}
	{
		r, err := f3.Request("yes")
		tools.Test(false, true, "#v", r, nil)
		tools.Test(false, true, "#v", err.Error(), "gob: type errors.errorString has no exported fields\n500 Internal Server Error")
	}
	{
		r, err := f4.Request(fmt.Errorf("yes"))
		tools.Test(false, true, "#v", r, "")
		tools.Test(false, true, "#v", err.Error(), "gob: type errors.errorString has no exported fields")
	}
	{
		r, err := f5.Request(5)
		tools.Test(false, true, "#v", r, nil)
		tools.Test(false, true, "#v", err.Error(), "gob: cannot encode nil value\n500 Internal Server Error")
	}
	{
		r, err := f6.Request("yes")
		tools.Test(false, true, "#v", r, 0)
		tools.Test(false, true, "#v", err.Error(), "gob: local interface type *interface {} can only be decoded from remote interface type; received concrete type string\n500 Internal Server Error")
	}
	{
		r, err := f6.Request(errors.New("yes"))
		tools.Test(false, true, "#v", r, 0)
		tools.Test(false, true, "#v", err.Error(), "gob: type errors.errorString has no exported fields")
	}
	{
		r, err := f7.Request(errors.New("yes"))
		tools.Test(false, true, "#v", r, "")
		tools.Test(false, true, "#v", err.Error(), "gob: type errors.errorString has no exported fields")
	}
	{
		r, err := f8.Request(true)
		tools.Test(false, true, "#v", r, struct{}{})
		tools.Test(false, true, "#v", err, nil)
	}
}

func Test(t *testing.T) {
	f1 := Create(IPAddress, port, "/f1", func(req bool) (string, error) {
		fmt.Println("f1 is work")
		time.Sleep(10 * time.Second)
		return fmt.Sprintf("f1 is complete %v", time.Now()), nil
	})
	f2 := Create(IPAddress, port, "/f2", func(req bool) (string, error) {
		fmt.Println("f2 is work")
		time.Sleep(10 * time.Second)
		return fmt.Sprintf("f2 is complete %v", time.Now()), nil
	})

	go func() {
		mux := http.NewServeMux()
		f1.Handle(mux)
		f2.Handle(mux)
		ListenAndServe(mux, IPAddress, port)
	}()

	time.Sleep(100 * time.Millisecond)

	var wait sync.WaitGroup
	wait.Add(10)

	f := func(c networkClass[bool, string]) {
		tools.Debug(c.Request(true))
		wait.Done()
	}
	go f(f1)
	go f(f1)
	go f(f1)
	go f(f1)
	go f(f1)
	go f(f2)
	go f(f2)
	go f(f2)
	go f(f2)
	go f(f2)
	wait.Wait()

	time.Sleep(15 * time.Second)
}
