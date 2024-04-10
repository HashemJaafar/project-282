package ht

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	tools "tools"
)

func ListenAndServe(mux *http.ServeMux, host string, port uint) {
	server := http.Server{
		Addr:    fmt.Sprintf("%v:%d", host, port),
		Handler: mux,
	}
	fmt.Println("############ start ############")
	if err := server.ListenAndServe(); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("error running http server: %s\n", err)
		}
	}
}

func Url(IPAddress string, port uint, pattern ...string) string {
	url := fmt.Sprintf("http://%v:%v", IPAddress, port)
	for _, v := range pattern {
		url += "/" + v
	}
	return url
}

// allways return this as false
type Useless struct{}

type networkClass[ReqT any, ResT any] struct {
	Handle  func(mux *http.ServeMux)
	Request func(req ReqT) (ResT, error)
	Process func(req ReqT) (ResT, error)
}

func Create[ReqT any, ResT any](host string, port uint, pattern string, process func(req ReqT) (ResT, error)) networkClass[ReqT, ResT] {
	var s networkClass[ReqT, ResT]

	s.Handle = func(mux *http.ServeMux) {
		HandleFunc(mux, pattern, func(req []byte) ([]byte, error) {
			d, err := tools.Decode[ReqT](req)
			if err != nil {
				return nil, err
			}
			res, err := process(d)
			if err != nil {
				return nil, err
			}
			e, err := tools.Encode(res)
			if err != nil {
				return nil, err
			}
			return e, nil
		})
	}
	s.Request = func(req ReqT) (ResT, error) {
		var zero ResT
		e, err := tools.Encode(req)
		if err != nil {
			return zero, err
		}
		res, err := NewRequest(host, port, pattern, e)
		if err != nil {
			return zero, err
		}
		d, err := tools.Decode[ResT](res)
		if err != nil {
			return zero, err
		}
		return d, nil
	}
	s.Process = process

	return s
}

func NewRequest(host string, port uint, pattern string, reqBodyByte []byte) ([]byte, error) {

	req, err := http.NewRequest(http.MethodPost, Url(host, port, pattern), bytes.NewReader(reqBodyByte))
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

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s%v", resBodyByte, res.Status)
	}

	return resBodyByte, nil
}

func HandleFunc(mux *http.ServeMux, pattern string, handle func(req []byte) ([]byte, error)) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, req *http.Request) {
		reqBodyByte, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resBodyByte, err := handle(reqBodyByte)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Write(resBodyByte)
	})
}

// add multiple respond
func NewRequest1(host string, port uint, pattern string, reqBodyByte []byte) ([]byte, error) {

	req, err := http.NewRequest(http.MethodPost, Url(host, port, pattern), bytes.NewReader(reqBodyByte))
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

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s%v", resBodyByte, res.Status)
	}

	return resBodyByte, nil
}

func HandleFunc1(mux *http.ServeMux, pattern string, handle func(req []byte) ([]byte, error)) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, req *http.Request) {
		reqBodyByte, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// http.Error(w, "", http.StatusProcessing)

		resBodyByte, err := handle(reqBodyByte)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Write(resBodyByte)
	})
}
