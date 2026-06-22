package client

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

func NewTor() (*http.Client, error) {
	//create a SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	//check if it can implement context dialer
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("dialer cannot implement context dialer")
	}

	//create transport
	transport := &http.Transport{
		DialContext:           contextDialer.DialContext,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	//create and return http client
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil

}
