package main

import (
	"embed"
	"errors"
)

//go:embed payload
var embedded embed.FS

func embeddedDLL() ([]byte, error) {
	data, err := embedded.ReadFile("payload/menustate_compilestring.dll")
	if err != nil || len(data) == 0 {
		return nil, errors.New("no embedded DLL (online download required)")
	}
	return data, nil
}
