package main

import (
	"errors"
	"testing"
)

func TestABICopyLengthAndPointerValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    uint64
		pointer bool
		want    error
	}{
		{"empty nil", 0, false, nil}, {"empty present", 0, true, nil},
		{"one byte", 1, true, nil}, {"largest C int", maxABICopyLength, true, nil},
		{"missing pointer", 1, false, errABIBufferPointer},
		{"first overflow", maxABICopyLength + 1, true, errABIBufferSize},
		{"size_t max", ^uint64(0), true, errABIBufferSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateABICopy(tc.size, tc.pointer); !errors.Is(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
