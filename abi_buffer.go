package main

import "errors"

// C.GoBytes accepts C.int, not size_t. This bound prevents narrowing overflow;
// it cannot prove that a trusted host pointer actually owns length readable bytes.
const maxABICopyLength uint64 = 1<<31 - 1

var (
	errABIBufferSize    = errors.New("ABI buffer length exceeds C.int range")
	errABIBufferPointer = errors.New("ABI buffer pointer is missing for non-empty data")
)

func validateABICopy(length uint64, pointerPresent bool) error {
	if length > maxABICopyLength {
		return errABIBufferSize
	}
	if length != 0 && !pointerPresent {
		return errABIBufferPointer
	}
	return nil
}
