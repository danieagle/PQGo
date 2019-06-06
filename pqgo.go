package pqgo

/*
#include "c/fips202/fips202.c"
#include "c/fips202/keccakf1600.c"

#include "c/randombytes/rng.c"
#include "c/randombytes/xof_hash.c"

#include "c/dilithium/params.h"
#include "c/dilithium/poly.c"
#include "c/dilithium/ntt.c"
#include "c/dilithium/packing.c"
#include "c/dilithium/sign.c"
#include "c/dilithium/polyvec.c"
#include "c/dilithium/reduce.c"
#include "c/dilithium/rounding.c"
*/
import "C"
import (
	"crypto/rand"
	"errors"
	"unsafe"
)

const (
	// DilithiumEntropyLen is the byte length of keypair entropy
	DilithiumEntropyLen = 32
)

var (
	// ErrKeypair ..
	ErrKeypair = errors.New("keypair returned non-zero")
	// ErrSign ..
	ErrSign = errors.New("sign returned non-zero")
	// ErrOpen ..
	ErrOpen = errors.New("open returned non-zero")
	// ErrEncrypt ..
	ErrEncrypt = errors.New("encrypt returned non-zero")
	// ErrDecrypt ..
	ErrDecrypt = errors.New("decrypt returned non-zero")
)

// Signature ...
type Signature interface {
	KeyGen(ent []byte) ([]byte, []byte, error)
	KeyGenRandom() ([]byte, []byte, error)
	Sign(m, sk []byte) ([]byte, error)
	Open(sm, pk []byte) ([]byte, error)
}

// Dilithium ...
type Dilithium struct{}

// KeyGenRandom ...
func (d Dilithium) KeyGenRandom() (pk, sk []byte, err error) {
	ent := make([]byte, DilithiumEntropyLen)
	_, err = rand.Read(ent)

	if err != nil {
		panic("random read failed")
	}

	return d.KeyGen(ent)
}

// KeyGen ...
func (Dilithium) KeyGen(ent []byte) (pk, sk []byte, err error) {
	if len(ent) != DilithiumEntropyLen {
		return nil, nil, errors.New("invalid entropy size")
	}
	pk = make([]byte, C.DILITHIUM_PUBLICKEYBYTES)
	sk = make([]byte, C.DILITHIUM_SECRETKEYBYTES)

	pkp := (*C.char)(unsafe.Pointer(&pk[0]))
	skp := (*C.char)(unsafe.Pointer(&sk[0]))
	entp := (*C.char)(unsafe.Pointer(&ent[0]))

	ret := C.dilithium_sign_keypair_cgo(pkp, skp, entp)

	if ret != 0 {
		return nil, nil, ErrKeypair
	}

	pk = []byte(C.GoStringN(pkp, C.DILITHIUM_PUBLICKEYBYTES))
	sk = []byte(C.GoStringN(skp, C.DILITHIUM_SECRETKEYBYTES))

	return pk, sk, nil
}

// Sign ...
func (Dilithium) Sign(m, sk []byte) (sm []byte, err error) {

	if len(sk) != C.DILITHIUM_SECRETKEYBYTES {
		return nil, errors.New("invalid secret key size")
	}

	mlen := C.ulonglong(len(m))
	sm = make([]byte, mlen+C.DILITHIUM_BYTES)

	skp := (*C.char)(unsafe.Pointer(&sk[0]))
	smp := (*C.char)(unsafe.Pointer(&sm[0]))
	mp := (*C.char)(unsafe.Pointer(&m[0]))

	ret := C.dilithium_sign_cgo(smp, mp, mlen, skp)

	if ret != 0 {
		return nil, ErrSign
	}

	sm = []byte(C.GoStringN(smp, C.int(len(m))+C.DILITHIUM_BYTES))

	return sm, nil
}

// Open ...
func (Dilithium) Open(sm, pk []byte) (m []byte, err error) {

	if len(pk) != C.DILITHIUM_PUBLICKEYBYTES {
		return nil, errors.New("invalid public key size")
	}

	smlen := C.ulonglong(len(sm))
	mlen := smlen - C.DILITHIUM_BYTES

	// C function may actually write as much as len(sm) at m!
	m = make([]byte, smlen)

	pkp := (*C.char)(unsafe.Pointer(&pk[0]))
	smp := (*C.char)(unsafe.Pointer(&sm[0]))
	mp := (*C.char)(unsafe.Pointer(&m[0]))

	ret := C.dilithium_sign_open_cgo(mp, smp, smlen, pkp)

	if ret != 0 {
		return nil, ErrOpen
	}

	m = []byte(C.GoStringN(mp, C.int(mlen)))

	return m, nil
}
