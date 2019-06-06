package pqgo

import (
	"bytes"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"testing"
)

// to show logs:
// go test -test.v

type KeyGen func() ([]byte, []byte, error)

// in order to update golden values, run:
// go test -update
var update = flag.Bool("update", false, "update .golden files")

// dummy vars to ensure benchmarks don't get optimized out
var (
	pkg []byte
	skg []byte
	smg []byte
	mg  []byte
)

func benchKeyGen(kg KeyGen, b *testing.B) {
	var pk []byte
	var sk []byte
	var err error
	for n := 0; n < b.N; n++ {
		pk, sk, err = kg()
		if err != nil {
			b.Fatalf(err.Error())
		}
	}
	// to avoid compiler optimization
	// cf. https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
	pkg = pk
	skg = sk
}

func BenchmarkDilithiumKeyGen(b *testing.B) {
	d := Dilithium{}
	benchKeyGen(d.KeyGenRandom, b)
}


func benchSign(s Signature, b *testing.B) {

	var sk []byte
	var err error
	_, sk, err = s.KeyGenRandom()
	if err != nil {
		b.Fatalf(err.Error())
	}

	messageLen := 256

	m := make([]byte, messageLen)
	var sm []byte

	for n := 0; n < b.N; n++ {
		sm, err = s.Sign(m, sk)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}

	smg = sm
}

func BenchmarkDilithiumSign(b *testing.B) {
	d := Dilithium{}
	benchSign(d, b)
}

func benchOpen(s Signature, b *testing.B) {

	var pk []byte
	var sk []byte
	var err error
	pk, sk, err = s.KeyGenRandom()
	if err != nil {
		b.Fatalf(err.Error())
	}

	messageLen := 256

	m := make([]byte, messageLen)
	var sm []byte
	sm, err = s.Sign(m, sk)
	if err != nil {
		b.Fatalf(err.Error())
	}

	for n := 0; n < b.N; n++ {
		m, err = s.Open(sm, pk)
		if err != nil {
			b.Fatalf(err.Error())
		}
	}

	mg = sm
}

func BenchmarkDilithiumOpen(b *testing.B) {
	d := Dilithium{}
	benchOpen(d, b)
}

// assumes deterministic signatures
func testSignatureGolden(s Signature, entropyLen int, name string, t *testing.T) {
	ent := make([]byte, entropyLen)
	pk, sk, err := s.KeyGen(ent)
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Log("pk vector")
	t.Log(hex.EncodeToString(pk))
	t.Log("sk vector")
	t.Log(hex.EncodeToString(sk))

	messageLen := 256

	m := make([]byte, messageLen)

	sm, err := s.Sign(m, sk)

	goldenpk := "golden/" + name + "_pk.golden"
	goldensk := "golden/" + name + "_sk.golden"
	goldensm := "golden/" + name + "_sm.golden"

	if *update {
		ioutil.WriteFile(goldenpk, pk, 0644)
		ioutil.WriteFile(goldensk, sk, 0644)
		ioutil.WriteFile(goldensm, sm, 0644)
	}
	pk0, _ := ioutil.ReadFile(goldenpk)
	sk0, _ := ioutil.ReadFile(goldensk)
	sm0, _ := ioutil.ReadFile(goldensm)

	if !bytes.Equal(pk, pk0) {
		t.Fatal("public key doesnt match")
	}
	if !bytes.Equal(sk, sk0) {
		t.Fatal("secret key doesnt match")
	}
	if !bytes.Equal(sm, sm0) {
		t.Fatal("signed message doesnt match")
	}
}

func TestDilithiumGolden(t *testing.T) {
	d := Dilithium{}
	testSignatureGolden(d, DilithiumEntropyLen, "dilithium", t)
}

func testSignature(s Signature, t *testing.T) {

	pk, sk, err := s.KeyGenRandom()

	if err != nil {
		t.Fatalf(err.Error())
	}

	t.Log("pk")
	t.Log(hex.EncodeToString(pk))
	t.Log("sk")
	t.Log(hex.EncodeToString(sk))

	messageLen := 256

	m := make([]byte, messageLen)

	sm, err := s.Sign(m, sk)

	if err != nil {
		t.Fatalf(err.Error())
	}

	t.Log("sm")
	t.Log(hex.EncodeToString(sm))
	t.Log("m")
	t.Log(hex.EncodeToString(m))

	mm, err := s.Open(sm, pk)

	if err != nil {
		t.Fatalf(err.Error())
	}

	if string(mm) != string(m) {
		t.Fatalf("opened message doesnt match signed message")
	}

	t.Log("mm")
	t.Log(hex.EncodeToString(mm))

	sm[0]++

	mm, err = s.Open(sm, pk)

	if err == nil {
		t.Fatalf("invalid signature verified")
	}
}

func TestDilithium(t *testing.T) {
	d := Dilithium{}
	testSignature(d, t)
}
