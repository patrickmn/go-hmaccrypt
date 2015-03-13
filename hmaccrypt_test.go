package hmaccrypt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"golang.org/x/crypto/bcrypt"
	"io"
	"testing"
)

func TestHmaccrypt(t *testing.T) {
	p := make([]byte, 64)
	if n, err := io.ReadFull(rand.Reader, p); err != nil {
		t.Fatalf("Error generating pepper: read %d of %d bytes, err %v", n, len(p), err)
	}
	op := make([]byte, 64)
	if n, err := io.ReadFull(rand.Reader, op); err != nil {
		t.Fatalf("Error generating pepper: read %d of %d bytes, err %v", n, len(op), err)
	}
	c := New(sha512.New, p)
	oc := New(sha512.New, op)
	pw := []byte("f00b4r!")
	bd, err := c.Bcrypt(pw, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("Error running c.bcrypt: %v", err)
	}
	obd, err := oc.Bcrypt(pw, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("Error running oc.bcrypt: %v", err)
	}

	// Same-password digests should match
	if err := c.BcryptCompare(bd, pw); err != nil {
		t.Errorf("no c/bd/pw bcrypt match: %v", err)
	}
	if err := oc.BcryptCompare(obd, pw); err != nil {
		t.Errorf("no c/obd/pw bcrypt match: %v", err)
	}

	// Digests of different passwords should not match
	if err := c.BcryptCompare(bd, []byte("f00b4r?")); err == nil {
		t.Error("bd/opw bcrypt match")
	}

	// Same-password digests from a HmacCrypt using the same hash function
	// and pepper should match
	nc := New(sha512.New, p)
	if err := nc.BcryptCompare(bd, pw); err != nil {
		t.Error("no nc/bd/pw bcrypt match")
	}

	// Same-password digests from a HmacCrypt using another hash function
	// and the same pepper should not match
	onc := New(sha256.New, p)
	if err := onc.BcryptCompare(bd, pw); err == nil {
		t.Error("onc/bd/pw bcrypt match")
	}

	// Same-password digests from a HmacCrypt using another pepper should
	// not match
	if err := c.BcryptCompare(obd, pw); err == nil {
		t.Error("c/obd/pw bcrypt match (hmac with another pepper)")
	}
	if err := oc.BcryptCompare(bd, pw); err == nil {
		t.Error("oc/bd/pw bcrypt match (hmac with another pepper)")
	}
}

func TestBcryptNullCharacter(t *testing.T) {
	var (
		pass = []byte("abc\x00def")
		notPass = []byte("abc\x00ghi")
	)
	passDigest, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("Error hashing pass: %v", err)
	}
	if err = bcrypt.CompareHashAndPassword(passDigest, notPass); err == nil {
		t.Error("pass matches notPass; please report this to the Go authors")
	}
}
