package hmaccrypt

import (
	"code.google.com/p/go.crypto/bcrypt"
	"crypto/rand"
	"crypto/sha512"
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

	// Real digests should match
	if err := c.BcryptCompare(bd, pw); err != nil {
		t.Errorf("no c/bd/pw bcrypt match: %v", err)
	}
	if err := oc.BcryptCompare(obd, pw); err != nil {
		t.Errorf("no c/obd/pw bcrypt match: %v", err)
	}

	// Real digests with another password should not match
	if err := c.BcryptCompare(bd, []byte("f00b4r?")); err == nil {
		t.Errorf("bd/opw match")
	}

	// Digests from a HmacCrypt using another pepper should not match
	if err := c.BcryptCompare(obd, pw); err == nil {
		t.Errorf("c/obd/pw bcrypt match on hmac with another pepper")
	}
	if err := oc.BcryptCompare(bd, pw); err == nil {
		t.Errorf("oc/bd/pw bcrypt match on hmac with another pepper")
	}
}
