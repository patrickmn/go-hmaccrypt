package hmaccrypt

import (
	"crypto/hmac"
	"golang.org/x/crypto/bcrypt"
	"hash"
	"sync"
)

type HmacCrypt struct {
	h  hash.Hash
	mu sync.Mutex
}

func (c *HmacCrypt) digest(data []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.h.Reset()
	c.h.Write(data)
	return c.h.Sum(nil)
}

// Generates a new bcrypt(HMAC-hash(password, pepper), salt(cost)) digest of a
// password with a given bcrypt cost/work factor, e.g. 10 (bcrypt.DefaultCost).
// Use BcryptCompare to compare a password to an existing digest.
func (c *HmacCrypt) Bcrypt(password []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(c.digest(password), cost)
}

// Compares an existing bcrypt digest to HMAC-hash(password, pepper). Returns
// an error if there is no match.
func (c *HmacCrypt) BcryptCompare(digest, password []byte) error {
	return bcrypt.CompareHashAndPassword(digest, c.digest(password))
}

// Returns a HmacCrypt using the specified hash (e.g. sha512.New) and pepper for
// its HMAC function. The pepper should be stored separately from the returned
// digests. If the digests are stored in a database, it is a good idea to store
// the pepper on the disk, or as a constant in the application itself.
func New(hash func() hash.Hash, pepper []byte) *HmacCrypt {
	c := &HmacCrypt{
		h:  hmac.New(hash, pepper),
		mu: sync.Mutex{},
	}
	return c
}
