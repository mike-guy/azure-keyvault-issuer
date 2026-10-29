package issuer

import (
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"k8s.io/apimachinery/pkg/types"
)

// credentialCache keeps one credential per issuer, so that its token cache
// survives between signatures. Each entry is valid only for the generation of
// the issuer it was built for. The CA is not cached: Sign fetches it every
// time, so a rotated CA is used at once.
type credentialCache struct {
	mu      sync.Mutex
	entries map[types.UID]cacheEntry
}

type cacheEntry struct {
	generation int64
	cred       azcore.TokenCredential
}

func newCredentialCache() *credentialCache {
	return &credentialCache{entries: map[types.UID]cacheEntry{}}
}

// get returns the credential cached for uid at generation, if there is one.
func (c *credentialCache) get(uid types.UID, generation int64) (azcore.TokenCredential, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[uid]
	if !ok || e.generation != generation {
		return nil, false
	}

	return e.cred, true
}

// put caches cred for uid at generation, replacing any older entry.
func (c *credentialCache) put(uid types.UID, generation int64, cred azcore.TokenCredential) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[uid] = cacheEntry{generation: generation, cred: cred}
}

// forget drops the entry for uid.
func (c *credentialCache) forget(uid types.UID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, uid)
}
