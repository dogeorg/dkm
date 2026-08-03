package keymgr

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"code.dogecoin.org/dkm/internal"
	"github.com/dogeorg/doge"
	"github.com/dogeorg/doge/bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var _ internal.KeyMgr = &keyMgr{}

const SessionTime = 65 * 60 // seconds (65 minutes)
const HandoverTime = 10     // seconds
const MainKey = 1           // ID of main key
const MnemonicEntropyBits = 256

// Argon2 parameters.
// RFC 9106: "If much less memory is available, a uniformly safe option is Argon2id
// with t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of RAM), 128-bit salt, and 256-bit
// tag size. This is the SECOND RECOMMENDED option."
const ArgonTime = 3
const ArgonThreads = 4
const ArgonMemory = 64 * 1024 // 64 MB
const SecretKeySize = doge.SerializedBip32KeyLength

var ErrOutOfEntropy = errors.New("insufficient entropy available")
var ErrWrongPassword = errors.New("incorrect password")
var ErrBadToken = errors.New("invalid or expired token")
var ErrKeyExists = errors.New("key already exists")
var ErrTooManyAttempts = errors.New("too many attempts to generate a key")
var ErrWrongMnemonic = errors.New("mnemonic does not match existing key")
var ErrNoKey = errors.New("key has not been created")
var ErrWrongToken = errors.New("invalid token")
var ErrBadKey = errors.New("bad stored key: cannot decode key")

type keyMgr struct {
	mu       sync.Mutex
	store    internal.StoreCtx
	sessions map[string]session
	key      []byte
}

type session struct {
	expires time.Time
	rolled  bool
}

func New(store internal.StoreCtx) internal.KeyMgr {
	return &keyMgr{
		store:    store,
		sessions: make(map[string]session),
	}
}

func (km *keyMgr) CreateKey(pass string) (mnemonic []string, err error) {
	mnemonic, key, pub, err := km.generateMnemonic()
	if err != nil {
		return nil, err
	}
	err = km.encryptAndSetKey(MainKey, key, pub, pass, false)
	memZero(key)
	if err != nil {
		if internal.IsAlreadyExistsError(err) {
			return nil, ErrKeyExists
		}
		return nil, err
	}
	return mnemonic, nil
}

func (km *keyMgr) LogIn(pass string) (token string, ends int, err error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.cleanSessions()
	// verify the password
	key, _, err := km.getAndDecryptKey(MainKey, pass)
	if err != nil {
		memZero(key)
		if errors.Is(err, internal.ErrNotFound) {
			return "", 0, ErrNoKey
		}
		return // wrong password
	}
	token, ends, err = km.newSession()
	if err != nil {
		memZero(key)
		return // out of entropy
	}
	km.key = key // keep key in-memory for `MakeDelegate`
	return token, ends, nil
}

func (km *keyMgr) RollToken(token string) (newtoken string, ends int, err error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.cleanSessions()
	now := time.Now()
	if s, ok := km.sessions[token]; ok && !s.rolled && s.expires.After(now) {
		// keep the current token alive for a short handover time,
		// in case there are concurrent requests using the old token.
		km.sessions[token] = session{expires: time.Now().Add(HandoverTime * time.Second), rolled: true}
		// issue a new token.
		return km.newSession()
	} else {
		// the token has already expired.
		delete(km.sessions, token)
		return "", 0, ErrBadToken
	}
}

func (km *keyMgr) LogOut(token string) {
	km.mu.Lock()
	defer km.mu.Unlock()

	// invalidate the token if it exists.
	delete(km.sessions, token)
	// remove key from memory after all sessions expire.
	km.cleanSessions()
	if len(km.sessions) < 1 {
		memZero(km.key)
		km.key = nil
	}
}

func (km *keyMgr) ChangePassword(password string, newpass string) error {
	// decrypt the key using the current password
	key, pub, err := km.getAndDecryptKey(MainKey, password)
	if err != nil {
		memZero(key)
		if errors.Is(err, internal.ErrNotFound) {
			return ErrNoKey
		}
		return err
	}
	err = km.encryptAndSetKey(MainKey, key, pub, newpass, true)
	memZero(key)
	return err
}

func (km *keyMgr) RecoverPassword(mnemonic []string, newpass string) error {
	// get the existing stored pubkey
	pub, err := km.store.GetKeyPub(MainKey) // ErrNotFound|error
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return ErrNoKey
		}
		return err
	}

	// re-generate the key from the supplied mnemonic
	seed, err := bip39.SeedFromMnemonic(mnemonic, "", bip39.EnglishWordList)
	if err != nil {
		return err // bad mnemonic
	}
	defer memZero(seed) // clear seed material

	// generate Bip32 master key from seed
	master, err := doge.Bip32MasterFromSeed(seed, &doge.DogeMainNetChain) // ErrBadSeed,ErrAnotherSeed
	if err != nil {
		return ErrWrongMnemonic // we check validity when we generate the mnemonic
	}
	defer master.Clear() // clear key material

	newpub := master.GetECPubKey()
	if !bytes.Equal(pub, newpub[:]) {
		return ErrWrongMnemonic // mnemonic pubkey differs from the stored pubkey
	}

	// re-encrypt the stored key using the new password
	key := []byte(master.EncodeWIF())
	defer memZero(key)
	err = km.encryptAndSetKey(MainKey, key, pub, newpass, true)
	return err
}

func (km *keyMgr) CreateDelegate(id string, pass string) (tok string, pubkey []byte, e error) {
	key, _, err := km.getAndDecryptKey(MainKey, pass) // ErrNoKey
	if err != nil {
		return "", nil, err
	}
	master, err := doge.DecodeBip32WIF(string(key), &doge.DogeMainNetChain) // bad-key
	memZero(key)                                                            // clear key material
	if err != nil {
		log.Printf("CreateDelegate: error decoding master key: %v", err)
		return "", nil, ErrBadKey
	}
	// pup namespace: m/1000'/2'/N'
	const H = doge.HardenedKey
	pupKey, err := master.PrivateCKD([]uint32{H + 1000, H + 2}, true)
	master.Clear() // clear key material
	if err != nil {
		return "", nil, ErrBadKey
	}
	defer pupKey.Clear() // clear key material at exit
	err = km.store.Transaction(func(tx internal.StoreTxn) error {
		max, err := tx.GetMaxDelegate()
		if err != nil {
			return err
		}
		keyIndex := uint32(max + 1)
		var child *doge.Bip32Key
		child, err = pupKey.PrivateCKD([]uint32{H + keyIndex}, true)
		if err != nil {
			return err
		}
		defer child.Clear()           // clear key material at exit
		token, err := generateToken() // ErrOutOfEntropy
		if err != nil {
			return err
		}
		child_wif := []byte(child.EncodeWIF())
		defer memZero(child_wif)                                 // clear key material at exit
		salt, nonce, enc, err := km.encryptKey(child_wif, token) // ErrOutOfEntropy
		if err != nil {
			return err
		}
		pub := child.GetECPubKey()
		err = tx.SetDelegate(id, salt, nonce, enc, pub[:], keyIndex) // DBConflict|AlreadyExists|error
		if err != nil {
			return err
		}
		tok = token     // set return value
		pubkey = pub[:] // set return value
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return
}

func (km *keyMgr) MakeDelegate(id string, token string) (privkey []byte, pubkey []byte, wif string, e error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	km.cleanSessions()
	if _, ok := km.sessions[token]; ok && km.key != nil {
		master, err := doge.DecodeBip32WIF(string(km.key), &doge.DogeMainNetChain) // bad-key
		if err != nil {
			log.Printf("CreateDelegate: error decoding master key: %v", err)
			return nil, nil, "", ErrBadKey
		}
		// pup namespace: m/1000'/2'/N'
		const H = doge.HardenedKey
		pupKey, err := master.PrivateCKD([]uint32{H + 1000, H + 2}, true)
		master.Clear() // clear key material
		if err != nil {
			return nil, nil, "", ErrBadKey
		}
		defer pupKey.Clear() // clear key material at exit
		err = km.store.Transaction(func(tx internal.StoreTxn) error {
			_, keyIndex, err := tx.GetDelegatePub(id) // NotFound|error
			if err != nil {
				if errors.Is(err, internal.ErrNotFound) {
					max, err := tx.GetMaxDelegate()
					if err != nil {
						return err
					}
					keyIndex = uint32(max + 1)
					err = tx.SetDelegate(id, []byte{}, []byte{}, []byte{}, []byte{}, keyIndex) // DBConflict|error
					if err != nil {
						return err
					}
				} else {
					return err
				}
			}
			child, err := pupKey.PrivateCKD([]uint32{H + keyIndex}, true)
			if err != nil {
				return err
			}
			defer child.Clear() // clear key material at exit
			pub := child.GetECPubKey()
			priv, err := child.GetECPrivKey()
			if err != nil {
				return err
			}
			// return values:
			privkey = priv[:]
			pubkey = pub[:]
			wif = child.EncodeWIF() // set return value
			return nil
		})
		if err != nil {
			return nil, nil, "", err
		}
		return
	} else {
		// the token has already expired.
		return nil, nil, "", ErrBadToken
	}
}

func (km *keyMgr) GetDelegatePub(id string) (pubkey []byte, err error) {
	pub, _, err := km.store.GetDelegatePub(id)
	return pub, err // NotFound|error
}

func (km *keyMgr) GetDelegatePriv(id string, token string) (privkey, pubkey []byte, err error) {
	salt, nonce, enc, pub, err := km.store.GetDelegatePriv(id) // NotFound|error
	if err != nil {
		return nil, nil, err
	}
	priv, err := km.decryptKey(salt, nonce, enc, token) // WrongPassword
	memZero(enc)
	memZero(salt)
	memZero(nonce)
	if err != nil {
		memZero(priv)
		if errors.Is(err, ErrWrongPassword) {
			err = ErrWrongToken
		}
		return nil, nil, err
	}
	return priv, pub, nil
}

// HELPERS

func generateToken() (string, error) {
	tokenBytes := [32]byte{}
	_, err := rand.Read(tokenBytes[:])
	if err != nil {
		return "", ErrOutOfEntropy
	}
	token := hex.EncodeToString(tokenBytes[:])
	memZero(tokenBytes[:])
	return token, nil
}

// cleanSessions removes expired sessions from memory.
func (km *keyMgr) cleanSessions() {
	// clean out expired tokens.
	now := time.Now()
	for key, s := range km.sessions {
		if s.expires.Before(now) {
			// seems safe: https://go.dev/doc/effective_go#for
			delete(km.sessions, key)
		}
	}
}

func (km *keyMgr) newSession() (token string, ends int, err error) {
	// generate a cryptographically-secure random token.
	tok := [16]byte{}
	_, err = rand.Read(tok[:])
	if err != nil {
		return "", 0, ErrOutOfEntropy
	}
	token = hex.EncodeToString(tok[:])
	km.sessions[token] = session{expires: time.Now().Add((SessionTime + HandoverTime) * time.Second)}
	return token, SessionTime, nil
}

func (km *keyMgr) getAndDecryptKey(keyId int, pass string) (key []byte, pub []byte, err error) {
	salt, nonce, enc, pubk, err := km.store.GetKey(keyId) // ErrNotFound|error
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			return nil, nil, ErrNoKey
		}
		return nil, nil, err
	}
	dec, err := km.decryptKey(salt, nonce, enc, pass) // ErrWrongPassword|error
	memZero(enc)
	memZero(salt)
	memZero(nonce)
	return dec, pubk, err
}

func (km *keyMgr) decryptKey(salt []byte, nonce []byte, enc []byte, pass string) (key []byte, err error) {
	// decrypt the private key using the password (via Argon2id)
	pwdKey := argon2.IDKey([]byte(pass), salt, ArgonTime, ArgonMemory, ArgonThreads, chacha20poly1305.KeySize)
	memZero(salt)
	aead, err := chacha20poly1305.NewX(pwdKey[:]) // bad-key-len
	memZero(pwdKey)
	if err != nil {
		memZero(nonce)
		memZero(enc)
		return nil, err
	}
	key = make([]byte, 0, SecretKeySize)
	key, err = aead.Open(key, nonce, enc, nil)
	memZero(nonce)
	memZero(enc)
	if err != nil {
		// only errOpen "message authentication failed"
		return nil, ErrWrongPassword
	}
	return key, nil
}

// encrypt secret with password and store. clears secret.
func (km *keyMgr) encryptAndSetKey(keyId int, secret, pub []byte, pass string, allowReplace bool) (err error) {
	salt, nonce, enc, err := km.encryptKey(secret, pass)
	if err != nil {
		return err
	}
	// store the password nonce, key nonce, encrypted key
	err = km.store.SetKey(keyId, salt, nonce, enc, pub, allowReplace)
	memZero(enc)
	memZero(nonce)
	memZero(salt)
	return err
}

// encrypt secret with password.
func (km *keyMgr) encryptKey(secret []byte, pass string) (salt, nonce, enc []byte, err error) {
	// generate salts
	salt = make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, nil, nil, ErrOutOfEntropy
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, nil, ErrOutOfEntropy
	}

	// encrypt the private key with the password (via Argon2id)
	pwdKey := argon2.IDKey([]byte(pass), salt, ArgonTime, ArgonMemory, ArgonThreads, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.NewX(pwdKey) // bad-key-len
	memZero(pwdKey)                            // minimum exposure time
	if err != nil {
		return nil, nil, nil, err
	}
	enc = make([]byte, 0, SecretKeySize*2) // to avoid realloc (includes Poly1305 tag)
	enc = aead.Seal(enc, nonce, secret, nil)

	return salt, nonce, enc, err
}

func (km *keyMgr) generateMnemonic() (mnemonic []string, seed []byte, pub []byte, err error) {
	attempt := 0
	for attempt < 1000 {
		mnemonic, err := bip39.GenerateRandomMnemonic(MnemonicEntropyBits, bip39.EnglishWordList)
		if err != nil {
			return nil, nil, nil, err // only ErrOutOfEntropy
		}

		// cannot use the password as BIP39 passphrase here,
		// otherwise we cannot support password recovery.
		newseed, err := bip39.SeedFromMnemonic(mnemonic, "", bip39.EnglishWordList) // ErrWrongLength,ErrWrongWord,ErrWrongChecksum
		if err != nil {
			log.Printf("BUG: could not decode generated mnemonic: %v", mnemonic)
			attempt += 1
			continue
		}

		// generate Bip32 master key from seed
		master, err := doge.Bip32MasterFromSeed(newseed, &doge.DogeMainNetChain) // ErrBadSeed,ErrAnotherSeed
		memZero(newseed)                                                         // clear seed material
		if err != nil {
			if errors.Is(err, doge.ErrAnotherSeed) {
				attempt += 1
				continue
			}
			return nil, nil, nil, err
		}
		newpub := master.GetECPubKey()
		pub := newpub[:]

		// encode the master key as a string byte-array.
		// not ideal, but this is the Bip32 serialization format.
		priv := []byte(master.EncodeWIF())
		master.Clear() // clear key material
		return mnemonic, priv, pub, nil
	}
	return nil, nil, nil, ErrTooManyAttempts
}

var arrayOfZeroBytes [128]byte // 128 zero-bytes (1-2 cache lines)

func memZero(slice []byte) {
	n := copy(slice, arrayOfZeroBytes[:])
	for n < len(slice) {
		n += copy(slice[n:], arrayOfZeroBytes[:])
	}
}
