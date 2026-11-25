package password

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Strength describes the storage protection provided by a password format.
type Strength int

const (
	// UnknownStrength means no recognized primary password verifier is present.
	UnknownStrength Strength = iota
	// WeakStrength is an unsalted, single-round digest such as SHA-256.
	WeakStrength
	// StrongStrength is a salted, cost-based hash such as bcrypt.
	StrongStrength
)

// Format names identify the supported primary password formats.
const (
	UnknownFormat = "unknown"
	SHA256Format  = "sha256"
	BcryptFormat  = "bcrypt"
)

// String returns the canonical format name for a strength.
func (s Strength) String() string {
	switch s {
	case WeakStrength:
		return SHA256Format
	case StrongStrength:
		return BcryptFormat
	default:
		return UnknownFormat
	}
}

// SHA256Hex returns the legacy unsalted SHA-256 password representation used by
// passsha256 fields.
func SHA256Hex(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// HashSHA256 is an alias for SHA256Hex.
func HashSHA256(password string) string {
	return SHA256Hex(password)
}

// Hash creates the canonical strong representation: lowercase hexadecimal
// encoding of a bcrypt hash. The hexadecimal encoding is the on-disk format
// already used by passbcrypt.
func Hash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hashed), nil
}

// HashBcrypt is an alias for Hash.
func HashBcrypt(password string) (string, error) {
	return Hash(password)
}

// VerifySHA256 compares a hexadecimal SHA-256 digest with password.
func VerifySHA256(stored, password string) bool {
	decoded, err := hex.DecodeString(strings.TrimSpace(stored))
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	sum := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(decoded, sum[:]) == 1
}

// VerifyBcrypt compares a stored hexadecimal bcrypt hash with password. Raw
// bcrypt hashes are also accepted to make the classifier useful at boundaries
// that do not use GLAuth's historical hex encoding.
func VerifyBcrypt(stored, password string) bool {
	normalized := strings.TrimSpace(stored)
	hash, err := hex.DecodeString(normalized)
	if err != nil || len(hash) == 0 {
		hash = []byte(normalized)
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

// IsBcrypt reports whether stored looks like a bcrypt hash in either its raw
// or hexadecimally encoded form.
func IsBcrypt(stored string) bool {
	trimmed := strings.TrimSpace(stored)
	if strings.HasPrefix(trimmed, "$2") {
		return isRawBcrypt(trimmed)
	}

	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return false
	}
	return isRawBcrypt(string(decoded))
}

func isRawBcrypt(value string) bool {
	// bcrypt hashes are $2<version>$<two-digit cost>$<22-char salt><31-char hash>.
	return len(value) == 60 &&
		strings.HasPrefix(value, "$2") &&
		strings.Count(value, "$") == 3
}

// IsSHA256 reports whether stored looks like a 32-byte hexadecimal digest.
func IsSHA256(stored string) bool {
	trimmed := strings.TrimSpace(stored)
	if len(trimmed) != hex.EncodedLen(sha256.Size) {
		return false
	}
	_, err := hex.DecodeString(trimmed)
	return err == nil
}

// Classify identifies a standalone stored hash. Account records should normally
// use ClassifyPrimary, because the field itself also declares the format.
func Classify(stored string) Strength {
	switch {
	case IsBcrypt(stored):
		return StrongStrength
	case IsSHA256(stored):
		return WeakStrength
	default:
		return UnknownStrength
	}
}

// ClassifyPrimary applies the storage policy to the two historical primary
// password fields. A configured strong field wins over a legacy field, even
// when both rows contain values.
func ClassifyPrimary(bcryptHash, sha256Hash string) Strength {
	if strings.TrimSpace(bcryptHash) != "" {
		return StrongStrength
	}
	if strings.TrimSpace(sha256Hash) != "" {
		return WeakStrength
	}
	return UnknownStrength
}

// NeedsUpgrade reports whether the primary credential is only present in the
// deprecated weak format.
func NeedsUpgrade(bcryptHash, sha256Hash string) bool {
	return strings.TrimSpace(bcryptHash) == "" && strings.TrimSpace(sha256Hash) != ""
}

// VerifyPrimary verifies password against the policy-selected primary hash.
// It never falls back from a configured strong hash to a weak hash.
func VerifyPrimary(bcryptHash, sha256Hash, password string) (bool, Strength) {
	result := VerifyPrimaryDetailed(bcryptHash, sha256Hash, password)
	return result.Valid, result.Strength
}

// Verification describes a policy-selected primary password check.
type Verification struct {
	Valid     bool
	Strength  Strength
	Malformed bool
}

// VerifyPrimaryDetailed is VerifyPrimary with a malformed-storage marker.
func VerifyPrimaryDetailed(bcryptHash, sha256Hash, password string) Verification {
	strength := ClassifyPrimary(bcryptHash, sha256Hash)
	switch strength {
	case StrongStrength:
		_, hexErr := hex.DecodeString(strings.TrimSpace(bcryptHash))
		if hexErr != nil && !IsBcrypt(bcryptHash) {
			return Verification{Valid: false, Strength: StrongStrength, Malformed: true}
		}
		return Verification{Valid: VerifyBcrypt(bcryptHash, password), Strength: StrongStrength}
	case WeakStrength:
		return Verification{Valid: VerifySHA256(sha256Hash, password), Strength: WeakStrength}
	default:
		return Verification{Valid: false, Strength: UnknownStrength}
	}
}
