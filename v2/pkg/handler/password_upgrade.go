package handler

import (
	"context"
	"errors"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/password"
)

// ErrPasswordUpgradeConflict indicates that an optimistic password rewrite
// lost a compare-and-swap race. The winning request has already persisted a
// replacement, so authentication must remain successful.
var ErrPasswordUpgradeConflict = errors.New("password hash upgrade conflict")

// PasswordHashUpgrader is implemented by backends that can atomically replace
// a legacy password hash with a strong hash.
//
// Implementations should compare-and-swap on the legacy value (and usually an
// empty strong-field condition) so concurrent binds cannot overwrite a hash
// written by another request. Returning ErrPasswordUpgradeConflict means the
// caller should treat the record as already upgraded.
type PasswordHashUpgrader interface {
	UpgradePasswordHash(ctx context.Context, user config.User, bcryptHash string) error
}

// upgradeVerifiedPrimaryPassword performs best-effort transparent migration.
// A failure here never changes the LDAP bind result: the supplied password has
// already been verified against the legacy record.
func (l LDAPOpsHelper) upgradeVerifiedPrimaryPassword(
	ctx context.Context,
	h LDAPOpsHandler,
	user config.User,
	plaintextPassword string,
) {
	if h == nil || !password.NeedsUpgrade(user.PassBcrypt, user.PassSHA256) {
		return
	}

	strongHash, err := password.Hash(plaintextPassword)
	if err != nil {
		if logger := h.GetLog(); logger != nil {
			logger.Warn().
				Str("binddn", user.Name).
				Err(err).
				Msg("unable to generate strong password hash for transparent upgrade")
		}
		return
	}

	supported, err := invokePasswordUpgrade(ctx, h, user, strongHash, plaintextPassword)
	if !supported {
		return
	}

	if err != nil {
		if errors.Is(err, ErrPasswordUpgradeConflict) {
			if logger := h.GetLog(); logger != nil {
				logger.Debug().
					Str("user", user.Name).
					Msg("password hash was upgraded by another concurrent bind")
			}
			return
		}
		if logger := h.GetLog(); logger != nil {
			logger.Warn().
				Str("user", user.Name).
				Err(err).
				Msg("failed to persist strong password hash after legacy bind")
		}
	}
}
