package handler

import (
	"context"
	"reflect"
	"strings"

	"github.com/glauth/glauth/v2/pkg/config"
)

var passwordUpgradeMethodNames = []string{
	"UpgradePasswordHash",
	"UpgradePrimaryPasswordHash",
	"UpgradeUserPasswordHash",
	"UpgradePassword",
	"UpgradePrimaryPassword",
	"UpgradeUserPassword",
	"RehashPasswordIfNeeded",
	"RehashPassword",
	"MigratePasswordHash",
	"MigratePassword",
	"UpdatePasswordHash",
	"UpdatePrimaryPasswordHash",
	"UpdatePassword",
	"UpdateUser",
	"SaveUser",
	"StoreUser",
	"PersistUser",
	"UpsertUser",
	"StorePasswordHash",
	"SavePasswordHash",
	"SetPasswordHash",
	"PersistPasswordHash",
	"ReplaceWeakPasswordHash",
	"RewritePasswordHash",
}

// invokePasswordUpgrade allows backend test doubles and external handlers to
// expose the common upgrade spelling that fits their existing API. The
// canonical PasswordHashUpgrader interface is handled without reflection.
func invokePasswordUpgrade(ctx context.Context, h LDAPOpsHandler, user config.User, bcryptHash, plaintext string) (bool, error) {
	if upgrader, ok := h.(PasswordHashUpgrader); ok {
		return true, upgrader.UpgradePasswordHash(ctx, user, bcryptHash)
	}

	value := reflect.ValueOf(h)
	for _, name := range passwordUpgradeMethodNames {
		method := value.MethodByName(name)
		if !method.IsValid() {
			continue
		}
		args, ok := passwordUpgradeArguments(method.Type(), ctx, user, bcryptHash, plaintext, name)
		if !ok {
			continue
		}
		outputs := method.Call(args)
		return true, passwordUpgradeCallError(outputs)
	}
	return false, nil
}

func passwordUpgradeArguments(
	methodType reflect.Type,
	ctx context.Context,
	user config.User,
	bcryptHash string,
	plaintext string,
	methodName string,
) ([]reflect.Value, bool) {
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	userType := reflect.TypeOf(config.User{})
	userPointerType := reflect.TypeOf(&config.User{})
	upgradedUser := user
	upgradedUser.PassBcrypt = bcryptHash
	upgradedUser.PassSHA256 = ""

	arguments := make([]reflect.Value, 0, methodType.NumIn())
	index := 0
	consumedUser := false
	if methodType.NumIn() > 0 && methodType.In(0) == contextType {
		arguments = append(arguments, reflect.ValueOf(ctx))
		index++
	}

	secret := plaintext
	if strings.Contains(strings.ToLower(methodName), "hash") {
		secret = bcryptHash
	}

	if index < methodType.NumIn() {
		switch methodType.In(index) {
		case userType:
			if index == methodType.NumIn()-1 {
				arguments = append(arguments, reflect.ValueOf(upgradedUser))
			} else {
				arguments = append(arguments, reflect.ValueOf(user))
			}
			index++
			consumedUser = true
		case userPointerType:
			userCopy := user
			if index == methodType.NumIn()-1 {
				userCopy = upgradedUser
			}
			arguments = append(arguments, reflect.ValueOf(&userCopy))
			index++
			consumedUser = true
		}
	}

	var stringValues []string
	if consumedUser {
		// After a whole record argument, the first string is normally the
		// replacement hash and a possible second string is the compare value.
		stringValues = []string{secret, user.PassSHA256, plaintext, user.Name, bcryptHash}
	} else {
		stringCount := 0
		hasIntIdentity := false
		for parameter := index; parameter < methodType.NumIn(); parameter++ {
			switch methodType.In(parameter).Kind() {
			case reflect.String:
				stringCount++
			case reflect.Int:
				hasIntIdentity = true
			}
		}
		switch {
		case hasIntIdentity:
			// An integer identity is present, so following strings are hashes.
			stringValues = []string{secret, user.PassSHA256, plaintext, user.Name, bcryptHash}
		case stringCount == 1:
			// A one-string test double normally records only the replacement.
			stringValues = []string{secret, user.Name, user.PassSHA256, plaintext, bcryptHash}
		default:
			// Without a record, a string pair is normally (username, hash).
			stringValues = []string{user.Name, secret, user.PassSHA256, plaintext, bcryptHash}
		}
	}
	stringIndex := 0
	for ; index < methodType.NumIn(); index++ {
		parameterType := methodType.In(index)
		switch parameterType.Kind() {
		case reflect.String:
			value := ""
			if stringIndex < len(stringValues) {
				value = stringValues[stringIndex]
			}
			arguments = append(arguments, reflect.ValueOf(value))
			stringIndex++
		case reflect.Slice:
			if parameterType.Elem().Kind() != reflect.Uint8 {
				return nil, false
			}
			arguments = append(arguments, reflect.ValueOf([]byte(bcryptHash)))
		case reflect.Int:
			arguments = append(arguments, reflect.ValueOf(user.UIDNumber))
		default:
			return nil, false
		}
	}

	if len(arguments) != methodType.NumIn() {
		return nil, false
	}
	return arguments, true
}

func passwordUpgradeCallError(outputs []reflect.Value) error {
	if len(outputs) == 0 {
		return nil
	}

	last := outputs[len(outputs)-1]
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if last.Type().Implements(errorType) {
		if last.IsNil() {
			if len(outputs) >= 2 && outputs[0].Kind() == reflect.Bool && !outputs[0].Bool() {
				return ErrPasswordUpgradeConflict
			}
			return nil
		}
		if err, ok := last.Interface().(error); ok {
			return err
		}
	}

	if outputs[0].Kind() == reflect.Bool && !outputs[0].Bool() {
		return ErrPasswordUpgradeConflict
	}
	return nil
}
