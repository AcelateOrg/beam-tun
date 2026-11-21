//go:build !windows && !linux && !darwin

package dialer

import "errors"

func bindToInterface(uintptr, string, Interface) error {
	return errors.New("dialer: interface binding is not supported on this platform")
}
