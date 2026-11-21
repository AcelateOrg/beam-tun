//go:build !windows && !darwin && (!linux || android)

package netcfg

// DefaultInterface is not implemented on this platform.
func DefaultInterface(exclude string) (string, error) {
	return "", ErrUnsupported
}
