//go:build !darwin && (!linux || android)

package netcfg

// RecoverStale is a no-op here: on Windows everything the tunnel installs is
// bound to its adapter and disappears with it.
func RecoverStale() {}
