//go:build !windows && !darwin && (!linux || android)

package netcfg

// Configure is unavailable here: on Android the VpnService owns the network
// setup of the tunnel.
func Configure(Config) (Network, error) {
	return nil, ErrUnsupported
}
