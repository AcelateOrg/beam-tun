// Package process maps a tunnelled flow to the executable that owns it, which
// drives per-app split tunneling. Only Windows has a real implementation.
package process

import "errors"

// ErrNotFound is returned when no process owns the flow (or the lookup is not
// supported on this platform).
var ErrNotFound = errors.New("tun: owning process not found")
