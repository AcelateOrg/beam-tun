//go:build !linux || android

package device

// preflightTun — no-op на платформах, где предстартовая проверка TUN не нужна:
//   - Windows: драйвер (wintun.dll) поставляется с приложением, права выданы
//     через UAC (см. internal/platform/privilege_windows.go).
//   - macOS: utun создаётся ядром, отдельных предусловий нет.
//   - Android: TUN fd приходит от VpnService, /dev/net/tun и CAP_NET_ADMIN
//     неприменимы.
func preflightTun() error { return nil }
