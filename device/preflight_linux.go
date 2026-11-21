//go:build linux && !android

// The !android constraint is intentional: Go sets the linux tag for
// GOOS=android too, but nothing here applies on Android - the TUN fd comes from
// VpnService instead of /dev/net/tun and the app has no CAP_NET_ADMIN. Without
// !android these prechecks would always block connecting on the phone.
//
// Called from Open() in device.go before /dev/net/tun is opened, so a missing
// module or capability turns into a clear error message.

package device

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const tunDevicePath = "/dev/net/tun"

// capNetAdminBit — номер CAP_NET_ADMIN в наборе capabilities (linux/capability.h).
const capNetAdminBit = 12

// preflightTun проверяет системные предусловия для TUN до старта ядра.
//
// Без него пользователь видел сырой errno от драйвера: "configure tun
// interface: no such device". Формулировка сбивает с толку дважды — звучит
// как отсутствие файла, хотя /dev/net/tun на месте, и не подсказывает, что
// делать. Реальных причин всего две, и обе лечатся одной командой, поэтому
// дешевле проверить их заранее и сказать словами.
func preflightTun() error {
	if err := checkTunDevice(); err != nil {
		return err
	}
	return checkNetAdmin()
}

func checkTunDevice() error {
	file, err := os.OpenFile(tunDevicePath, os.O_RDWR, 0)
	if err == nil {
		_ = file.Close()
		return nil
	}

	switch {
	// Именно ENODEV, а не ENOENT: узел устройства на месте, но за ним нет
	// драйвера — модуль tun не загружен. Обычное дело для минимальных образов,
	// контейнеров и свежих виртуалок.
	case errors.Is(err, syscall.ENODEV):
		return fmt.Errorf("модуль ядра tun не загружен, поэтому %s не открывается. Выполните: sudo modprobe tun. Чтобы модуль подхватывался после перезагрузки: echo tun | sudo tee /etc/modules-load.d/tun.conf", tunDevicePath)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("в системе нет %s — ядро собрано без поддержки TUN/TAP либо устройство не создано. Выполните: sudo modprobe tun", tunDevicePath)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("нет доступа к %s. Посмотрите права на устройство: ls -l %s", tunDevicePath, tunDevicePath)
	}
	return fmt.Errorf("не удалось открыть %s: %w", tunDevicePath, err)
}

func checkNetAdmin() error {
	ok, err := hasCapNetAdmin()
	if err != nil {
		// Не смогли прочитать /proc — не повод блокировать запуск. В экзотическом
		// окружении (свой LSM, урезанный procfs) пусть лучше попробует ядро и
		// упадёт само, чем мы не пустим пользователя дальше по своей догадке.
		return nil
	}
	if ok {
		return nil
	}

	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "<путь к beam>"
	}
	return fmt.Errorf("у процесса нет CAP_NET_ADMIN — создать TUN-интерфейс нельзя. Выдайте права бинарнику: sudo setcap cap_net_admin,cap_net_raw+eip %s. Если getcap после этого ничего не показывает, бинарник лежит на файловой системе без расширенных атрибутов (шара гипервизора, NTFS) — перенесите его на ext4/btrfs", exe)
}

// hasCapNetAdmin читает эффективный набор capabilities из /proc/self/status.
// Под root там выставлены все биты, так что отдельная проверка uid не нужна.
func hasCapNetAdmin() (bool, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		value, found := strings.CutPrefix(line, "CapEff:")
		if !found {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return false, err
		}
		return mask&(1<<capNetAdminBit) != 0, nil
	}
	return false, errors.New("CapEff не найден в /proc/self/status")
}
