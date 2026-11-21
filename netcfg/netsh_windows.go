package netcfg

import (
	"fmt"
	"os"
	"strings"
)

// runNetshBatch выполняет набор netsh-команд ОДНИМ процессом через
// скриптовый файл. Остался только для разового системного отключения
// Teredo/6to4/ISATAP. netsh -f продолжает скрипт после ошибки строки, но
// возвращает ненулевой код — доброкачественный вывод ошибкой не считается.
func runNetshBatch(commands [][]string) error {
	if len(commands) == 0 {
		return nil
	}
	lines := make([]string, 0, len(commands))
	for _, args := range commands {
		if len(args) < 2 || args[0] != "netsh" {
			return fmt.Errorf("tun: internal: non-netsh command in batch: %v", args)
		}
		line := strings.Join(args[1:], " ")
		if !isASCII(line) {
			return runCommandsSerial(commands)
		}
		lines = append(lines, line)
	}

	file, err := os.CreateTemp("", "beam-netsh-*.txt")
	if err != nil {
		return runCommandsSerial(commands)
	}
	path := file.Name()
	if _, err := file.WriteString(strings.Join(lines, "\r\n") + "\r\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return runCommandsSerial(commands)
	}
	_ = file.Close()
	defer os.Remove(path)

	if err := runCommand([]string{"netsh", "-f", path}); err != nil && !netshOutputBenignText(err.Error()) {
		return err
	}
	return nil
}

// netshOutputBenignText — вывод из «Ok.» и доброкачественных «уже
// применено/уже удалено» ошибкой не является.
func netshOutputBenignText(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "Ok." || strings.HasPrefix(line, "netsh -f ") {
			continue
		}
		lower := strings.ToLower(line)
		benign := false
		for _, marker := range []string{
			"already exists", "уже существует", "object already exists", "file exists",
			"not found", "не найден", "no such", "not present",
			"cannot find", "не удается найти", "не найдено", "exit status",
		} {
			if strings.Contains(lower, marker) {
				benign = true
				break
			}
		}
		if !benign {
			return false
		}
	}
	return true
}

// runCommandsSerial — запасной путь: покомандный запуск с терпимостью к
// «уже применено»/«уже удалено».
func runCommandsSerial(commands [][]string) error {
	for _, args := range commands {
		if err := runSetupCommand(args); err != nil {
			return err
		}
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
