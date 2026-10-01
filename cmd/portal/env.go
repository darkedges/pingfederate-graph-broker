package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// loadEnvFile reads only portal settings. It does not evaluate shell syntax,
// interpolate variables, or expose values in errors or command arguments.
// Explicit process environment values take precedence over the file.
func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open portal environment file: %w", err)
	}
	defer f.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !validEnvName(key) {
			return fmt.Errorf("invalid portal environment file line %d", lineNumber)
		}
		if !strings.HasPrefix(key, "PORTAL_") {
			continue
		}
		if _, exists := values[key]; exists {
			return fmt.Errorf("duplicate portal setting on line %d", lineNumber)
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '\'' && value[len(value)-1] == '\'' || value[0] == '"' && value[len(value)-1] == '"') {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read portal environment file: %w", err)
	}
	for key, value := range values {
		if _, set := os.LookupEnv(key); !set {
			if err := os.Setenv(key, value); err != nil {
				return fmt.Errorf("set portal environment variable %s: %w", key, err)
			}
		}
	}
	return nil
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}
