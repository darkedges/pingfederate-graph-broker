package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnvFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEnvFile(t *testing.T) {
	const secret = `s#c$ret=with spaces`
	path := writeEnvFixture(t, "# comment\r\nBROKER_PORT=18082\r\nPORTAL_PF_CLIENT_SECRET='"+secret+"'\r\nPORTAL_PF_CONNECT_START_URL=https://localhost:9031/sp/startSSO.ping?PartnerIdpId=test&TargetResource=a=b\r\n")
	t.Setenv("PORTAL_PF_CLIENT_SECRET", "explicit-secret")
	if err := loadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("PORTAL_PF_CLIENT_SECRET"); got != "explicit-secret" {
		t.Fatal("file overrode explicit environment")
	}
	if got := os.Getenv("PORTAL_PF_CONNECT_START_URL"); got != "https://localhost:9031/sp/startSSO.ping?PartnerIdpId=test&TargetResource=a=b" {
		t.Fatal("URL was not preserved")
	}
	t.Cleanup(func() { _ = os.Unsetenv("PORTAL_PF_CONNECT_START_URL") })
}

func TestLoadEnvFileRejectsDuplicateWithoutLeakingValue(t *testing.T) {
	const secret = "do-not-print-this"
	path := writeEnvFixture(t, "PORTAL_PF_CLIENT_SECRET="+secret+"\nPORTAL_PF_CLIENT_SECRET=another\n")
	err := loadEnvFile(path)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("duplicate was accepted or leaked")
	}
}

func TestLoadEnvFileRejectsMalformedLine(t *testing.T) {
	path := writeEnvFixture(t, "PORTAL_PF_CLIENT_SECRET=example\nnot an assignment\n")
	if err := loadEnvFile(path); err == nil {
		t.Fatal("malformed line accepted")
	}
}
