package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type config struct {
	listen, cert, key                                   string
	publicURL, pfURL, pfBrowserURL, brokerURL, startURL *url.URL
	clientID, clientSecret                              string
	agentClientID, agentClientSecret                    string
	samlConnectEnabled                                  bool
	referenceSubject, samlSubject                       string
}

func envURL(name string, required bool) (*url.URL, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" && !required {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid %s", name)
	}
	return u, nil
}

func loadConfig() (config, error) {
	c := config{listen: ":8788", cert: os.Getenv("PORTAL_TLS_CERT_FILE"), key: os.Getenv("PORTAL_TLS_KEY_FILE"), clientID: os.Getenv("PORTAL_PF_CLIENT_ID"), clientSecret: os.Getenv("PORTAL_PF_CLIENT_SECRET"), agentClientID: os.Getenv("PORTAL_AGENT_CLIENT_ID"), agentClientSecret: os.Getenv("PORTAL_AGENT_CLIENT_SECRET")}
	c.samlConnectEnabled = os.Getenv("PORTAL_SAML_CONNECT_ENABLED") == "true"
	c.referenceSubject = strings.TrimSpace(os.Getenv("PORTAL_REFERENCE_SUBJECT"))
	c.samlSubject = strings.TrimSpace(os.Getenv("PORTAL_SAML_SUBJECT"))
	if v := os.Getenv("PORTAL_LISTEN_ADDR"); v != "" {
		c.listen = v
	}
	var err error
	if c.publicURL, err = envURL("PORTAL_PUBLIC_URL", true); err != nil {
		return c, err
	}
	if c.pfURL, err = envURL("PORTAL_PF_URL", true); err != nil {
		return c, err
	}
	if c.pfBrowserURL, err = envURL("PORTAL_PF_BROWSER_URL", false); err != nil {
		return c, err
	}
	if c.pfBrowserURL == nil {
		c.pfBrowserURL = c.pfURL
	}
	if c.brokerURL, err = envURL("PORTAL_BROKER_URL", true); err != nil {
		return c, err
	}
	if c.startURL, err = envURL("PORTAL_PF_CONNECT_START_URL", false); err != nil {
		return c, err
	}
	if c.publicURL.Scheme != "https" || c.publicURL.Path != "" || c.publicURL.RawQuery != "" || c.pfURL.Scheme != "https" || c.pfURL.Path != "" || c.pfURL.RawQuery != "" ||
		c.pfBrowserURL.Scheme != "https" || c.pfBrowserURL.Path != "" || c.pfBrowserURL.RawQuery != "" {
		return c, errors.New("portal and PF URLs must be HTTPS origins")
	}
	if c.startURL != nil && (c.startURL.Scheme != "https" || c.startURL.Host != c.pfBrowserURL.Host) {
		return c, errors.New("PF connection start URL must use the configured PF HTTPS origin")
	}
	if c.startURL != nil && c.referenceSubject == "" {
		return c, errors.New("PORTAL_REFERENCE_SUBJECT is required for the PF Reference ID journey")
	}
	if c.samlConnectEnabled && c.samlSubject == "" {
		return c, errors.New("PORTAL_SAML_SUBJECT is required when SAML connection is enabled")
	}
	if c.referenceSubject != "" && c.referenceSubject == c.samlSubject {
		return c, errors.New("Reference ID and SAML subjects must differ")
	}
	if c.brokerURL.Scheme != "https" && !(c.brokerURL.Scheme == "http" && (c.brokerURL.Hostname() == "localhost" || c.brokerURL.Hostname() == "127.0.0.1")) {
		return c, errors.New("broker URL must use HTTPS or loopback HTTP")
	}
	if c.brokerURL.Path != "" || c.brokerURL.RawQuery != "" {
		return c, errors.New("broker URL must be an origin")
	}
	if c.cert == "" || c.key == "" {
		return c, errors.New("PORTAL_TLS_CERT_FILE and PORTAL_TLS_KEY_FILE are required")
	}
	if c.clientID == "" {
		return c, errors.New("PORTAL_PF_CLIENT_ID is required")
	}
	if c.clientSecret == "" {
		return c, errors.New("PORTAL_PF_CLIENT_SECRET is required")
	}
	if (c.agentClientID == "") != (c.agentClientSecret == "") {
		return c, errors.New("PORTAL_AGENT_CLIENT_ID and PORTAL_AGENT_CLIENT_SECRET must be set together")
	}
	return c, nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	envFile := flag.String("env-file", "", "load PORTAL_ settings from an environment file")
	flag.Parse()
	if *envFile != "" {
		if err := loadEnvFile(*envFile); err != nil {
			logger.Error("portal_configuration_failed", "error", err.Error())
			os.Exit(1)
		}
	}
	if strings.EqualFold(os.Getenv("PORTAL_LOG_LEVEL"), "debug") {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	if err := run(logger); err != nil {
		logger.Error("portal_stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	p := newPortal(c, logger)
	srv := &http.Server{Addr: c.listen, Handler: p.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		logger.Info("portal_listening", "address", c.listen)
		done <- srv.ListenAndServeTLS(c.cert, c.key)
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
