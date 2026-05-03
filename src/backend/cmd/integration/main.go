package main

import (
	"context"
	"crypto/aes"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/golang-jwt/jwt/v5"
)

const (
	integrationID         = "connector"
	integrationName       = "Connector Blinds"
	protocolName          = "connector"
	defaultPort           = "8099"
	defaultSetupPath      = "config/connector.secrets.json"
	defaultMQTTBroker     = "tcp://emqx:1883"
	defaultPollInterval   = 60
	udpSendPort           = 32100
	multicastListenAddr   = "238.0.0.18"
	multicastListenPort   = 32101
	defaultUDPTimeout     = 3 * time.Second
	followUpSyncDelay     = 3 * time.Second
	multicastRetryDelay   = 30 * time.Second
	maxResponseSize       = 4096
	commandSetState       = "set_state"
	deviceCommandBasePath = "/api/device/"
)

type claims struct {
	Role string `json:"role"`
	Name string `json:"name"`
	jwt.RegisteredClaims
}

type authGuard struct {
	pubKey  *rsa.PublicKey
	enabled bool
}

func newAuthGuardFromEnv() (*authGuard, error) {
	path := strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY_PATH"))
	inlineKey := strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY"))
	if path == "" && inlineKey == "" {
		return &authGuard{enabled: false}, nil
	}
	var keyData []byte
	if inlineKey != "" {
		keyData = []byte(inlineKey)
	} else {
		var err error
		keyData, err = os.ReadFile(path) // #nosec G304 -- env configured path
		if err != nil {
			return nil, err
		}
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}
	return &authGuard{pubKey: pubKey, enabled: true}, nil
}

func (a *authGuard) requireRole(w http.ResponseWriter, r *http.Request, required string) bool {
	if a == nil || !a.enabled || a.pubKey == nil {
		log.Printf("auth unavailable for %s %s", r.Method, r.URL.Path)
		writeJSONError(w, http.StatusServiceUnavailable, "auth not configured")
		return false
	}
	tokenStr := extractToken(r)
	if tokenStr == "" {
		log.Printf("auth missing token for %s %s", r.Method, r.URL.Path)
		writeJSONError(w, http.StatusUnauthorized, "missing token")
		return false
	}
	token, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(token *jwt.Token) (interface{}, error) {
		return a.pubKey, nil
	})
	if err != nil || !token.Valid {
		log.Printf("auth invalid token for %s %s: %v", r.Method, r.URL.Path, err)
		writeJSONError(w, http.StatusUnauthorized, "invalid token")
		return false
	}
	parsedClaims, ok := token.Claims.(*claims)
	if !ok {
		log.Printf("auth invalid claims for %s %s", r.Method, r.URL.Path)
		writeJSONError(w, http.StatusUnauthorized, "invalid claims")
		return false
	}
	if !roleAtLeast(required, strings.TrimSpace(parsedClaims.Role)) {
		log.Printf("auth forbidden for %s %s: need=%s have=%s", r.Method, r.URL.Path, required, strings.TrimSpace(parsedClaims.Role))
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

func extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	if cookie, err := r.Cookie("auth_token"); err == nil {
		return cookie.Value
	}
	return ""
}

func roleAtLeast(required, actual string) bool {
	roleRank := map[string]int{
		"public":   0,
		"user":     1,
		"resident": 2,
		"admin":    3,
		"service":  4,
	}
	return roleRank[actual] >= roleRank[required]
}

type setupConfig struct {
	GatewayHost     string `json:"gateway_host"`
	APIKey          string `json:"api_key"`
	PollIntervalSec int    `json:"poll_interval_sec"`
}

func (c setupConfig) normalized() setupConfig {
	c.GatewayHost = normalizeHosts(c.GatewayHost)
	c.APIKey = strings.TrimSpace(c.APIKey)
	if c.PollIntervalSec <= 0 {
		c.PollIntervalSec = defaultPollInterval
	}
	return c
}

func (c setupConfig) validate() error {
	if len(c.hosts()) == 0 {
		return errors.New("gateway_host is required")
	}
	if c.APIKey == "" {
		return errors.New("api_key is required")
	}
	if len(c.APIKey) != 16 {
		return errors.New("api_key must be exactly 16 characters including hyphens")
	}
	if c.PollIntervalSec < 5 || c.PollIntervalSec > 3600 {
		return errors.New("poll_interval_sec must be between 5 and 3600")
	}
	return nil
}

func (c setupConfig) hosts() []string {
	return parseHosts(c.GatewayHost)
}

func parseHosts(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', '\n', '\r', ';':
			return true
		default:
			return false
		}
	})
	if len(parts) == 0 {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	}
	seen := make(map[string]struct{}, len(parts))
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		host := strings.TrimSpace(part)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
}

func normalizeHosts(raw string) string {
	return strings.Join(parseHosts(raw), ", ")
}

func hostMatches(hosts []string, actual string) bool {
	actual = strings.TrimSpace(actual)
	if actual == "" {
		return false
	}
	for _, host := range hosts {
		if strings.EqualFold(strings.TrimSpace(host), actual) {
			return true
		}
	}
	return false
}

type setupStore struct {
	path string
	mu   sync.Mutex
}

func newSetupStore(path string) *setupStore {
	return &setupStore{path: path}
}

func (s *setupStore) load() (setupConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cfg setupConfig
	payload, err := os.ReadFile(s.path) // #nosec G304 -- configured file path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return setupConfig{PollIntervalSec: defaultPollInterval}, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return cfg, err
	}
	cfg = cfg.normalized()
	if cfg.PollIntervalSec == 0 {
		cfg.PollIntervalSec = defaultPollInterval
	}
	return cfg, nil
}

func (s *setupStore) save(cfg setupConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg = cfg.normalized()
	if err := cfg.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		if !errors.Is(err, os.ErrPermission) {
			return err
		}
		log.Printf("setup store temp write fallback for %s: %v", s.path, err)
		return os.WriteFile(s.path, payload, 0o600)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		if removeErr := os.Remove(tmp); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			log.Printf("setup store temp cleanup failed for %s: %v", tmp, removeErr)
		}
		if !errors.Is(err, os.ErrPermission) {
			return err
		}
		log.Printf("setup store rename fallback for %s: %v", s.path, err)
		return os.WriteFile(s.path, payload, 0o600)
	}
	return nil
}

type gatewayState struct {
	Host            string `json:"host"`
	GatewayMAC      string `json:"gateway_mac,omitempty"`
	DeviceType      string `json:"device_type,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	Status          string `json:"status,omitempty"`
	Available       bool   `json:"available"`
	DeviceCount     int    `json:"device_count"`
	RSSI            *int   `json:"rssi,omitempty"`
	LastSyncAt      string `json:"last_sync_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
}

type blindDevice struct {
	ID             string        `json:"id"`
	MAC            string        `json:"mac"`
	Host           string        `json:"host,omitempty"`
	Name           string        `json:"name"`
	DeviceType     string        `json:"device_type,omitempty"`
	BlindTypeCode  int           `json:"blind_type_code,omitempty"`
	BlindType      string        `json:"blind_type,omitempty"`
	Description    string        `json:"description,omitempty"`
	Online         bool          `json:"online"`
	Status         any           `json:"status,omitempty"`
	LimitStatus    any           `json:"limit_status,omitempty"`
	Position       any           `json:"position,omitempty"`
	OpenPercent    *float64      `json:"open_percent,omitempty"`
	TiltPercent    *float64      `json:"tilt_percent,omitempty"`
	BatteryLevel   any           `json:"battery_level,omitempty"`
	BatteryVoltage any           `json:"battery_voltage,omitempty"`
	Charging       *bool         `json:"charging,omitempty"`
	RSSI           *int          `json:"rssi,omitempty"`
	WirelessMode   string        `json:"wireless_mode,omitempty"`
	VoltageMode    string        `json:"voltage_mode,omitempty"`
	LastSeen       string        `json:"last_seen,omitempty"`
	UpdatedAt      string        `json:"updated_at,omitempty"`
	Inputs         []bridgeInput `json:"inputs,omitempty"`
}

type bridgeCapability struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	Property  string         `json:"property"`
	ValueType string         `json:"value_type"`
	Unit      string         `json:"unit,omitempty"`
	Range     map[string]any `json:"range,omitempty"`
	Enum      []any          `json:"enum,omitempty"`
	Access    map[string]any `json:"access"`
}

type bridgeInput struct {
	ID           string           `json:"id"`
	Label        string           `json:"label"`
	Type         string           `json:"type"`
	CapabilityID string           `json:"capability_id"`
	Property     string           `json:"property"`
	Options      []map[string]any `json:"options,omitempty"`
	Range        map[string]any   `json:"range,omitempty"`
}

type snapshotState struct {
	Configured bool          `json:"configured"`
	Gateway    gatewayState  `json:"gateway"`
	Devices    []blindDevice `json:"devices"`
}

type deviceStore struct {
	mu      sync.RWMutex
	gateway gatewayState
	devices map[string]blindDevice
}

func newDeviceStore() *deviceStore {
	return &deviceStore{devices: make(map[string]blindDevice)}
}

func (s *deviceStore) snapshot(configured bool) snapshotState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	devices := make([]blindDevice, 0, len(s.devices))
	for _, device := range s.devices {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		return strings.ToLower(devices[i].Name) < strings.ToLower(devices[j].Name)
	})
	return snapshotState{Configured: configured, Gateway: s.gateway, Devices: devices}
}

func (s *deviceStore) replace(gateway gatewayState, devices []blindDevice) (removed []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		seen[device.ID] = struct{}{}
	}
	for id := range s.devices {
		if _, ok := seen[id]; !ok {
			removed = append(removed, id)
		}
	}
	next := make(map[string]blindDevice, len(devices))
	for _, device := range devices {
		next[device.ID] = device
	}
	s.devices = next
	s.gateway = gateway
	sort.Strings(removed)
	return removed
}

func (s *deviceStore) upsert(device blindDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[device.ID] = device
}

func (s *deviceStore) get(id string) (blindDevice, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	device, ok := s.devices[id]
	return device, ok
}

func (s *deviceStore) setGateway(gateway gatewayState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gateway = gateway
}

type connectorBridge struct {
	setup      *setupStore
	store      *deviceStore
	mqttClient mqtt.Client
	manualSync chan string
}

type multicastListener struct {
	conn *net.UDPConn
}

type connectorDeviceRef struct {
	MAC        string
	DeviceType string
}

type connectorClient struct {
	host           string
	apiKey         string
	timeout        time.Duration
	multiRespDelay time.Duration
	gatewayMAC     string
	gatewayType    string
	protocol       string
	firmware       string
	token          string
	accessToken    string
}

type deviceCommandEnvelope struct {
	Schema   string         `json:"schema,omitempty"`
	Type     string         `json:"type,omitempty"`
	DeviceID string         `json:"device_id,omitempty"`
	Command  string         `json:"command,omitempty"`
	Args     map[string]any `json:"args,omitempty"`
	Corr     string         `json:"corr,omitempty"`
}

type deviceCommandRequest struct {
	State  map[string]any `json:"state,omitempty"`
	Action string         `json:"action,omitempty"`
	Corr   string         `json:"corr,omitempty"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	port := envOrDefault("PORT", defaultPort)
	setupPath := envOrDefault("CONNECTOR_SETUP_PATH", defaultSetupPath)
	webRoot := envOrDefault("WEB_ROOT", "web")

	auth, err := newAuthGuardFromEnv()
	if err != nil {
		log.Fatalf("load auth: %v", err)
	}
	setup := newSetupStore(setupPath)
	store := newDeviceStore()
	bridge := &connectorBridge{
		setup:      setup,
		store:      store,
		manualSync: make(chan string, 1),
	}

	mqttClient, err := newMQTTClient(bridge)
	if err != nil {
		log.Printf("mqtt disabled: %v", err)
	} else {
		bridge.mqttClient = mqttClient
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bridge.run(ctx)
	go bridge.runRealtime(ctx)

	mux := http.NewServeMux()
	registerAPI(mux, auth, bridge)
	registerStatic(mux, webRoot)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("%s listening on :%s", integrationName, port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}

func registerAPI(mux *http.ServeMux, auth *authGuard, bridge *connectorBridge) {
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "integration": integrationID})
	})
	mux.HandleFunc("/api/setup", func(w http.ResponseWriter, r *http.Request) {
		if !auth.requireRole(w, r, "admin") {
			return
		}
		switch r.Method {
		case http.MethodGet:
			log.Printf("setup requested: method=GET remote=%s", r.RemoteAddr)
			cfg, err := bridge.setup.load()
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			log.Printf("setup loaded: hosts=%q poll_interval=%d api_key_length=%d", cfg.GatewayHost, cfg.PollIntervalSec, len(cfg.APIKey))
			writeJSON(w, http.StatusOK, cfg)
		case http.MethodPost:
			var cfg setupConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid json")
				return
			}
			cfg = cfg.normalized()
			log.Printf("setup verify started: hosts=%q host_count=%d poll_interval=%d api_key_length=%d", cfg.GatewayHost, len(cfg.hosts()), cfg.PollIntervalSec, len(cfg.APIKey))
			if err := cfg.validate(); err != nil {
				log.Printf("setup verify rejected: %v", err)
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			probe, devices, err := probeGateway(r.Context(), cfg)
			if err != nil {
				log.Printf("setup verify failed: %v", err)
				if probe.LastError != "" {
					log.Printf("setup verify details: %s", probe.LastError)
				}
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := bridge.setup.save(cfg); err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			log.Printf("setup saved: hosts=%q devices=%d", cfg.GatewayHost, len(devices))
			bridge.triggerSync("setup saved")
			writeJSON(w, http.StatusOK, map[string]any{
				"saved":        true,
				"gateway":      probe,
				"device_count": len(devices),
			})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireRole(w, r, "resident") {
			return
		}
		bridge.triggerSync("manual api sync")
		writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
	})
	mux.HandleFunc("/api/realtime/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireRole(w, r, "resident") {
			return
		}
		cfg, err := bridge.setup.load()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, bridge.store.snapshot(cfg.GatewayHost != "" && cfg.APIKey != ""))
	})
	mux.HandleFunc(deviceCommandBasePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !auth.requireRole(w, r, "resident") {
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/command") {
			http.NotFound(w, r)
			return
		}
		rawID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, deviceCommandBasePath), "/command")
		if rawID == "" {
			http.NotFound(w, r)
			return
		}
		deviceID, err := url.PathUnescape(rawID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid device id")
			return
		}
		var req deviceCommandRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if req.Corr == "" {
			req.Corr = newMsgID()
		}
		updated, err := bridge.dispatchDeviceCommand(r.Context(), deviceID, req, req.Corr)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device": updated, "corr": req.Corr})
	})
}

func registerStatic(mux *http.ServeMux, webRoot string) {
	fileServer := http.FileServer(http.Dir(webRoot))
	mux.Handle("/assets/", fileServer)
	mux.Handle("/ui/", fileServer)
	mux.Handle("/widgets/", fileServer)
	mux.Handle("/.well-known/", fileServer)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/ui/dashboard.html", http.StatusTemporaryRedirect)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func probeGateway(ctx context.Context, cfg setupConfig) (gatewayState, []blindDevice, error) {
	hosts := cfg.hosts()
	if len(hosts) == 0 {
		return gatewayState{}, nil, errors.New("gateway_host is required")
	}
	log.Printf("probing connector endpoints: %s", strings.Join(hosts, ", "))
	devicesByID := make(map[string]blindDevice)
	var firstGateway gatewayState
	successfulHosts := 0
	errorsByHost := make([]string, 0)
	for _, host := range hosts {
		log.Printf("probe host start: %s", host)
		client := newConnectorClientForHost(cfg, host)
		refs, err := client.getDeviceList(ctx)
		if err != nil {
			log.Printf("probe host device list failed: host=%s err=%v", host, err)
			errorsByHost = append(errorsByHost, fmt.Sprintf("%s: %v", host, err))
			continue
		}
		log.Printf("probe host device list ok: host=%s refs=%d", host, len(refs))
		gateway, err := client.readGateway(ctx)
		if err != nil {
			log.Printf("probe host gateway read failed: host=%s err=%v", host, err)
			errorsByHost = append(errorsByHost, fmt.Sprintf("%s: %v", host, err))
			continue
		}
		if successfulHosts == 0 {
			firstGateway = gateway
		}
		successfulHosts++
		for _, ref := range refs {
			payload, err := client.readDevice(ctx, ref.MAC, ref.DeviceType)
			if err != nil {
				log.Printf("probe device read failed: host=%s mac=%s type=%s err=%v", host, ref.MAC, ref.DeviceType, err)
				errorsByHost = append(errorsByHost, fmt.Sprintf("%s/%s: %v", host, ref.MAC, err))
				continue
			}
			device := blindDeviceFromResponse(payload, ref.MAC, ref.DeviceType, host)
			log.Printf("probe device ok: host=%s device_id=%s name=%q", host, device.ID, device.Name)
			devicesByID[device.ID] = device
		}
	}
	devices := make([]blindDevice, 0, len(devicesByID))
	for _, device := range devicesByID {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		return strings.ToLower(devices[i].Name) < strings.ToLower(devices[j].Name)
	})
	gateway := firstGateway
	gateway.Host = strings.Join(hosts, ", ")
	gateway.DeviceCount = len(devices)
	gateway.Available = successfulHosts > 0
	gateway.LastSyncAt = time.Now().UTC().Format(time.RFC3339)
	if len(hosts) > 1 {
		gateway.Status = fmt.Sprintf("%d/%d endpoints reachable", successfulHosts, len(hosts))
	}
	if len(errorsByHost) > 0 {
		gateway.LastError = strings.Join(errorsByHost, " | ")
	}
	if successfulHosts == 0 {
		log.Printf("probe failed: no reachable endpoints")
		if gateway.LastError == "" {
			gateway.LastError = "no endpoint responded"
		}
		return gateway, nil, errors.New(gateway.LastError)
	}
	log.Printf("probe completed: reachable=%d total=%d devices=%d", successfulHosts, len(hosts), len(devices))
	return gateway, devices, nil
}

func (b *connectorBridge) run(ctx context.Context) {
	b.publishAdapterStatus(true, "starting")
	b.triggerSync("initial sync")

	var ticker *time.Ticker
	var tickC <-chan time.Time
	currentInterval := time.Duration(defaultPollInterval) * time.Second

	for {
		cfg, err := b.setup.load()
		if err == nil {
			interval := time.Duration(cfg.normalized().PollIntervalSec) * time.Second
			if ticker == nil || interval != currentInterval {
				if ticker != nil {
					ticker.Stop()
				}
				currentInterval = interval
				ticker = time.NewTicker(interval)
				tickC = ticker.C
			}
		}

		select {
		case <-ctx.Done():
			if ticker != nil {
				ticker.Stop()
			}
			b.publishAdapterStatus(false, "stopped")
			return
		case <-tickC:
			if err := b.syncOnce(ctx); err != nil {
				log.Printf("sync failed: %v", err)
			}
		case reason := <-b.manualSync:
			log.Printf("sync requested: %s", reason)
			if err := b.syncOnce(ctx); err != nil {
				log.Printf("sync failed: %v", err)
			}
		}
	}
}

func (b *connectorBridge) runRealtime(ctx context.Context) {
	for {
		if err := b.listenForRealtime(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("realtime listener unavailable: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(multicastRetryDelay):
		}
	}
}

func (b *connectorBridge) listenForRealtime(ctx context.Context) error {
	listener, err := newMulticastListener()
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("realtime listener active on %s:%d", multicastListenAddr, multicastListenPort)
	buffer := make([]byte, maxResponseSize)
	for {
		if err := listener.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		n, src, err := listener.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}
		b.handleRealtimePacket(buffer[:n], src)
	}
}

func newMulticastListener() (*multicastListener, error) {
	group := &net.UDPAddr{IP: net.ParseIP(multicastListenAddr), Port: multicastListenPort}
	conn, err := net.ListenMulticastUDP("udp4", nil, group)
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadBuffer(maxResponseSize * 4); err != nil {
		log.Printf("realtime listener read buffer warning: %v", err)
	}
	return &multicastListener{conn: conn}, nil
}

func (l *multicastListener) Close() {
	if l == nil || l.conn == nil {
		return
	}
	if err := l.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("realtime listener close warning: %v", err)
	}
}

func (b *connectorBridge) handleRealtimePacket(payload []byte, src *net.UDPAddr) {
	var message map[string]any
	if err := json.Unmarshal(payload, &message); err != nil {
		return
	}
	msgType := responseType(message)
	if msgType != "Report" && msgType != "ReadDeviceAck" && msgType != "WriteDeviceAck" {
		return
	}

	mac := firstNonEmpty(stringValue(message, "mac"), stringValue(dataMap(message), "mac"))
	if mac == "" {
		return
	}
	id := deviceID(mac)
	current, ok := b.store.get(id)
	if !ok {
		if src != nil {
			if cfg, err := b.setup.load(); err == nil && hostMatches(cfg.hosts(), src.IP.String()) {
				log.Printf("realtime listener discovered unknown device from %s, scheduling sync", src.IP.String())
				b.triggerSync("realtime discovered unknown device")
			}
		}
		return
	}

	host := current.Host
	if src != nil && src.IP != nil {
		host = firstNonEmpty(host, src.IP.String())
	}
	updated := blindDeviceFromResponse(message, current.MAC, current.DeviceType, host)
	updated = mergeBlindDevice(current, updated)
	b.store.upsert(updated)
	b.publishDevice(updated, "")
	log.Printf("realtime update applied: device_id=%s type=%s source=%s", updated.ID, msgType, host)
}

func (b *connectorBridge) triggerSync(reason string) {
	select {
	case b.manualSync <- reason:
	default:
	}
}

func (b *connectorBridge) syncOnce(ctx context.Context) error {
	cfg, err := b.setup.load()
	if err != nil {
		return err
	}
	cfg = cfg.normalized()
	if len(cfg.hosts()) == 0 || cfg.APIKey == "" {
		b.store.setGateway(gatewayState{Host: cfg.GatewayHost, Available: false, LastError: "integration not configured"})
		b.publishAdapterStatus(false, "not configured")
		return nil
	}

	gateway, devices, err := probeGateway(ctx, cfg)
	if err != nil {
		state := gatewayState{Host: cfg.GatewayHost, Available: false, LastError: err.Error(), LastSyncAt: time.Now().UTC().Format(time.RFC3339)}
		b.store.setGateway(state)
		b.publishAdapterStatus(false, err.Error())
		return err
	}
	removed := b.store.replace(gateway, devices)
	b.publishAdapterStatus(true, fmt.Sprintf("ok: %d devices", len(devices)))
	for _, id := range removed {
		b.clearRetainedTopics(id)
		b.publishJSON(fmt.Sprintf("homenavi/hdp/device/event/%s", id), map[string]any{
			"schema":    "hdp.v1",
			"type":      "event",
			"device_id": id,
			"event":     "device_removed",
			"data":      map[string]any{},
			"ts":        nowMillis(),
		}, false)
	}
	for _, device := range devices {
		b.publishDevice(device, "")
	}
	return nil
}

func (b *connectorBridge) dispatchDeviceCommand(ctx context.Context, deviceID string, req deviceCommandRequest, corr string) (blindDevice, error) {
	cfg, err := b.setup.load()
	if err != nil {
		return blindDevice{}, err
	}
	cfg = cfg.normalized()
	if err := cfg.validate(); err != nil {
		return blindDevice{}, err
	}
	current, ok := b.store.get(deviceID)
	if !ok {
		return blindDevice{}, errors.New("device not found")
	}
	data, err := buildCommandData(current, req)
	if err != nil {
		return blindDevice{}, err
	}
	client := newConnectorClientForHost(cfg, current.Host)
	if _, err := client.getDeviceList(ctx); err != nil {
		return blindDevice{}, err
	}
	response, err := client.writeDevice(ctx, current.MAC, current.DeviceType, data)
	if err != nil {
		b.publishCommandResult(deviceID, corr, false, "failed", true, err.Error())
		return blindDevice{}, err
	}
	updated := blindDeviceFromResponse(response, current.MAC, current.DeviceType, current.Host)
	if updated.Name == "" {
		updated.Name = current.Name
	}
	b.store.upsert(updated)
	b.publishCommandResult(deviceID, corr, true, "in_progress", false, "")
	b.publishDevice(updated, corr)
	b.publishCommandResult(deviceID, corr, true, "applied", true, "")
	go func() {
		time.Sleep(followUpSyncDelay)
		b.triggerSync("post-command follow-up")
	}()
	return updated, nil
}

func buildCommandData(device blindDevice, req deviceCommandRequest) (map[string]any, error) {
	data := map[string]any{}
	state := req.State
	if state == nil {
		state = map[string]any{}
	}
	if req.Action != "" {
		state["action"] = req.Action
	}
	if raw, ok := state["action"]; ok {
		action := strings.ToLower(strings.TrimSpace(fmt.Sprint(raw)))
		switch action {
		case "open":
			data["operation"] = 1
		case "close":
			data["operation"] = 0
		case "stop":
			data["operation"] = 2
		case "favorite":
			data["operation"] = 12
		case "refresh":
			data["operation"] = 5
		case "":
		default:
			return nil, fmt.Errorf("unsupported action %q", action)
		}
	}
	if raw, ok := state["open_percent"]; ok {
		if device.OpenPercent == nil {
			return nil, errors.New("open_percent is not supported by this device")
		}
		openPercent, err := toFloat(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid open_percent: %w", err)
		}
		data["targetPosition"] = int(math.Round(clamp(openPercent, 0, 100)))
		data["targetPosition"] = 100 - data["targetPosition"].(int)
	}
	if raw, ok := state["tilt_percent"]; ok {
		if !deviceSupportsTilt(device) {
			return nil, errors.New("tilt_percent is not supported by this device")
		}
		tiltPercent, err := toFloat(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid tilt_percent: %w", err)
		}
		data["targetAngle"] = int(math.Round(clamp(tiltPercent, 0, 100) * 180.0 / 100.0))
	}
	if len(data) == 0 {
		return nil, errors.New("no supported command fields provided")
	}
	_ = device
	return data, nil
}

func newMQTTClient(bridge *connectorBridge) (mqtt.Client, error) {
	broker := strings.TrimSpace(envOrDefault("MQTT_BROKER_URL", defaultMQTTBroker))
	if broker == "" {
		return nil, errors.New("MQTT_BROKER_URL is empty")
	}
	clientID := envOrDefault("MQTT_CLIENT_ID", fmt.Sprintf("homenavi-connector-%d", time.Now().UnixNano()))
	opts := mqtt.NewClientOptions().AddBroker(broker).SetClientID(clientID)
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetKeepAlive(30 * time.Second)
	opts.SetPingTimeout(10 * time.Second)
	if username := strings.TrimSpace(os.Getenv("MQTT_USERNAME")); username != "" {
		opts.SetUsername(username)
		opts.SetPassword(os.Getenv("MQTT_PASSWORD"))
	}
	opts.OnConnect = func(client mqtt.Client) {
		log.Printf("mqtt connected")
		if token := client.Subscribe("homenavi/hdp/device/command/connector/#", 1, bridge.handleMQTTCommand); token.Wait() && token.Error() != nil {
			log.Printf("mqtt subscribe failed: %v", token.Error())
		}
		bridge.publishAdapterHello()
		bridge.publishAdapterStatus(true, "connected")
	}
	opts.OnConnectionLost = func(_ mqtt.Client, err error) {
		log.Printf("mqtt disconnected: %v", err)
	}
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}
	return client, nil
}

func (b *connectorBridge) handleMQTTCommand(_ mqtt.Client, msg mqtt.Message) {
	deviceID := strings.TrimPrefix(msg.Topic(), "homenavi/hdp/device/command/")
	var env deviceCommandEnvelope
	if err := json.Unmarshal(msg.Payload(), &env); err != nil {
		log.Printf("invalid mqtt command payload for %s: %v", deviceID, err)
		return
	}
	if env.Command != "" && env.Command != commandSetState {
		b.publishCommandResult(deviceID, env.Corr, false, "rejected", true, fmt.Sprintf("unsupported command %q", env.Command))
		return
	}
	req := deviceCommandRequest{State: env.Args, Corr: env.Corr}
	if _, err := b.dispatchDeviceCommand(context.Background(), deviceID, req, env.Corr); err != nil {
		log.Printf("mqtt command failed for %s: %v", deviceID, err)
	}
}

func (b *connectorBridge) publishAdapterHello() {
	payload := map[string]any{
		"schema":     "hdp.v1",
		"type":       "hello",
		"adapter_id": integrationID,
		"protocol":   protocolName,
		"name":       integrationName,
		"ts":         nowMillis(),
	}
	b.publishJSON("homenavi/hdp/adapter/hello", payload, false)
}

func (b *connectorBridge) publishAdapterStatus(online bool, detail string) {
	payload := map[string]any{
		"schema":     "hdp.v1",
		"type":       "status",
		"adapter_id": integrationID,
		"protocol":   protocolName,
		"online":     online,
		"detail":     detail,
		"ts":         nowMillis(),
	}
	b.publishJSON("homenavi/hdp/adapter/status/connector", payload, true)
}

func (b *connectorBridge) publishDevice(device blindDevice, corr string) {
	metadata := map[string]any{
		"schema":       "hdp.v1",
		"type":         "metadata",
		"device_id":    device.ID,
		"protocol":     protocolName,
		"manufacturer": "Connector",
		"model":        firstNonEmpty(device.BlindType, device.DeviceType),
		"description":  firstNonEmpty(device.Description, "Connector smart blind"),
		"icon":         "door",
		"online":       device.Online,
		"last_seen":    device.LastSeen,
		"ts":           nowMillis(),
		"capabilities": capabilitiesForDevice(device),
		"inputs":       inputsForDevice(device),
	}
	state := map[string]any{
		"schema":    "hdp.v1",
		"type":      "state",
		"device_id": device.ID,
		"ts":        nowMillis(),
		"state":     deviceStateForPublish(device),
	}
	if corr != "" {
		state["corr"] = corr
	}
	b.publishJSON(fmt.Sprintf("homenavi/hdp/device/metadata/%s", device.ID), metadata, true)
	b.publishJSON(fmt.Sprintf("homenavi/hdp/device/state/%s", device.ID), state, true)
}

func (b *connectorBridge) publishCommandResult(deviceID, corr string, success bool, status string, terminal bool, errMsg string) {
	payload := map[string]any{
		"schema":    "hdp.v1",
		"type":      "command_result",
		"origin":    integrationID,
		"device_id": deviceID,
		"corr":      corr,
		"success":   success,
		"status":    status,
		"terminal":  terminal,
		"ts":        nowMillis(),
	}
	if errMsg != "" {
		payload["error"] = errMsg
	}
	b.publishJSON(fmt.Sprintf("homenavi/hdp/device/command_result/%s", deviceID), payload, false)
}

func (b *connectorBridge) clearRetainedTopics(deviceID string) {
	b.publishRaw(fmt.Sprintf("homenavi/hdp/device/metadata/%s", deviceID), []byte{}, true)
	b.publishRaw(fmt.Sprintf("homenavi/hdp/device/state/%s", deviceID), []byte{}, true)
}

func (b *connectorBridge) publishJSON(topic string, payload any, retained bool) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("marshal publish payload failed for %s: %v", topic, err)
		return
	}
	b.publishRaw(topic, body, retained)
}

func (b *connectorBridge) publishRaw(topic string, payload []byte, retained bool) {
	if b.mqttClient == nil || !b.mqttClient.IsConnected() {
		return
	}
	token := b.mqttClient.Publish(topic, 1, retained, payload)
	if token.WaitTimeout(5*time.Second) && token.Error() != nil {
		log.Printf("mqtt publish failed for %s: %v", topic, token.Error())
	}
}

func newConnectorClient(cfg setupConfig) *connectorClient {
	cfg = cfg.normalized()
	return &connectorClient{
		host:           cfg.GatewayHost,
		apiKey:         cfg.APIKey,
		timeout:        defaultUDPTimeout,
		multiRespDelay: 200 * time.Millisecond,
	}
}

func newConnectorClientForHost(cfg setupConfig, host string) *connectorClient {
	cfg = cfg.normalized()
	cfg.GatewayHost = strings.TrimSpace(host)
	return newConnectorClient(cfg)
}

func (c *connectorClient) getDeviceList(ctx context.Context) ([]connectorDeviceRef, error) {
	responses, err := c.send(ctx, map[string]any{
		"msgType": "GetDeviceList",
		"msgID":   newMsgID(),
	})
	if err != nil {
		return nil, err
	}
	var refs []connectorDeviceRef
	for _, response := range responses {
		if responseType(response) != "GetDeviceListAck" {
			continue
		}
		if err := checkActionResult(response); err != nil {
			return nil, err
		}
		c.gatewayMAC = stringValue(response, "mac")
		c.gatewayType = stringValue(response, "deviceType")
		c.protocol = stringValue(response, "ProtocolVersion")
		c.firmware = stringValue(response, "fwVersion")
		c.token = stringValue(response, "token")
		access, err := accessToken(c.token, c.apiKey)
		if err != nil {
			return nil, err
		}
		c.accessToken = access
		for _, item := range dataSlice(response) {
			refs = append(refs, connectorDeviceRef{
				MAC:        stringValue(item, "mac"),
				DeviceType: stringValue(item, "deviceType"),
			})
		}
	}
	if c.gatewayMAC == "" {
		return nil, errors.New("gateway did not return a device list")
	}
	return refs, nil
}

func (c *connectorClient) readGateway(ctx context.Context) (gatewayState, error) {
	if c.gatewayMAC == "" || c.accessToken == "" {
		if _, err := c.getDeviceList(ctx); err != nil {
			return gatewayState{}, err
		}
	}
	responses, err := c.send(ctx, map[string]any{
		"msgType":     "ReadDevice",
		"msgID":       newMsgID(),
		"mac":         c.gatewayMAC,
		"deviceType":  c.gatewayType,
		"AccessToken": c.accessToken,
	})
	if err != nil {
		return gatewayState{}, err
	}
	for _, response := range responses {
		if responseType(response) != "ReadDeviceAck" {
			continue
		}
		if err := checkActionResult(response); err != nil {
			return gatewayState{}, err
		}
		state := gatewayState{
			Host:            c.host,
			GatewayMAC:      firstNonEmpty(stringValue(response, "mac"), c.gatewayMAC),
			DeviceType:      firstNonEmpty(stringValue(response, "deviceType"), c.gatewayType),
			ProtocolVersion: firstNonEmpty(c.protocol, stringValue(response, "ProtocolVersion")),
			FirmwareVersion: firstNonEmpty(c.firmware, stringValue(response, "fwVersion")),
			Available:       true,
			LastSyncAt:      time.Now().UTC().Format(time.RFC3339),
		}
		data := dataMap(response)
		state.Status = gatewayStatusName(intValue(data, "currentStatus"))
		state.DeviceCount = intValue(data, "numberOfDevices")
		if rssi, ok := optionalInt(data, "RSSI"); ok {
			state.RSSI = &rssi
		}
		return state, nil
	}
	return gatewayState{}, errors.New("gateway status response missing")
}

func (c *connectorClient) readDevice(ctx context.Context, mac, deviceType string) (map[string]any, error) {
	if c.accessToken == "" {
		if _, err := c.getDeviceList(ctx); err != nil {
			return nil, err
		}
	}
	responses, err := c.send(ctx, map[string]any{
		"msgType":     "ReadDevice",
		"msgID":       newMsgID(),
		"mac":         mac,
		"deviceType":  deviceType,
		"AccessToken": c.accessToken,
	})
	if err != nil {
		return nil, err
	}
	for _, response := range responses {
		if responseType(response) != "ReadDeviceAck" {
			continue
		}
		if err := checkActionResult(response); err != nil {
			return nil, err
		}
		return response, nil
	}
	return nil, errors.New("device status response missing")
}

func (c *connectorClient) writeDevice(ctx context.Context, mac, deviceType string, data map[string]any) (map[string]any, error) {
	if c.accessToken == "" {
		if _, err := c.getDeviceList(ctx); err != nil {
			return nil, err
		}
	}
	responses, err := c.send(ctx, map[string]any{
		"msgType":     "WriteDevice",
		"msgID":       newMsgID(),
		"mac":         mac,
		"deviceType":  deviceType,
		"AccessToken": c.accessToken,
		"data":        data,
	})
	if err != nil {
		return nil, err
	}
	for _, response := range responses {
		if responseType(response) != "WriteDeviceAck" && responseType(response) != "Report" {
			continue
		}
		if err := checkActionResult(response); err != nil {
			return nil, err
		}
		return response, nil
	}
	return nil, errors.New("device command response missing")
}

func (c *connectorClient) send(ctx context.Context, payload map[string]any) ([]map[string]any, error) {
	remote, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.host, udpSendPort))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(body); err != nil {
		return nil, err
	}
	responses := make([]map[string]any, 0, 2)
	buffer := make([]byte, maxResponseSize)
	deadline := time.Now().Add(c.timeout)
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if len(responses) == 0 {
					return nil, fmt.Errorf("gateway %s timed out", c.host)
				}
				break
			}
			return nil, err
		}
		var response map[string]any
		if err := json.Unmarshal(buffer[:n], &response); err != nil {
			return nil, fmt.Errorf("invalid gateway response: %w", err)
		}
		responses = append(responses, response)
		deadline = time.Now().Add(c.multiRespDelay)
	}
	return responses, nil
}

func blindDeviceFromResponse(response map[string]any, fallbackMAC, fallbackType, host string) blindDevice {
	data := dataMap(response)
	deviceType := firstNonEmpty(stringValue(response, "deviceType"), fallbackType)
	mac := firstNonEmpty(stringValue(response, "mac"), fallbackMAC)
	blindTypeCode := intValue(data, "type")
	blindType := blindTypeName(blindTypeCode)
	name := friendlyName(mac, blindType)
	device := blindDevice{
		ID:            deviceID(mac),
		MAC:           mac,
		Host:          host,
		Name:          name,
		DeviceType:    deviceType,
		BlindTypeCode: blindTypeCode,
		BlindType:     blindType,
		Description:   descriptionForBlind(blindType),
		Online:        true,
		Status:        blindStatusValue(deviceType, data),
		LimitStatus:   limitStatusValue(deviceType, data),
		Position:      positionValue(deviceType, data),
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
		LastSeen:      time.Now().UTC().Format(time.RFC3339),
	}
	if openPercent, ok := openPercentValue(deviceType, data); ok {
		device.OpenPercent = &openPercent
	}
	if supportsTilt(deviceType, blindTypeCode) {
		if tiltPercent, ok := tiltPercentValue(deviceType, data); ok {
			device.TiltPercent = &tiltPercent
		}
	}
	if voltage, ok := batteryVoltageValue(deviceType, data); ok {
		device.BatteryVoltage = voltage
	}
	if level, ok := batteryLevelValue(deviceType, data); ok {
		device.BatteryLevel = level
	}
	if charging, ok := chargingValue(data); ok {
		device.Charging = &charging
	}
	if rssi, ok := optionalInt(data, "RSSI"); ok {
		device.RSSI = &rssi
	}
	device.WirelessMode = wirelessModeName(intValue(data, "wirelessMode"))
	device.VoltageMode = voltageModeName(intValue(data, "voltageMode"))
	device.Inputs = inputsForDevice(device)
	return device
}

func mergeBlindDevice(current, incoming blindDevice) blindDevice {
	merged := incoming
	merged.ID = firstNonEmpty(incoming.ID, current.ID)
	merged.MAC = firstNonEmpty(incoming.MAC, current.MAC)
	merged.Host = firstNonEmpty(incoming.Host, current.Host)
	merged.Name = firstNonEmpty(incoming.Name, current.Name)
	merged.DeviceType = firstNonEmpty(incoming.DeviceType, current.DeviceType)
	if merged.BlindTypeCode == 0 {
		merged.BlindTypeCode = current.BlindTypeCode
	}
	merged.BlindType = firstNonEmpty(incoming.BlindType, current.BlindType)
	merged.Description = firstNonEmpty(incoming.Description, current.Description)
	if merged.Status == nil {
		merged.Status = current.Status
	}
	if merged.LimitStatus == nil {
		merged.LimitStatus = current.LimitStatus
	}
	if merged.Position == nil {
		merged.Position = current.Position
	}
	if merged.OpenPercent == nil {
		merged.OpenPercent = current.OpenPercent
	}
	if merged.TiltPercent == nil {
		merged.TiltPercent = current.TiltPercent
	}
	if merged.BatteryLevel == nil {
		merged.BatteryLevel = current.BatteryLevel
	}
	if merged.BatteryVoltage == nil {
		merged.BatteryVoltage = current.BatteryVoltage
	}
	if merged.Charging == nil {
		merged.Charging = current.Charging
	}
	if merged.RSSI == nil {
		merged.RSSI = current.RSSI
	}
	merged.WirelessMode = firstNonEmpty(incoming.WirelessMode, current.WirelessMode)
	merged.VoltageMode = firstNonEmpty(incoming.VoltageMode, current.VoltageMode)
	merged.LastSeen = firstNonEmpty(incoming.LastSeen, current.LastSeen)
	merged.UpdatedAt = firstNonEmpty(incoming.UpdatedAt, current.UpdatedAt)
	merged.Inputs = inputsForDevice(merged)
	return merged
}

func deviceStateForPublish(device blindDevice) map[string]any {
	state := map[string]any{
		"online":       device.Online,
		"status":       device.Status,
		"limit_status": device.LimitStatus,
	}
	if device.Position != nil {
		state["position"] = device.Position
	}
	if device.OpenPercent != nil {
		state["open_percent"] = *device.OpenPercent
		state["closed_percent"] = 100 - *device.OpenPercent
	}
	if device.TiltPercent != nil {
		state["tilt_percent"] = *device.TiltPercent
	}
	if device.BatteryLevel != nil {
		state["battery"] = device.BatteryLevel
	}
	if device.BatteryVoltage != nil {
		state["battery_voltage"] = device.BatteryVoltage
	}
	if device.Charging != nil {
		state["charging"] = *device.Charging
	}
	if device.RSSI != nil {
		state["rssi"] = *device.RSSI
	}
	if device.WirelessMode != "" {
		state["wireless_mode"] = device.WirelessMode
	}
	if device.VoltageMode != "" {
		state["voltage_mode"] = device.VoltageMode
	}
	return state
}

func capabilitiesForDevice(device blindDevice) []bridgeCapability {
	caps := []bridgeCapability{}
	if device.OpenPercent != nil {
		caps = append(caps, bridgeCapability{
			ID:        "cover.position",
			Name:      "Open Position",
			Kind:      "actuator",
			Property:  "open_percent",
			ValueType: "number",
			Unit:      "%",
			Range:     map[string]any{"min": 0, "max": 100, "step": 1},
			Access:    map[string]any{"read": true, "write": true, "event": true},
		})
	}
	caps = append(caps,
		bridgeCapability{
			ID:        "cover.action",
			Name:      "Action",
			Kind:      "actuator",
			Property:  "action",
			ValueType: "enum",
			Enum:      []any{"open", "close", "stop", "favorite"},
			Access:    map[string]any{"read": false, "write": true, "event": false},
		},
		bridgeCapability{
			ID:        "cover.status",
			Name:      "Status",
			Kind:      "sensor",
			Property:  "status",
			ValueType: "string",
			Access:    map[string]any{"read": true, "write": false, "event": true},
		},
	)
	if deviceSupportsTilt(device) {
		caps = append(caps, bridgeCapability{
			ID:        "cover.tilt",
			Name:      "Tilt",
			Kind:      "actuator",
			Property:  "tilt_percent",
			ValueType: "number",
			Unit:      "%",
			Range:     map[string]any{"min": 0, "max": 100, "step": 1},
			Access:    map[string]any{"read": true, "write": true, "event": true},
		})
	}
	if device.BatteryLevel != nil {
		caps = append(caps, bridgeCapability{
			ID:        "battery",
			Name:      "Battery",
			Kind:      "sensor",
			Property:  "battery",
			ValueType: "number",
			Unit:      "%",
			Range:     map[string]any{"min": 0, "max": 100, "step": 1},
			Access:    map[string]any{"read": true, "write": false, "event": true},
		})
	}
	return caps
}

func inputsForDevice(device blindDevice) []bridgeInput {
	inputs := []bridgeInput{}
	if device.OpenPercent != nil {
		inputs = append(inputs, bridgeInput{
			ID:           "set_open_percent",
			Label:        "Open",
			Type:         "slider",
			CapabilityID: "cover.position",
			Property:     "open_percent",
			Range:        map[string]any{"min": 0, "max": 100, "step": 1},
		})
	}
	inputs = append(inputs, bridgeInput{
		ID:           "set_action",
		Label:        "Action",
		Type:         "select",
		CapabilityID: "cover.action",
		Property:     "action",
		Options: []map[string]any{
			{"value": "open", "label": "Open"},
			{"value": "close", "label": "Close"},
			{"value": "stop", "label": "Stop"},
			{"value": "favorite", "label": "Favorite"},
		},
	})
	if deviceSupportsTilt(device) {
		inputs = append(inputs, bridgeInput{
			ID:           "set_tilt_percent",
			Label:        "Tilt",
			Type:         "slider",
			CapabilityID: "cover.tilt",
			Property:     "tilt_percent",
			Range:        map[string]any{"min": 0, "max": 100, "step": 1},
		})
	}
	return inputs
}

func accessToken(token, key string) (string, error) {
	if len(token) != 16 || len(key) != 16 {
		return "", errors.New("token and key must be 16 characters")
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	plain := []byte(token)
	ciphertext := make([]byte, 16)
	block.Encrypt(ciphertext, plain)
	return strings.ToUpper(hex.EncodeToString(ciphertext)), nil
}

func responseType(payload map[string]any) string {
	return stringValue(payload, "msgType")
}

func checkActionResult(response map[string]any) error {
	if actionResult, ok := response["actionResult"]; ok {
		return fmt.Errorf("gateway rejected request: %s", fmt.Sprint(actionResult))
	}
	return nil
}

func dataMap(response map[string]any) map[string]any {
	if raw, ok := response["data"].(map[string]any); ok {
		return raw
	}
	return map[string]any{}
}

func dataSlice(response map[string]any) []map[string]any {
	raw, ok := response["data"].([]any)
	if !ok {
		return nil
	}
	items := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if parsed, ok := item.(map[string]any); ok {
			items = append(items, parsed)
		}
	}
	return items
}

func stringValue(data map[string]any, key string) string {
	if raw, ok := data[key]; ok {
		return strings.TrimSpace(fmt.Sprint(raw))
	}
	return ""
}

func intValue(data map[string]any, key string) int {
	value, _ := optionalInt(data, key)
	return value
}

func optionalInt(data map[string]any, key string) (int, bool) {
	raw, ok := data[key]
	if !ok || raw == nil {
		return 0, false
	}
	switch value := raw.(type) {
	case float64:
		return int(math.Round(value)), true
	case float32:
		return int(math.Round(float64(value))), true
	case int:
		return value, true
	case int64:
		return int(value), true
	case json.Number:
		parsed, err := value.Int64()
		if err == nil {
			return int(parsed), true
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func toFloat(value any) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case json.Number:
		return v.Float64()
	case string:
		return strconv.ParseFloat(strings.TrimSpace(v), 64)
	default:
		return 0, fmt.Errorf("unsupported numeric value %T", value)
	}
}

func positionValue(deviceType string, data map[string]any) any {
	if deviceType == "10000001" {
		top, topOK := optionalInt(data, "currentPosition_T")
		bottom, bottomOK := optionalInt(data, "currentPosition_B")
		if !topOK && !bottomOK {
			return nil
		}
		combined := float64(top+bottom) / 2.0
		return map[string]any{"T": top, "B": bottom, "C": combined}
	}
	if position, ok := optionalInt(data, "currentPosition"); ok {
		return position
	}
	return nil
}

func openPercentValue(deviceType string, data map[string]any) (float64, bool) {
	if deviceType == "10000001" {
		top, topOK := optionalInt(data, "currentPosition_T")
		bottom, bottomOK := optionalInt(data, "currentPosition_B")
		if !topOK && !bottomOK {
			return 0, false
		}
		width := float64(bottom - top)
		return clamp(100-width, 0, 100), true
	}
	if position, ok := optionalInt(data, "currentPosition"); ok {
		return clamp(100-float64(position), 0, 100), true
	}
	return 0, false
}

func tiltPercentValue(deviceType string, data map[string]any) (float64, bool) {
	if deviceType == "10000001" {
		if angle, ok := optionalInt(data, "currentAngle_B"); ok {
			return clamp(float64(angle)*100.0/180.0, 0, 100), true
		}
		return 0, false
	}
	if angle, ok := optionalInt(data, "currentAngle"); ok {
		return clamp(float64(angle)*100.0/180.0, 0, 100), true
	}
	return 0, false
}

func supportsTilt(deviceType string, blindTypeCode int) bool {
	if deviceType == "10000001" {
		return true
	}
	switch blindTypeCode {
	case 2, 5, 11, 15, 21, 22, 28, 29:
		return true
	}
	name := strings.ToLower(blindTypeName(blindTypeCode))
	for _, marker := range []string{"tilt", "venetian", "vertical", "shutter", "shangrila", "dimming"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func deviceSupportsTilt(device blindDevice) bool {
	return device.TiltPercent != nil && supportsTilt(device.DeviceType, device.BlindTypeCode)
}

func batteryVoltageValue(deviceType string, data map[string]any) (any, bool) {
	if deviceType == "10000001" {
		result := map[string]float64{}
		if raw, ok := optionalInt(data, "batteryLevel_T"); ok {
			result["T"] = float64(raw) / 100.0
		}
		if raw, ok := optionalInt(data, "batteryLevel_B"); ok {
			result["B"] = float64(raw) / 100.0
		}
		if len(result) > 0 {
			return result, true
		}
		return nil, false
	}
	if voltage, ok := optionalInt(data, "batteryLevel"); ok {
		return float64(voltage) / 100.0, true
	}
	return nil, false
}

func batteryLevelValue(deviceType string, data map[string]any) (any, bool) {
	if deviceType == "10000001" {
		result := map[string]float64{}
		if raw, ok := optionalInt(data, "batteryLevel_T"); ok {
			result["T"] = estimateBatteryPercent(raw)
		}
		if raw, ok := optionalInt(data, "batteryLevel_B"); ok {
			result["B"] = estimateBatteryPercent(raw)
		}
		if len(result) > 0 {
			return result, true
		}
		return nil, false
	}
	if raw, ok := optionalInt(data, "batteryLevel"); ok {
		return estimateBatteryPercent(raw), true
	}
	return nil, false
}

func estimateBatteryPercent(raw int) float64 {
	voltage := float64(raw)
	switch {
	case voltage <= 0:
		return 0
	case voltage >= 1600:
		return 100
	case voltage <= 1100:
		return 0
	default:
		return math.Round((voltage - 1100.0) * 100.0 / 500.0)
	}
}

func chargingValue(data map[string]any) (bool, bool) {
	if raw, ok := optionalInt(data, "chargingState"); ok {
		return raw == 1, true
	}
	return false, false
}

func blindStatusValue(deviceType string, data map[string]any) any {
	if deviceType == "10000001" {
		status := map[string]string{}
		if raw, ok := optionalInt(data, "operation_T"); ok {
			status["T"] = blindStatusName(raw)
		}
		if raw, ok := optionalInt(data, "operation_B"); ok {
			status["B"] = blindStatusName(raw)
		}
		if len(status) == 0 {
			return nil
		}
		return status
	}
	if raw, ok := optionalInt(data, "operation"); ok {
		return blindStatusName(raw)
	}
	return nil
}

func limitStatusValue(deviceType string, data map[string]any) any {
	if deviceType == "10000001" {
		limit := map[string]string{}
		if raw, ok := optionalInt(data, "currentState_T"); ok {
			limit["T"] = limitStatusName(raw)
		}
		if raw, ok := optionalInt(data, "currentState_B"); ok {
			limit["B"] = limitStatusName(raw)
		}
		if len(limit) == 0 {
			return nil
		}
		return limit
	}
	if raw, ok := optionalInt(data, "currentState"); ok {
		return limitStatusName(raw)
	}
	return nil
}

func friendlyName(mac, blindType string) string {
	suffix := mac
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	kind := firstNonEmpty(blindType, "Blind")
	return fmt.Sprintf("%s %s", kind, suffix)
}

func descriptionForBlind(blindType string) string {
	if blindType == "" {
		return "Connector smart blind"
	}
	return fmt.Sprintf("Connector %s device", blindType)
}

func blindTypeName(value int) string {
	blindTypes := map[int]string{
		1:  "RollerBlind",
		2:  "VenetianBlind",
		3:  "RomanBlind",
		4:  "HoneycombBlind",
		5:  "ShangriLaBlind",
		6:  "RollerShutter",
		7:  "RollerGate",
		8:  "Awning",
		9:  "TopDownBottomUp",
		10: "DayNightBlind",
		11: "DimmingBlind",
		12: "Curtain",
		13: "CurtainLeft",
		14: "CurtainRight",
		15: "RollerTiltMotor",
		17: "DoubleRoller",
		21: "VerticalBlindLeft",
		22: "WoodShutter",
		24: "RadioReceiver",
		26: "SkylightBlind",
		27: "DualShade",
		28: "VerticalBlind",
		29: "VerticalBlindRight",
		40: "WovenWoodShades",
		43: "Switch",
		44: "InsectScreen",
		57: "TriangleBlind",
	}
	if name, ok := blindTypes[value]; ok {
		return name
	}
	if value == 0 {
		return ""
	}
	return fmt.Sprintf("Type%d", value)
}

func blindStatusName(value int) string {
	statuses := map[int]string{
		0: "Closing",
		1: "Opening",
		2: "Stopped",
		5: "StatusQuery",
		6: "FirmwareBug",
		7: "JogUp",
		8: "JogDown",
	}
	if name, ok := statuses[value]; ok {
		return name
	}
	return "Unknown"
}

func limitStatusName(value int) string {
	statuses := map[int]string{
		0: "NoLimitDetected",
		1: "TopLimitDetected",
		2: "BottomLimitDetected",
		3: "BothLimitsDetected",
		4: "Limit3Detected",
	}
	if name, ok := statuses[value]; ok {
		return name
	}
	return "Unknown"
}

func voltageModeName(value int) string {
	statuses := map[int]string{
		0: "AC",
		1: "DC",
	}
	if name, ok := statuses[value]; ok {
		return name
	}
	return "Unknown"
}

func wirelessModeName(value int) string {
	statuses := map[int]string{
		0: "UniDirection",
		1: "BiDirection",
		2: "BiDirectionLimits",
		3: "WiFi",
		4: "VirtualPercentageLimits",
		5: "Others",
	}
	if name, ok := statuses[value]; ok {
		return name
	}
	return "Unknown"
}

func gatewayStatusName(value int) string {
	statuses := map[int]string{
		1: "Working",
		2: "Pairing",
		3: "Updating",
	}
	if name, ok := statuses[value]; ok {
		return name
	}
	return "Unknown"
}

func deviceID(mac string) string {
	return protocolName + "/" + mac
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func newMsgID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func nowMillis() int64 {
	return time.Now().UnixMilli()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message, "code": status})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
