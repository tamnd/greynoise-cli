package greynoise_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tamnd/greynoise-cli/greynoise"
)

func TestGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("request carried no User-Agent")
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := greynoise.NewClient()
	c.Rate = 0 // no pacing in the test

	body, err := c.GetRaw(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
}

func TestGetRetriesOn503(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("recovered"))
	}))
	defer srv.Close()

	c := greynoise.NewClient()
	c.Rate = 0
	c.Retries = 5

	start := time.Now()
	body, err := c.GetRaw(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "recovered" {
		t.Errorf("body = %q after retries", body)
	}
	if hits != 3 {
		t.Errorf("server saw %d hits, want 3", hits)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Error("retries did not back off")
	}
}

func TestGetIPQuiet(t *testing.T) {
	// Simulates the "not observed scanning" response for a quiet IP.
	payload := `{"ip":"8.8.8.8","noise":false,"riot":false,"message":"IP not observed scanning the internet."}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c := greynoise.NewClient()
	c.Rate = 0

	info, err := c.GetIPFrom(context.Background(), srv.URL+"/v3/community/8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if info.IP != "8.8.8.8" {
		t.Errorf("IP = %q, want 8.8.8.8", info.IP)
	}
	if info.Noise {
		t.Error("Noise = true, want false")
	}
	if info.RIOT {
		t.Error("RIOT = true, want false")
	}
	if info.Message == "" {
		t.Error("Message is empty, want non-empty")
	}
}

func TestGetIPNoisy(t *testing.T) {
	// Simulates a noisy/malicious IP response.
	payload := `{"ip":"1.2.3.4","noise":true,"riot":false,"classification":"malicious","name":"SomeScanner","link":"https://viz.greynoise.io/ip/1.2.3.4","last_seen":"2024-01-15"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c := greynoise.NewClient()
	c.Rate = 0

	info, err := c.GetIPFrom(context.Background(), srv.URL+"/v3/community/1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Noise {
		t.Error("Noise = false, want true")
	}
	if info.Classification != "malicious" {
		t.Errorf("Classification = %q, want malicious", info.Classification)
	}
	if info.Name != "SomeScanner" {
		t.Errorf("Name = %q, want SomeScanner", info.Name)
	}
	if info.LastSeen != "2024-01-15" {
		t.Errorf("LastSeen = %q, want 2024-01-15", info.LastSeen)
	}
}

func TestGetIPRIOT(t *testing.T) {
	// Simulates a RIOT (safe infrastructure) IP response.
	payload := `{"ip":"8.8.8.8","noise":false,"riot":true,"classification":"benign","name":"Google Public DNS","link":"https://viz.greynoise.io/riot/8.8.8.8","last_seen":"2024-01-15"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c := greynoise.NewClient()
	c.Rate = 0

	info, err := c.GetIPFrom(context.Background(), srv.URL+"/v3/community/8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if !info.RIOT {
		t.Error("RIOT = false, want true")
	}
	if info.Classification != "benign" {
		t.Errorf("Classification = %q, want benign", info.Classification)
	}
	if info.Name != "Google Public DNS" {
		t.Errorf("Name = %q, want Google Public DNS", info.Name)
	}
}

func TestGetIP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := greynoise.NewClient()
	c.Rate = 0
	c.Retries = 0

	_, err := c.GetIPFrom(context.Background(), srv.URL+"/v3/community/0.0.0.0")
	if err == nil {
		t.Error("expected error on 404, got nil")
	}
}

func TestIPInfoJSON(t *testing.T) {
	// Verify round-trip JSON encoding of IPInfo.
	original := &greynoise.IPInfo{
		IP:             "1.2.3.4",
		Noise:          true,
		RIOT:           false,
		Classification: "malicious",
		Name:           "BadActor",
		Link:           "https://viz.greynoise.io/ip/1.2.3.4",
		LastSeen:       "2024-01-15",
		Message:        "",
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got greynoise.IPInfo
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.IP != original.IP || got.Noise != original.Noise || got.Classification != original.Classification {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, original)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := greynoise.DefaultConfig()
	if cfg.Rate != 500*time.Millisecond {
		t.Errorf("Rate = %v, want 500ms", cfg.Rate)
	}
	if cfg.Retries != 5 {
		t.Errorf("Retries = %d, want 5", cfg.Retries)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", cfg.Timeout)
	}
}
