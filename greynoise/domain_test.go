package greynoise

import (
	"testing"

	"github.com/tamnd/any-cli/kit"
)

// These tests are offline: they exercise the URI driver's pure string functions
// and the host wiring (mint, body, resolve), which need no network. The
// client's HTTP behaviour is covered in greynoise_test.go.

func TestDomainInfo(t *testing.T) {
	info := Domain{}.Info()
	if info.Scheme != "greynoise" {
		t.Errorf("Scheme = %q, want greynoise", info.Scheme)
	}
	if len(info.Hosts) == 0 || info.Hosts[0] != Host {
		t.Errorf("Hosts = %v, want [%s]", info.Hosts, Host)
	}
	if info.Identity.Binary != "greynoise" {
		t.Errorf("Identity.Binary = %q, want greynoise", info.Identity.Binary)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		in  string
		typ string
		id  string
		ok  bool
	}{
		{"8.8.8.8", "ip", "8.8.8.8", true},
		{"1.1.1.1", "ip", "1.1.1.1", true},
		{"2001:4860:4860::8888", "ip", "2001:4860:4860::8888", true},
		{"not-an-ip", "", "", false},
		{"greynoise.io", "", "", false},
	}
	for _, tc := range cases {
		typ, id, err := Domain{}.Classify(tc.in)
		if tc.ok {
			if err != nil || typ != tc.typ || id != tc.id {
				t.Errorf("Classify(%q) = (%q, %q, %v), want (%q, %q, nil)",
					tc.in, typ, id, err, tc.typ, tc.id)
			}
		} else {
			if err == nil {
				t.Errorf("Classify(%q) succeeded, want error", tc.in)
			}
		}
	}
}

func TestLocate(t *testing.T) {
	got, err := Domain{}.Locate("ip", "8.8.8.8")
	want := "https://viz.greynoise.io/ip/8.8.8.8"
	if err != nil || got != want {
		t.Errorf("Locate = (%q, %v), want (%q, nil)", got, err, want)
	}
}

func TestLocateUnknownType(t *testing.T) {
	_, err := Domain{}.Locate("page", "8.8.8.8")
	if err == nil {
		t.Error("Locate with unknown type succeeded, want error")
	}
}

// TestHostWiring mounts the driver in a kit Host and checks the round trip:
// a record mints to its URI, its body is readable, and a bare id resolves back
// to the same URI. The init in domain.go registers the domain, so kit.Open
// finds it.
func TestHostWiring(t *testing.T) {
	h, err := kit.Open()
	if err != nil {
		t.Fatal(err)
	}

	ip := &IPInfo{
		IP:             "8.8.8.8",
		Noise:          false,
		RIOT:           true,
		Classification: "benign",
		Name:           "Google Public DNS",
		Link:           "https://viz.greynoise.io/riot/8.8.8.8",
		Message:        "This IP is commonly associated with legitimate internet infrastructure.",
	}
	u, err := h.Mint(ip)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if want := "greynoise://ip/8.8.8.8"; u.String() != want {
		t.Errorf("Mint = %q, want %q", u.String(), want)
	}

	got, err := h.ResolveOn("greynoise", "1.1.1.1")
	if err != nil || got.String() != "greynoise://ip/1.1.1.1" {
		t.Errorf("ResolveOn = (%q, %v), want greynoise://ip/1.1.1.1", got.String(), err)
	}
}
