package greynoise

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/tamnd/any-cli/kit"
	"github.com/tamnd/any-cli/kit/errs"
)

// domain.go exposes greynoise as a kit Domain: a driver that a multi-domain
// host (ant) enables with a single blank import,
//
//	import _ "github.com/tamnd/greynoise-cli/greynoise"
//
// exactly as a database/sql program enables a driver with
// `import _ "github.com/lib/pq"`. The init below registers it; the host then
// dereferences greynoise:// URIs by routing to the operations Register installs.
// The same Domain also builds the standalone greynoise binary (see cli.NewApp),
// so the binary and a host share one source of truth.
func init() { kit.Register(Domain{}) }

// Domain is the greynoise driver. It carries no state; the per-run client is
// built by the factory Register hands kit.
type Domain struct{}

// Info describes the scheme, the hostnames a pasted link is matched against,
// and the identity reused for the binary's help and version.
func (Domain) Info() kit.DomainInfo {
	return kit.DomainInfo{
		Scheme: "greynoise",
		Hosts:  []string{Host},
		Identity: kit.Identity{
			Binary: "greynoise",
			Short:  "Look up IP addresses against the GreyNoise Community API.",
			Long: `greynoise looks up IP addresses against the GreyNoise Community API.

No API key is required. For each IP you learn whether it has been observed
scanning the internet (noise), whether it belongs to safe benign infrastructure
(RIOT), its threat classification, and a link to the full GreyNoise analysis.

Output is line-delimited JSON by default and pipes cleanly into jq, grep,
and the rest of your toolchain.`,
			Site: "viz.greynoise.io",
			Repo: "https://github.com/tamnd/greynoise-cli",
		},
	}
}

// Register installs the client factory and every operation onto app.
func (Domain) Register(app *kit.App) {
	app.SetClient(newClient)

	// Resolver op: one IPInfo per IP address.
	kit.Handle(app, kit.OpMeta{
		Name:     "ip",
		Group:    "read",
		Single:   true,
		Summary:  "Look up an IP address in the GreyNoise Community API",
		URIType:  "ip",
		Resolver: true,
		Args:     []kit.Arg{{Name: "ip", Help: "IP address to query"}},
	}, getIP)
}

// newClient builds the client from the host-resolved config, so a host and the
// standalone binary pace and identify themselves the same way.
func newClient(_ context.Context, cfg kit.Config) (any, error) {
	c := NewClient()
	if cfg.UserAgent != "" {
		c.UserAgent = cfg.UserAgent
	}
	if cfg.Rate > 0 {
		c.Rate = cfg.Rate
	}
	if cfg.Retries > 0 {
		c.Retries = cfg.Retries
	}
	if cfg.Timeout > 0 {
		c.HTTP.Timeout = cfg.Timeout
	}
	return c, nil
}

// --- inputs ---

type ipInput struct {
	IP     string  `kit:"arg" help:"IP address to query"`
	Client *Client `kit:"inject"`
}

// --- handlers ---

func getIP(ctx context.Context, in ipInput, emit func(*IPInfo) error) error {
	info, err := in.Client.GetIP(ctx, in.IP)
	if err != nil {
		return mapErr(err)
	}
	return emit(info)
}

// --- Resolver: the URI-native string functions, pure and network-free ---

// Classify turns any accepted input into the canonical (type, id).
// A valid IP address (contains dots and numeric segments) maps to ("ip", ip).
func (Domain) Classify(input string) (uriType, id string, err error) {
	input = strings.TrimSpace(input)
	if !isIP(input) {
		return "", "", errs.Usage("not a valid IP address: %q", input)
	}
	return "ip", input, nil
}

// Locate is the inverse: the live https URL for a (type, id).
func (Domain) Locate(uriType, id string) (string, error) {
	switch uriType {
	case "ip":
		return fmt.Sprintf("https://viz.greynoise.io/ip/%s", id), nil
	default:
		return "", errs.Usage("greynoise has no resource type %q", uriType)
	}
}

// --- helpers ---

// isIP returns true if s is a syntactically valid IPv4 or IPv6 address.
func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// mapErr converts a library error into the kit error kind that carries the
// right exit code, so a host renders the same outcomes the standalone binary
// does.
func mapErr(err error) error {
	return err
}
