package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func withURL(t *testing.T, u string) {
	t.Helper()
	orig := URL
	URL = u
	t.Cleanup(func() { URL = orig })
}

// loopbacks is the set of names to try as the bound interface when
// running the test; portable across Linux ("lo") and macOS ("lo0").
var loopbacks = []string{"lo", "lo0"}

func TestLookupParsesCanonicalShape(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"ip": "192.0.2.1",
			"forwardedFor": ["192.0.2.1"],
			"asn": 65000,
			"asOrganization": "ExampleNet",
			"country": "ZZ"
		}`))
	}))
	defer srv.Close()
	withURL(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, ifname := range loopbacks {
		info, err := Lookup(ctx, ifname, "amane/test")
		if err != nil {
			if strings.Contains(err.Error(), "no such") || strings.Contains(err.Error(), "not found") {
				continue
			}
			t.Fatalf("Lookup(%s): %v", ifname, err)
		}
		if info.IP != "192.0.2.1" {
			t.Errorf("IP = %q", info.IP)
		}
		if info.ASN != 65000 {
			t.Errorf("ASN = %d", info.ASN)
		}
		if info.ASOrg != "ExampleNet" {
			t.Errorf("ASOrg = %q", info.ASOrg)
		}
		if info.Country != "ZZ" {
			t.Errorf("Country = %q", info.Country)
		}
		if info.FetchedAt.IsZero() {
			t.Error("FetchedAt not set")
		}
		if gotUA != "amane/test" {
			t.Errorf("User-Agent = %q, want amane/test", gotUA)
		}
		return
	}
	t.Skip("no loopback interface name resolved on this platform")
}

func TestLookupRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	withURL(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, ifname := range loopbacks {
		_, err := Lookup(ctx, ifname, "amane/test")
		if err != nil {
			if strings.Contains(err.Error(), "no such") || strings.Contains(err.Error(), "not found") {
				continue
			}
			if !strings.Contains(err.Error(), "500") {
				t.Fatalf("got %v, want HTTP 500 error", err)
			}
			return
		}
		t.Fatal("accepted non-2xx response")
	}
	t.Skip("no loopback interface name resolved on this platform")
}

func TestLookupRejectsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	withURL(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, ifname := range loopbacks {
		_, err := Lookup(ctx, ifname, "amane/test")
		if err != nil {
			if strings.Contains(err.Error(), "no such") || strings.Contains(err.Error(), "not found") {
				continue
			}
			if !strings.Contains(err.Error(), "parse") {
				t.Fatalf("got %v, want parse error", err)
			}
			return
		}
		t.Fatal("accepted malformed JSON")
	}
	t.Skip("no loopback interface name resolved on this platform")
}

func TestLookupRejectsEmptyIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"asn": 65000}`))
	}))
	defer srv.Close()
	withURL(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, ifname := range loopbacks {
		_, err := Lookup(ctx, ifname, "amane/test")
		if err != nil {
			if strings.Contains(err.Error(), "no such") || strings.Contains(err.Error(), "not found") {
				continue
			}
			if !strings.Contains(err.Error(), "missing ip") {
				t.Fatalf("got %v, want missing-ip error", err)
			}
			return
		}
		t.Fatal("accepted response without ip field")
	}
	t.Skip("no loopback interface name resolved on this platform")
}
