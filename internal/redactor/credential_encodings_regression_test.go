package redactor

import (
	"strings"
	"testing"
)

func TestDefaultRules_CredentialEncodings(t *testing.T) {
	fakeGoogleAPIKey := "AIza" + strings.Repeat("Fake0", 7)
	cases := []struct {
		name     string
		in       string
		leaked   string
		survives string
	}{
		{"azure sas sig", "GET /c/blob.txt?sv=2022-11-02&sig=AbCdEf%2Bsecret%3D&se=2026", "AbCdEf", "sv=2022-11-02"},
		{"google key param", "GET /maps/api?key=" + fakeGoogleAPIKey, "Fake0Fake0", "/maps/api"},
		{"google key bare", "config loaded " + fakeGoogleAPIKey + " ok", "Fake0Fake0", "config loaded"},
		{"opaque key param", "GET /x?a=1&key=opaqueValue77", "opaqueValue77", "a=1"},
		{"oauth code", "GET /callback?code=4/0AY0e-g7secretcode&state=xyz", "0AY0e-g7secretcode", "state=xyz"},
		{"encoded oauth code", "GET /r?next=%2Fcb%3Fcode%3Dsplendid42%26x%3D1", "splendid42", "/r?next="},
		{"percent encoded password", "body: user%3Dbob%26password%3Dhunter2", "hunter2", "user%3Dbob"},
		{"spaced password", "password = hunter2", "hunter2", "password"},
		{"spaced token tab", "token\t=\tghp_abcdef", "ghp_abcdef", "token"},
		{"json escaped quote", `{"password":"ab\"cd","user":"bob"}`, "cd", `"user":"bob"`},
		{"escaped json", `msg="{\"user\":\"bob\",\"password\":\"hunter2\"}"`, "hunter2", `\"user\":\"bob\"`},
		{"escaped json inner quote", `{\"token\":\"ab\\\"cd\",\"n\":1}`, "cd", `\"n\":1`},
	}
	r := Default()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.RedactText(c.in)
			if strings.Contains(got, c.leaked) {
				t.Errorf("still leaks %q: %q", c.leaked, got)
			}
			if !strings.Contains(got, c.survives) {
				t.Errorf("lost non-secret context %q: %q", c.survives, got)
			}
		})
	}
}

func TestDefaultRules_CodeAndKeyOutsideQueryAreKept(t *testing.T) {
	r := Default()
	for _, in := range []string{
		"HTTP/1.1 response code=200 latency=12ms",
		"grpc status code=14 UNAVAILABLE",
		"cache key=user:42 miss",
		"exit code = 137",
	} {
		if got := r.RedactText(in); got != in {
			t.Errorf("RedactText(%q) = %q, want unchanged", in, got)
		}
	}
}
