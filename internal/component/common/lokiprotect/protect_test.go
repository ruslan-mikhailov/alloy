package lokiprotect

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/daead/subtle"
	"golang.org/x/crypto/hkdf"
)

func keyFile(t *testing.T, master []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "master")
	require.NoError(t, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(master)+"\n"), 0600))
	return path
}

func TestEnvelopeFieldBindingAndPolicies(t *testing.T) {
	master := make([]byte, 32)
	other := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
		other[i] = byte(31 - i)
	}
	p, err := New([]Policy{
		{Fields: []string{"label.namespace", "line.email", "metadata.customer_email"}, KeyFile: keyFile(t, master), ValueScheme: Scheme},
		{Fields: []string{"line.api_token"}, KeyFile: keyFile(t, other), ValueScheme: Scheme},
	})
	require.NoError(t, err)
	got, err := p.Seal("line.email", "alice@example.invalid")
	require.NoError(t, err)
	require.Equal(t, "lenc:v1:630dcd2966c4336691125448bbb25b4f:kIAS6bsREGxxOaHcIg83QMuD1Kmm4efCubuxwDkrv6b4TbuaeA", got)
	repeat, err := p.Seal("line.email", "alice@example.invalid")
	require.NoError(t, err)
	require.Equal(t, got, repeat)
	hash := sha256.Sum256(master)
	require.True(t, strings.HasPrefix(got, "lenc:v1:"+hex.EncodeToString(hash[:16])+":"))
	parts := strings.Split(got, ":")
	require.Len(t, parts, 4)
	bytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(bytes), 16)
	derived := make([]byte, subtle.AESSIVKeySize)
	_, err = io.ReadFull(hkdf.New(sha256.New, master, []byte("loki-value-v1"), []byte("aes-256-siv")), derived)
	require.NoError(t, err)
	siv, err := subtle.NewAESSIV(derived)
	require.NoError(t, err)
	ad := func(field string) []byte {
		b := make([]byte, len("loki:value:v1")+1+4+len(field))
		copy(b, "loki:value:v1")
		binary.BigEndian.PutUint32(b[len("loki:value:v1")+1:], uint32(len(field)))
		copy(b[len("loki:value:v1")+5:], field)
		return b
	}
	plaintext, err := siv.DecryptDeterministically(bytes, ad("line.email"))
	require.NoError(t, err)
	require.Equal(t, "alice@example.invalid", string(plaintext))
	_, err = siv.DecryptDeterministically(bytes, ad("label.email"))
	require.Error(t, err)
	_, err = siv.DecryptDeterministically(bytes, ad("metadata.customer_email"))
	require.Error(t, err)
	wrong, err := p.Seal("line.api_token", "alice@example.invalid")
	require.NoError(t, err)
	require.NotEqual(t, got, wrong)
	_, err = siv.DecryptDeterministically(mustPayload(t, wrong), ad("line.api_token"))
	require.Error(t, err)
	crossContext, err := p.Seal("label.namespace", "alice@example.invalid")
	require.NoError(t, err)
	require.NotEqual(t, got, crossContext)
}

func mustPayload(t *testing.T, envelope string) []byte {
	t.Helper()
	parts := strings.Split(envelope, ":")
	require.Len(t, parts, 4)
	b, err := base64.RawURLEncoding.DecodeString(parts[3])
	require.NoError(t, err)
	return b
}

func TestRejectedPoliciesAndValues(t *testing.T) {
	master := make([]byte, 32)
	key := keyFile(t, master)
	cases := [][]Policy{
		nil,
		{{Fields: []string{"line.email"}, KeyFile: key, ValueScheme: "unknown"}},
		{{Fields: []string{"line.email", "line.email"}, KeyFile: key, ValueScheme: Scheme}},
		{{Fields: []string{"line.email"}, KeyFile: key, ValueScheme: Scheme}, {Fields: []string{"line.email"}, KeyFile: key, ValueScheme: Scheme}},
		{{Fields: []string{"line.email.ambiguous"}, KeyFile: key, ValueScheme: Scheme}},
		{{Fields: []string{"body.email"}, KeyFile: key, ValueScheme: Scheme}},
	}
	for _, policies := range cases { _, err := New(policies); require.Error(t, err) }
	path := filepath.Join(t.TempDir(), "bad")
	require.NoError(t, os.WriteFile(path, []byte(base64.RawStdEncoding.EncodeToString(master)), 0600))
	_, err := New([]Policy{{Fields: []string{"line.email"}, KeyFile: path, ValueScheme: Scheme}})
	require.Error(t, err)
	p, err := New([]Policy{{Fields: []string{"line.email"}, KeyFile: key, ValueScheme: Scheme}})
	require.NoError(t, err)
	for _, value := range []string{"lenc:v1:fake:literal", string([]byte{0xff}), strings.Repeat("x", MaxValueBytes+1)} {
		_, err := p.Seal("line.email", value)
		require.Error(t, err)
	}
	_, err = p.Seal("line.missing", "plain")
	require.Error(t, err)
}
