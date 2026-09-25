package encryptedattributesprocessor

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/processor"
)

const publicFixtureKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func fixtureKeyFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestEncryptedValuesMatchWireContract(t *testing.T) {
	enc, err := newEncryptor(fixtureKeyFile(t, publicFixtureKey), valueScheme)
	require.NoError(t, err)
	require.Equal(t, "630dcd2966c4336691125448bbb25b4f", enc.kid)

	for _, tc := range []struct {
		name, storedName, plaintext, want string
	}{
		{"ascii", "enc.password", "abc", "enc:v1:630dcd2966c4336691125448bbb25b4f:7aUwjY5fPtHvu_dUnzcxBJc6XQ"},
		{"empty", "enc.password", "", "enc:v1:630dcd2966c4336691125448bbb25b4f:l4ghA-S-aF9uZIBVXGBXsA"},
		{"unicode", "enc.password", "π🙂", "enc:v1:630dcd2966c4336691125448bbb25b4f:Q7TnRtl8MzhotH3OUlYfe4R-HKvCyg"},
		{"field-bound", "enc.token", "abc", "enc:v1:630dcd2966c4336691125448bbb25b4f:Tmlsk4UeuIxW4e8k0i4OmCaSPg"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := enc.seal(tc.storedName, tc.plaintext)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			repeated, err := enc.seal(tc.storedName, tc.plaintext)
			require.NoError(t, err)
			require.Equal(t, got, repeated)
		})
	}
}

func TestEncryptorReadsKeyOnlyAtConstruction(t *testing.T) {
	keyFile := fixtureKeyFile(t, publicFixtureKey)
	enc, err := newEncryptor(keyFile, valueScheme)
	require.NoError(t, err)
	before, err := enc.seal("enc.password", "abc")
	require.NoError(t, err)

	rotatedKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, os.WriteFile(keyFile, []byte(rotatedKey), 0o600))
	after, err := enc.seal("enc.password", "abc")
	require.NoError(t, err)
	require.Equal(t, before, after)

	rotated, err := newEncryptor(keyFile, valueScheme)
	require.NoError(t, err)
	next, err := rotated.seal("enc.password", "abc")
	require.NoError(t, err)
	require.NotEqual(t, before, next)
	require.NotEqual(t, enc.kid, rotated.kid)
}

func TestConfigValidation(t *testing.T) {
	valid := Config{SpanAttributes: []string{"password", "token"}, KeyFile: "key", ValueScheme: valueScheme}
	require.NoError(t, valid.Validate())

	for _, tc := range []struct {
		name string
		cfg  *Config
	}{
		{"nil", nil},
		{"missing names", &Config{KeyFile: "key", ValueScheme: valueScheme}},
		{"empty name", &Config{SpanAttributes: []string{"password", ""}, KeyFile: "key", ValueScheme: valueScheme}},
		{"duplicate", &Config{SpanAttributes: []string{"password", "password"}, KeyFile: "key", ValueScheme: valueScheme}},
		{"reserved name", &Config{SpanAttributes: []string{"enc.password"}, KeyFile: "key", ValueScheme: valueScheme}},
		{"missing file", &Config{SpanAttributes: []string{"password"}, ValueScheme: valueScheme}},
		{"missing scheme", &Config{SpanAttributes: []string{"password"}, KeyFile: "key"}},
		{"unsupported scheme", &Config{SpanAttributes: []string{"password"}, KeyFile: "key", ValueScheme: "other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, tc.cfg.Validate())
		})
	}
}

func TestCreateRejectsMalformedKeyAndScheme(t *testing.T) {
	for _, tc := range []struct {
		name, contents, scheme string
		missing                bool
	}{
		{"unreadable", "", valueScheme, true},
		{"bad base64", "not-base64!", valueScheme, false},
		{"short", base64.StdEncoding.EncodeToString(make([]byte, 31)), valueScheme, false},
		{"long", base64.StdEncoding.EncodeToString(make([]byte, 33)), valueScheme, false},
		{"interior linebreak", publicFixtureKey[:20] + "\n" + publicFixtureKey[20:], valueScheme, false},
		{"interior space", publicFixtureKey[:20] + " " + publicFixtureKey[20:], valueScheme, false},
		{"wrong scheme", publicFixtureKey, "aes-gcm", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := filepath.Join(t.TempDir(), "missing")
			if !tc.missing {
				keyFile = fixtureKeyFile(t, tc.contents)
			}
			cfg := &Config{SpanAttributes: []string{"password"}, KeyFile: keyFile, ValueScheme: tc.scheme}
			got, err := createTracesProcessor(context.Background(), processor.Settings{}, cfg, consumertest.NewNop())
			require.Error(t, err)
			require.Nil(t, got)
			if tc.contents != "" {
				require.NotContains(t, err.Error(), tc.contents)
			}
		})
	}
}

func TestCreateAcceptsPaddedAndUnpaddedBase64(t *testing.T) {
	for _, encoded := range []string{publicFixtureKey, strings.TrimSuffix(publicFixtureKey, "=")} {
		keyFile := fixtureKeyFile(t, " \n"+encoded+"\t\n")
		cfg := &Config{SpanAttributes: []string{"password"}, KeyFile: keyFile, ValueScheme: valueScheme}
		got, err := createTracesProcessor(context.Background(), processor.Settings{}, cfg, consumertest.NewNop())
		require.NoError(t, err)
		require.NotNil(t, got)
	}
}
