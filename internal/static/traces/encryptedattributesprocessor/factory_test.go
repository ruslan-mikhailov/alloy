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
	enc, err := newEncryptor(fixtureKeyFile(t, publicFixtureKey), valueScheme, false)
	require.NoError(t, err)
	require.Equal(t, "630dcd2966c4336691125448bbb25b4f", enc.kid)
	require.Equal(t, [32]byte{}, enc.substringKey)

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
	enc, err := newEncryptor(keyFile, valueScheme, false)
	require.NoError(t, err)
	before, err := enc.seal("enc.password", "abc")
	require.NoError(t, err)

	rotatedKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, os.WriteFile(keyFile, []byte(rotatedKey), 0o600))
	after, err := enc.seal("enc.password", "abc")
	require.NoError(t, err)
	require.Equal(t, before, after)

	rotated, err := newEncryptor(keyFile, valueScheme, false)
	require.NoError(t, err)
	next, err := rotated.seal("enc.password", "abc")
	require.NoError(t, err)
	require.NotEqual(t, before, next)
	require.NotEqual(t, enc.kid, rotated.kid)
}

func TestConfigValidation(t *testing.T) {
	first := Policy{SpanAttributes: []string{"password", "token"}, KeyFile: "key", ValueScheme: valueScheme}
	second := Policy{SpanAttributes: []string{"customer.email"}, KeyFile: "other-key", ValueScheme: valueScheme}
	valid := Config{Policies: []Policy{first, second}}
	first.SubstringIndex = substringIndex
	valid.Policies[0] = first
	require.NoError(t, valid.Validate())

	for _, tc := range []struct {
		name string
		cfg  *Config
	}{
		{"nil", nil},
		{"missing policies", &Config{}},
		{"missing names in second policy", &Config{Policies: []Policy{first, {KeyFile: "other-key", ValueScheme: valueScheme}}}},
		{"empty name", &Config{Policies: []Policy{{SpanAttributes: []string{"password", ""}, KeyFile: "key", ValueScheme: valueScheme}}}},
		{"duplicate within policy", &Config{Policies: []Policy{{SpanAttributes: []string{"password", "password"}, KeyFile: "key", ValueScheme: valueScheme}}}},
		{"duplicate across policies", &Config{Policies: []Policy{first, {SpanAttributes: []string{"token"}, KeyFile: "other-key", ValueScheme: valueScheme}}}},
		{"reserved name", &Config{Policies: []Policy{{SpanAttributes: []string{"enc.password"}, KeyFile: "key", ValueScheme: valueScheme}}}},
		{"reserved index name", &Config{Policies: []Policy{{SpanAttributes: []string{"bi.password"}, KeyFile: "key", ValueScheme: valueScheme}}}},
		{"unsupported substring index", &Config{Policies: []Policy{first, {SpanAttributes: []string{"customer.email"}, KeyFile: "other-key", ValueScheme: valueScheme, SubstringIndex: "other"}}}},
		{"missing second key file", &Config{Policies: []Policy{first, {SpanAttributes: []string{"customer.email"}, ValueScheme: valueScheme}}}},
		{"missing scheme", &Config{Policies: []Policy{{SpanAttributes: []string{"password"}, KeyFile: "key"}}}},
		{"unsupported second scheme", &Config{Policies: []Policy{first, {SpanAttributes: []string{"customer.email"}, KeyFile: "other-key", ValueScheme: "other"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, tc.cfg.Validate())
		})
	}
}

func TestCreateRejectsAttributeAssignedToTwoKeys(t *testing.T) {
	firstKey := fixtureKeyFile(t, publicFixtureKey)
	secondKey := fixtureKeyFile(t, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	cfg := &Config{Policies: []Policy{
		{SpanAttributes: []string{"password", "token"}, KeyFile: firstKey, ValueScheme: valueScheme},
		{SpanAttributes: []string{"token"}, KeyFile: secondKey, ValueScheme: valueScheme},
	}}
	got, err := createTracesProcessor(context.Background(), processor.Settings{}, cfg, consumertest.NewNop())
	require.ErrorContains(t, err, `duplicate span attribute name "token"`)
	require.Nil(t, got)
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
			cfg := &Config{Policies: []Policy{{SpanAttributes: []string{"password"}, KeyFile: keyFile, ValueScheme: tc.scheme}}}
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
		cfg := &Config{Policies: []Policy{{SpanAttributes: []string{"password"}, KeyFile: keyFile, ValueScheme: valueScheme}}}
		got, err := createTracesProcessor(context.Background(), processor.Settings{}, cfg, consumertest.NewNop())
		require.NoError(t, err)
		require.NotNil(t, got)
	}
}

func TestCreateRejectsInvalidSecondKeyBeforeProcessing(t *testing.T) {
	goodKey := fixtureKeyFile(t, publicFixtureKey)
	badKey := fixtureKeyFile(t, "not-base64!")
	cfg := &Config{Policies: []Policy{
		{SpanAttributes: []string{"password"}, KeyFile: goodKey, ValueScheme: valueScheme},
		{SpanAttributes: []string{"token"}, KeyFile: badKey, ValueScheme: valueScheme},
	}}
	got, err := createTracesProcessor(context.Background(), processor.Settings{}, cfg, consumertest.NewNop())
	require.ErrorContains(t, err, "policy 1")
	require.NotContains(t, err.Error(), "not-base64!")
	require.Nil(t, got)
}

func TestSubstringTokensMatchWireContract(t *testing.T) {
	enc, err := newEncryptor(fixtureKeyFile(t, publicFixtureKey), valueScheme, true)
	require.NoError(t, err)
	sealed, err := enc.seal("enc.password", "abc")
	require.NoError(t, err)
	require.Equal(t, "enc:v1:630dcd2966c4336691125448bbb25b4f:7aUwjY5fPtHvu_dUnzcxBJc6XQ", sealed)
	coo := "bi:v1:630dcd2966c4336691125448bbb25b4f:E_S8rZC-kHLrifr_71XBBSP7w8jOWNCm2j6LHigypgM"
	ool := "bi:v1:630dcd2966c4336691125448bbb25b4f:zQb64aCXnVL2KksfrDxrQwVtdw6Ljmwxv37So9E7ghc"
	tokens, err := enc.indexTokens("enc.secret", "some cool value")
	require.NoError(t, err)
	require.Len(t, tokens, 13)
	require.Equal(t, []string{coo, ool}, tokens[5:7])
	for _, token := range tokens {
		require.Len(t, token, len("bi:v1:")+32+1+43)
	}

	composed, err := enc.indexTokens("enc.secret", "é🙂a")
	require.NoError(t, err)
	decomposed, err := enc.indexTokens("enc.secret", "e\u0301🙂a")
	require.NoError(t, err)
	require.Equal(t, composed, decomposed)
	require.Len(t, decomposed, 1)
	fieldBound, err := enc.indexTokens("enc.other", "é🙂a")
	require.NoError(t, err)
	require.NotEqual(t, composed, fieldBound)

	repeated, err := enc.indexTokens("enc.secret", "aaaabca")
	require.NoError(t, err)
	require.Len(t, repeated, 5)
	require.Equal(t, repeated[0], repeated[1])
	require.NotEqual(t, repeated[1], repeated[2])
	require.NotEqual(t, repeated[2], repeated[3])
	require.NotEqual(t, repeated[3], repeated[4])

	other, err := newEncryptor(fixtureKeyFile(t, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))), valueScheme, true)
	require.NoError(t, err)
	otherTokens, err := other.indexTokens("enc.secret", "é🙂a")
	require.NoError(t, err)
	require.NotEqual(t, composed, otherTokens)
}

func TestSubstringIndexValidatesNormalizedLimitsAndUTF8(t *testing.T) {
	enc, err := newEncryptor(fixtureKeyFile(t, publicFixtureKey), valueScheme, true)
	require.NoError(t, err)

	for _, tc := range []struct {
		name, plaintext string
		wantTokens      int
	}{
		{"empty", "", 0},
		{"two scalars", "🙂é", 0},
		{"exact three", "e\u0301🙂a", 1},
		{"512 scalars", strings.Repeat("a", 512), 510},
		{"2048 bytes", strings.Repeat("🙂", 512), 510},
		{"decomposed input normalizes under limit", strings.Repeat("e\u0301", 512), 510},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokens, err := enc.indexTokens("enc.secret", tc.plaintext)
			require.NoError(t, err)
			require.Len(t, tokens, tc.wantTokens)
		})
	}

	for _, tc := range []struct {
		name, plaintext string
	}{
		{"invalid UTF-8", "known-value\xff"},
		{"too many scalars", strings.Repeat("a", 513)},
		{"too many bytes", strings.Repeat("🙂", 512) + "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokens, err := enc.indexTokens("enc.secret", tc.plaintext)
			require.Error(t, err)
			require.Nil(t, tokens)
			require.NotContains(t, err.Error(), tc.plaintext)
			require.NotContains(t, err.Error(), "known-value")
		})
	}
}
