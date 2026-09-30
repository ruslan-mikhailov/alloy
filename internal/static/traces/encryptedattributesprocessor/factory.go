package encryptedattributesprocessor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/tink-crypto/tink-go/v2/daead/subtle"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"golang.org/x/crypto/hkdf"
)

const (
	TypeStr        = "encrypted_attributes"
	valueScheme    = "aes256siv-hkdf-v1"
	substringIndex = "ordered-trigram-v1"
)

// Config assigns disjoint span attribute names to encryption policies.
type Config struct {
	Policies []Policy `mapstructure:"policies"`
}

type Policy struct {
	SpanAttributes []string `mapstructure:"span_attributes"`
	KeyFile        string   `mapstructure:"key_file"`
	ValueScheme    string   `mapstructure:"value_scheme"`
	SubstringIndex string   `mapstructure:"substring_index"`
}

func (policy Policy) effectiveValueScheme() string {
	if policy.ValueScheme == "" {
		return valueScheme
	}
	return policy.ValueScheme
}

func (cfg *Config) Validate() error {
	if cfg == nil {
		return fmt.Errorf("encrypted_attributes: missing configuration")
	}
	if len(cfg.Policies) == 0 {
		return fmt.Errorf("encrypted_attributes: policies must not be empty")
	}
	seen := make(map[string]struct{})
	for i, policy := range cfg.Policies {
		if len(policy.SpanAttributes) == 0 {
			return fmt.Errorf("encrypted_attributes: policy %d span_attributes must not be empty", i)
		}
		for _, name := range policy.SpanAttributes {
			if name == "" || strings.HasPrefix(name, "enc.") || strings.HasPrefix(name, "bi.") {
				return fmt.Errorf("encrypted_attributes: policy %d span_attributes contains an empty or reserved name", i)
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("encrypted_attributes: duplicate span attribute name %q", name)
			}
			seen[name] = struct{}{}
		}
		if policy.KeyFile == "" {
			return fmt.Errorf("encrypted_attributes: policy %d key_file must not be empty", i)
		}
		if policy.effectiveValueScheme() != valueScheme {
			return fmt.Errorf("encrypted_attributes: policy %d unsupported value_scheme %q", i, policy.ValueScheme)
		}
		if policy.SubstringIndex != "" && policy.SubstringIndex != substringIndex {
			return fmt.Errorf("encrypted_attributes: policy %d unsupported substring_index %q", i, policy.SubstringIndex)
		}
	}
	return nil
}

// NewFactory creates a traces-only Collector processor. Its stability is alpha.
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(TypeStr),
		createDefaultConfig,
		processor.WithTraces(createTracesProcessor, component.StabilityLevelAlpha),
	)
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func createTracesProcessor(
	_ context.Context,
	_ processor.Settings,
	cfg component.Config,
	nextConsumer consumer.Traces,
) (processor.Traces, error) {
	config, ok := cfg.(*Config)
	if !ok {
		return nil, fmt.Errorf("encrypted_attributes: invalid configuration type")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	encryptors := make([]*encryptor, len(config.Policies))
	for i, policy := range config.Policies {
		enc, err := newEncryptor(policy.KeyFile, policy.effectiveValueScheme(), policy.SubstringIndex == substringIndex)
		if err != nil {
			return nil, fmt.Errorf("encrypted_attributes: policy %d: %w", i, err)
		}
		encryptors[i] = enc
	}
	return newProcessor(nextConsumer, config, encryptors), nil
}

type encryptor struct {
	siv          *subtle.AESSIV
	kid          string
	substringKey [32]byte
}

// newEncryptor reads the key file once. Neither the master nor the derived key is logged.
func newEncryptor(keyFile, scheme string, indexEnabled bool) (*encryptor, error) {
	switch scheme {
	case valueScheme:
		return newAESSIVEncryptor(keyFile, indexEnabled)
	default:
		return nil, fmt.Errorf("encrypted_attributes: unsupported value_scheme %q", scheme)
	}
}

func newAESSIVEncryptor(keyFile string, indexEnabled bool) (*encryptor, error) {
	contents, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("encrypted_attributes: read key_file: %w", err)
	}
	defer clear(contents)
	encoded := strings.TrimSpace(string(contents))
	if strings.IndexFunc(encoded, unicode.IsSpace) != -1 {
		return nil, fmt.Errorf("encrypted_attributes: key_file must contain standard base64 without interior whitespace")
	}
	encoding := base64.StdEncoding.Strict()
	if !strings.Contains(encoded, "=") {
		encoding = base64.RawStdEncoding.Strict()
	}
	master, err := encoding.DecodeString(encoded)
	if err != nil || len(master) != 32 {
		return nil, fmt.Errorf("encrypted_attributes: key_file must contain exactly 32 base64-encoded bytes")
	}
	defer clear(master)

	hash := sha256.Sum256(master)
	derived := make([]byte, subtle.AESSIVKeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, []byte("tempo-attr-v1"), []byte("aes-256-siv")), derived); err != nil {
		return nil, fmt.Errorf("encrypted_attributes: derive encryption key: %w", err)
	}
	siv, err := subtle.NewAESSIV(derived)
	if err != nil {
		return nil, fmt.Errorf("encrypted_attributes: initialize encryption: %w", err)
	}
	enc := &encryptor{siv: siv, kid: hex.EncodeToString(hash[:16])}
	if indexEnabled {
		if _, err := io.ReadFull(hkdf.New(sha256.New, master, []byte("tempo-substring-v1"), []byte("hmac-sha256-trigram")), enc.substringKey[:]); err != nil {
			return nil, fmt.Errorf("encrypted_attributes: derive substring key: %w", err)
		}
	}
	return enc, nil
}

// seal authenticates the exact stored field name as the sole AD component.
func (enc *encryptor) seal(storedName, plaintext string) (string, error) {
	ad := make([]byte, len("tempo:span:v1")+1+4+len(storedName))
	copy(ad, "tempo:span:v1")
	binary.BigEndian.PutUint32(ad[len("tempo:span:v1")+1:], uint32(len(storedName)))
	copy(ad[len("tempo:span:v1")+1+4:], storedName)
	ciphertext, err := enc.siv.EncryptDeterministically([]byte(plaintext), ad)
	if err != nil {
		return "", fmt.Errorf("encrypted_attributes: encrypt attribute %q: %w", storedName, err)
	}
	return "enc:v1:" + enc.kid + ":" + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// indexTokens validates the complete selected value before encryption or mutation.
// The original string, rather than its normalized form, is still passed to seal.
func (enc *encryptor) indexTokens(storedName, plaintext string) ([]string, error) {
	if !utf8.ValidString(plaintext) {
		return nil, fmt.Errorf("encrypted_attributes: invalid UTF-8 in selected span attribute")
	}
	normalized := norm.NFC.String(plaintext)
	if len(normalized) > 2048 {
		return nil, fmt.Errorf("encrypted_attributes: selected span attribute exceeds substring index limit")
	}
	scalars := []rune(normalized)
	if len(scalars) > 512 {
		return nil, fmt.Errorf("encrypted_attributes: selected span attribute exceeds substring index limit")
	}
	if len(scalars) < 3 {
		return nil, nil
	}
	if uint64(len(storedName)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("encrypted_attributes: selected span attribute name exceeds substring frame limit")
	}

	// The first two frames are shared by every gram of this value. The length
	// of each UTF-8 gram fits in the stack buffer (three runes, at most 12 bytes).
	const domain = "tempo:substring:v1"
	prefix := make([]byte, 4+len(domain)+4+len(storedName))
	binary.BigEndian.PutUint32(prefix, uint32(len(domain)))
	copy(prefix[4:], domain)
	binary.BigEndian.PutUint32(prefix[4+len(domain):], uint32(len(storedName)))
	copy(prefix[8+len(domain):], storedName)
	tokens := make([]string, 0, len(scalars)-2)
	mac := hmac.New(sha256.New, enc.substringKey[:])
	var digest [sha256.Size]byte
	for i := 0; i+2 < len(scalars); i++ {
		var gram [4 + 12]byte
		bytes := gram[4:4]
		for _, scalar := range scalars[i : i+3] {
			bytes = utf8.AppendRune(bytes, scalar)
		}
		binary.BigEndian.PutUint32(gram[:4], uint32(len(bytes)))
		mac.Reset()
		writeMAC(mac, prefix)
		writeMAC(mac, gram[:4+len(bytes)])
		sum := mac.Sum(digest[:0])
		tokens = append(tokens, "bi:v1:"+enc.kid+":"+base64.RawURLEncoding.EncodeToString(sum))
	}
	return tokens, nil
}

// hash.Hash.Write never fails for HMAC-SHA256.
func writeMAC(mac hash.Hash, data []byte) {
	_, _ = mac.Write(data)
}
