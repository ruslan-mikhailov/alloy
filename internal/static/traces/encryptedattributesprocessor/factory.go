package encryptedattributesprocessor

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/tink-crypto/tink-go/v2/daead/subtle"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"golang.org/x/crypto/hkdf"
)

const (
	TypeStr     = "encrypted_attributes"
	valueScheme = "aes256siv-hkdf-v1"
)

// Config assigns disjoint span attribute names to encryption policies.
type Config struct {
	Policies []Policy `mapstructure:"policies"`
}

type Policy struct {
	SpanAttributes []string `mapstructure:"span_attributes"`
	KeyFile        string   `mapstructure:"key_file"`
	ValueScheme    string   `mapstructure:"value_scheme"`
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
			if name == "" || strings.HasPrefix(name, "enc.") {
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
		if policy.ValueScheme != valueScheme {
			return fmt.Errorf("encrypted_attributes: policy %d unsupported value_scheme %q", i, policy.ValueScheme)
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
		enc, err := newEncryptor(policy.KeyFile, policy.ValueScheme)
		if err != nil {
			return nil, fmt.Errorf("encrypted_attributes: policy %d: %w", i, err)
		}
		encryptors[i] = enc
	}
	return newProcessor(nextConsumer, config, encryptors), nil
}

type encryptor struct {
	siv *subtle.AESSIV
	kid string
}

// newEncryptor reads the key file once. Neither the master nor the derived key is logged.
func newEncryptor(keyFile, scheme string) (*encryptor, error) {
	switch scheme {
	case valueScheme:
		return newAESSIVEncryptor(keyFile)
	default:
		return nil, fmt.Errorf("encrypted_attributes: unsupported value_scheme %q", scheme)
	}
}

func newAESSIVEncryptor(keyFile string) (*encryptor, error) {
	contents, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("encrypted_attributes: read key_file: %w", err)
	}
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

	hash := sha256.Sum256(master)
	derived := make([]byte, subtle.AESSIVKeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, []byte("tempo-attr-v1"), []byte("aes-256-siv")), derived); err != nil {
		return nil, fmt.Errorf("encrypted_attributes: derive encryption key: %w", err)
	}
	siv, err := subtle.NewAESSIV(derived)
	if err != nil {
		return nil, fmt.Errorf("encrypted_attributes: initialize encryption: %w", err)
	}
	return &encryptor{siv: siv, kid: hex.EncodeToString(hash[:16])}, nil
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
