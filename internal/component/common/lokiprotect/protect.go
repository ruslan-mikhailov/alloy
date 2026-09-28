// Package lokiprotect seals exact Loki field values before they reach an exporter.
package lokiprotect

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/tink-crypto/tink-go/v2/daead/subtle"
	"golang.org/x/crypto/hkdf"
)

const Scheme = "aes256siv-hkdf-v1"
const MaxValueBytes = 64 * 1024

// Policy assigns fields to one local master. A field belongs to exactly one policy.
type Policy struct {
	Fields      []string `alloy:"fields,attr" mapstructure:"fields"`
	KeyFile     string   `alloy:"key_file,attr" mapstructure:"key_file"`
	ValueScheme string   `alloy:"value_scheme,attr" mapstructure:"value_scheme"`
}

type key struct {
	siv *subtle.AESSIV
	kid string
}

// Protector is immutable and safe to share between consumers.
type Protector struct {
	fields map[string]*key
}

// ValidatePolicies rejects ambiguous, unsupported, or incomplete selections.
func ValidatePolicies(policies []Policy) error {
	if len(policies) == 0 {
		return fmt.Errorf("encrypted_logs: policies must not be empty")
	}
	seen := make(map[string]bool)
	for i, policy := range policies {
		if len(policy.Fields) == 0 || policy.KeyFile == "" || policy.ValueScheme != Scheme {
			return fmt.Errorf("encrypted_logs: policy %d requires fields, key_file and value_scheme %q", i, Scheme)
		}
		for _, field := range policy.Fields {
			category, name, ok := strings.Cut(field, ".")
			if !ok || !validName(name) ||
				(category != "label" && category != "line" && category != "metadata") {
				return fmt.Errorf("encrypted_logs: invalid field %q", field)
			}
			if seen[field] {
				return fmt.Errorf("encrypted_logs: duplicate field %q", field)
			}
			seen[field] = true
		}
	}
	return nil
}

// Loki label and logfmt identifiers have one unambiguous spelling across ingestion and query.
func validName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	for i := range len(name) {
		b := name[i]
		if b == '_' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || i > 0 && b >= '0' && b <= '9' {
			continue
		}
		return false
	}
	return true
}

// New loads each key once. A key file contains padded standard base64 for 32 bytes.
func New(policies []Policy) (*Protector, error) {
	if err := ValidatePolicies(policies); err != nil {
		return nil, err
	}
	p := &Protector{fields: make(map[string]*key)}
	for i, policy := range policies {
		contents, err := readKeyFile(policy.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("encrypted_logs: policy %d read key_file: %w", i, err)
		}
		encoded := strings.TrimSuffix(string(contents), "\n")
		encoded = strings.TrimSuffix(encoded, "\r")
		clear(contents)
		master, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(master) != 32 {
			clear(master)
			return nil, fmt.Errorf("encrypted_logs: policy %d key_file must contain exactly 32 standard base64-encoded bytes", i)
		}
		hash := sha256.Sum256(master)
		derived := make([]byte, subtle.AESSIVKeySize)
		_, err = io.ReadFull(hkdf.New(sha256.New, master, []byte("loki-value-v1"), []byte("aes-256-siv")), derived)
		clear(master)
		if err != nil {
			clear(derived)
			return nil, fmt.Errorf("encrypted_logs: derive key: %w", err)
		}
		// AESSIV retains references to the derived key slices; do not clear on success.
		siv, err := subtle.NewAESSIV(derived)
		if err != nil {
			clear(derived)
			return nil, fmt.Errorf("encrypted_logs: initialize encryption: %w", err)
		}
		k := &key{siv: siv, kid: hex.EncodeToString(hash[:16])}
		for _, field := range policy.Fields {
			p.fields[field] = k
		}
	}
	return p, nil
}

func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 46 {
		return nil, fmt.Errorf("key_file must be a regular file of at most 46 bytes")
	}
	contents, err := io.ReadAll(io.LimitReader(f, 47))
	if err != nil {
		return nil, err
	}
	if len(contents) > 46 {
		clear(contents)
		return nil, fmt.Errorf("key_file exceeds 46 bytes")
	}
	return contents, nil
}

func (p *Protector) Has(field string) bool { _, ok := p.fields[field]; return ok }

// Fields enumerates configured field paths, without exposing keys.
func (p *Protector) Fields() []string {
	fields := make([]string, 0, len(p.fields))
	for field := range p.fields {
		fields = append(fields, field)
	}
	return fields
}

// Seal authenticates exact UTF-8 bytes and the category-qualified original field name.
func (p *Protector) Seal(field, plaintext string) (string, error) {
	k := p.fields[field]
	if k == nil {
		return "", fmt.Errorf("encrypted_logs: unconfigured field %q", field)
	}
	if len(plaintext) > MaxValueBytes || !utf8.ValidString(plaintext) || strings.HasPrefix(plaintext, "lenc:") {
		return "", fmt.Errorf("encrypted_logs: invalid or already encrypted value for %q", field)
	}
	const domain = "loki:value:v1"
	ad := make([]byte, len(domain)+1+4+len(field))
	copy(ad, domain)
	binary.BigEndian.PutUint32(ad[len(domain)+1:], uint32(len(field)))
	copy(ad[len(domain)+1+4:], field)
	ciphertext, err := k.siv.EncryptDeterministically([]byte(plaintext), ad)
	if err != nil {
		return "", fmt.Errorf("encrypted_logs: encrypt %q: %w", field, err)
	}
	return "lenc:v1:" + k.kid + ":" + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}
