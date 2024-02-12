package syft

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Relationship is a struct that represents the relationships between packages.
type Relationship struct {
	Parent   string `json:"parent"`
	Child    string `json:"child"`
	Type     string `json:"type"`
	Metadata any    `json:"metadata,omitempty"`
}

// UniqueID returns a string that uniquely identifies a relationship
// it's made of the parent, child and type of the relationship hashed together
func (m *Relationship) UniqueID() string {
	builder := strings.Builder{}
	_, _ = builder.WriteString(m.Parent + ":" + m.Child + ":" + m.Type)
	relationshipDigest := sha256.Sum256([]byte(builder.String()))
	return fmt.Sprintf("%s", relationshipDigest)
}
