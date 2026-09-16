package observability

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCredentialProtectorPreservesAdmittedContentAndProtectsSuppliedSecrets(t *testing.T) {
	configured := "configured-key"
	escaped := `a"b`
	userinfoSecret := "p@ss:word"
	goEscaped := fmt.Sprintf("quoted=%q", escaped)
	queryEscaped := "https://example.test/path?credential=" + url.QueryEscape(userinfoSecret)
	pathEscaped := "https://example.test/" + url.PathEscape(userinfoSecret)
	userinfoEscaped := (&url.URL{
		Scheme: "https",
		Host:   "example.test",
		User:   url.UserPassword("user", userinfoSecret),
	}).String()

	value := map[string]any{
		"token":    "fictional-token",
		"password": "fictional-password",
		"secret":   "fictional-secret",
		"detail":   "failed with " + configured,
		"go":       goEscaped,
		"query":    queryEscaped,
		"path":     pathEscaped,
		"userinfo": userinfoEscaped,
		"nested": []any{
			map[string]any{"authorization": "Bearer auth-secret"},
		},
	}

	got := NewCredentialProtector(configured, escaped, userinfoSecret).Snapshot(value, 4096, "auth-secret")
	require.Empty(t, got.UnavailableReason)

	encoded, err := json.Marshal(got.Value)
	require.NoError(t, err)
	output := string(encoded)
	require.Contains(t, output, "fictional-token")
	require.Contains(t, output, "fictional-password")
	require.Contains(t, output, "fictional-secret")
	require.NotContains(t, output, configured)
	require.NotContains(t, output, strconv.Quote(escaped))
	require.NotContains(t, output, url.QueryEscape(userinfoSecret))
	require.NotContains(t, output, url.PathEscape(userinfoSecret))
	require.NotContains(t, output, userinfoEscaped)
	require.NotContains(t, output, "auth-secret")
	require.Contains(t, output, CredentialProtectionRedacted)
}

func TestCredentialProtectorProtectsJSONByteContentAndErrors(t *testing.T) {
	protector := NewCredentialProtector("provider-secret")

	jsonValue := protector.Snapshot([]byte(`{"token":"fictional","detail":"provider-secret"}`), 256)
	require.Empty(t, jsonValue.UnavailableReason)
	decoded, ok := jsonValue.Value.(map[string]any)
	require.True(t, ok)
	require.Equal(t, "fictional", decoded["token"])
	require.Equal(t, CredentialProtectionRedacted, decoded["detail"])

	errorValue := protector.Snapshot(errors.New("provider failed: provider-secret"), 256)
	require.Empty(t, errorValue.UnavailableReason)
	require.Equal(t, "provider failed: "+CredentialProtectionRedacted, errorValue.Value)
	_, retainsError := errorValue.Value.(error)
	require.False(t, retainsError)
}

func TestCredentialProtectorSnapshotsWithoutMutation(t *testing.T) {
	value := map[string]any{
		"nested": []any{map[string]any{"message": "before configured"}},
	}
	before, err := json.Marshal(value)
	require.NoError(t, err)
	beforeHash := sha256.Sum256(before)

	got := NewCredentialProtector("credential").Snapshot(value, 1024)
	require.Empty(t, got.UnavailableReason)
	afterCapture, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, beforeHash, sha256.Sum256(afterCapture))
	value["nested"].([]any)[0].(map[string]any)["message"] = "after"

	snapshot, err := json.Marshal(got.Value)
	require.NoError(t, err)
	require.JSONEq(t, `{"nested":[{"message":"before configured"}]}`, string(snapshot))
}

func TestCredentialProtectorUsesLongestOverlappingVariant(t *testing.T) {
	got := NewCredentialProtector("secret", "secret-long").Snapshot("secret-long secret", 128)
	require.Empty(t, got.UnavailableReason)
	require.Equal(t, "[REDACTED] [REDACTED]", got.Value)
}

func TestCredentialProtectorRejectsUnsafeValuesWithoutRawFallback(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		budget int
		reason string
	}{
		{name: "invalid budget", value: "safe", budget: 0, reason: CredentialProtectionInvalidBudget},
		{name: "budget exceeded", value: strings.Repeat("界", 10), budget: 3, reason: CredentialProtectionBudgetExceeded},
		{name: "unsupported struct", value: struct{ Value string }{Value: "safe"}, budget: 128, reason: CredentialProtectionUnsupported},
		{name: "unsupported map key", value: map[int]string{1: "safe"}, budget: 128, reason: CredentialProtectionUnsupported},
		{name: "invalid map key encoding", value: map[string]string{string([]byte{0xff}): "safe"}, budget: 128, reason: CredentialProtectionInvalidEncoding},
		{name: "invalid string encoding", value: string([]byte{0xff}), budget: 128, reason: CredentialProtectionInvalidEncoding},
		{name: "invalid byte encoding", value: []byte{0xff}, budget: 128, reason: CredentialProtectionInvalidEncoding},
		{name: "nonfinite float", value: math.NaN(), budget: 128, reason: CredentialProtectionFormattingFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NewCredentialProtector("safe").Snapshot(test.value, test.budget)
			require.Equal(t, test.reason, got.UnavailableReason)
			require.Nil(t, got.Value)
		})
	}

	cyclicMap := map[string]any{}
	cyclicMap["self"] = cyclicMap
	got := NewCredentialProtector("safe").Snapshot(cyclicMap, 1024)
	require.Equal(t, CredentialProtectionCycleDetected, got.UnavailableReason)
	require.Nil(t, got.Value)

	cyclicSlice := []any{nil}
	cyclicSlice[0] = cyclicSlice
	got = NewCredentialProtector("safe").Snapshot(cyclicSlice, 1024)
	require.Equal(t, CredentialProtectionCycleDetected, got.UnavailableReason)
	require.Nil(t, got.Value)
}

func TestCredentialProtectorRejectsExcessiveDepth(t *testing.T) {
	var value any = "leaf"
	for index := 0; index < MaxCredentialProtectionDepth+1; index++ {
		value = map[string]any{"next": value}
	}

	got := NewCredentialProtector("leaf").Snapshot(value, 1<<20)
	require.Equal(t, CredentialProtectionDepthExceeded, got.UnavailableReason)
	require.Nil(t, got.Value)

	value = []byte(`{"next":"leaf"}`)
	for index := 0; index < MaxCredentialProtectionDepth; index++ {
		value = map[string]any{"next": value}
	}
	got = NewCredentialProtector("leaf").Snapshot(value, 1<<20)
	require.Equal(t, CredentialProtectionDepthExceeded, got.UnavailableReason)
	require.Nil(t, got.Value)
}

func TestCredentialProtectorDetachedAuthenticationSecretsAndUnicodeByteBudget(t *testing.T) {
	protector := NewCredentialProtector("configured")
	value := map[string]any{"message": "configured auth-only"}
	got := protector.Snapshot(value, 256, "auth-only")
	require.Empty(t, got.UnavailableReason)
	before, err := json.Marshal(value)
	require.NoError(t, err)
	got = protector.Snapshot(value, 256, "auth-only")
	after, err := json.Marshal(value)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(before), sha256.Sum256(after))
	value["message"] = "changed"
	require.Equal(t, map[string]any{"message": "[REDACTED] [REDACTED]"}, got.Value)
	independent := protector.Snapshot(map[string]any{"message": "auth-only"}, 256)
	require.Empty(t, independent.UnavailableReason)
	require.Equal(t, map[string]any{"message": "auth-only"}, independent.Value)

	text := strings.Repeat("界", 4)
	encoded, err := json.Marshal(text)
	require.NoError(t, err)
	require.Empty(t, protector.Snapshot(text, len(encoded)).UnavailableReason)
	require.Equal(t, CredentialProtectionBudgetExceeded, protector.Snapshot(text, len(encoded)-1).UnavailableReason)

	if reflect.DeepEqual(got.Value, value) {
		t.Fatal("snapshot unexpectedly retained the caller map")
	}
}

func TestCredentialProtectorPreservesLosslessJSONNumbers(t *testing.T) {
	for _, input := range []string{`9007199254740993`, `1e1000000`} {
		got := NewCredentialProtector("secret").Snapshot([]byte(input), 128)
		require.Empty(t, got.UnavailableReason)
		encoded, err := json.Marshal(got.Value)
		require.NoError(t, err)
		require.Equal(t, input, string(encoded))
	}
}

type panicDiagnosticError struct{}

func (panicDiagnosticError) Error() string { panic("diagnostic formatting failed") }

func TestCredentialProtectorConvertsFormattingPanicsToBoundedFailure(t *testing.T) {
	got := NewCredentialProtector("secret").Snapshot(panicDiagnosticError{}, 256)
	require.Equal(t, CredentialProtectionFormattingFailed, got.UnavailableReason)
	require.Nil(t, got.Value)
}
