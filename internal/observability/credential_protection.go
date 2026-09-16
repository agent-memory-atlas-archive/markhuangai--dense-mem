package observability

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MaxCredentialProtectionDepth bounds recursive diagnostic snapshots.
	MaxCredentialProtectionDepth = 64

	// CredentialProtectionRedacted is the bounded representation of a protected
	// credential in an otherwise available diagnostic value.
	CredentialProtectionRedacted = "[REDACTED]"

	CredentialProtectionInvalidBudget    = "invalid_max_bytes"
	CredentialProtectionBudgetExceeded   = "max_bytes_exceeded"
	CredentialProtectionDepthExceeded    = "max_depth_exceeded"
	CredentialProtectionCycleDetected    = "cycle_detected"
	CredentialProtectionUnsupported      = "unsupported_value"
	CredentialProtectionInvalidEncoding  = "invalid_encoding"
	CredentialProtectionFormattingFailed = "formatting_failed"
)

// ProtectedDiagnostic is a detached operator-facing representation. An empty
// UnavailableReason means Value is available; a non-empty reason means Value is
// nil and must not be used as a partial or raw fallback.
type ProtectedDiagnostic struct {
	Value             any
	UnavailableReason string
}

// CredentialProtector protects exact operational credentials supplied by a
// trusted owner. It deliberately has no environment or global-secret lookup;
// callers provide resolved PostgreSQL, Redis, provider, control, telemetry,
// SSO, bearer, OAuth, session, or CSRF values at the ownership boundary.
type CredentialProtector struct {
	variants []string
}

// NewCredentialProtector creates an immutable credential protector from the
// configured operational secret values. Empty values are ignored.
func NewCredentialProtector(configuredSecrets ...string) *CredentialProtector {
	return &CredentialProtector{variants: credentialVariants(configuredSecrets)}
}

// Snapshot returns a detached, bounded representation of value. Per-call
// authentication secrets are combined with the configured values without
// mutating the protector. Unsupported, cyclic, invalid, or over-budget values
// return a bounded reason and never return a raw or partial Value.
func (p *CredentialProtector) Snapshot(value any, maxBytes int, authenticatedSecrets ...string) (result ProtectedDiagnostic) {
	result = ProtectedDiagnostic{Value: nil}
	defer func() {
		if recover() != nil {
			result = unavailableDiagnostic(CredentialProtectionFormattingFailed)
		}
	}()

	if maxBytes <= 0 {
		return unavailableDiagnostic(CredentialProtectionInvalidBudget)
	}

	variants := make([]string, 0)
	if p != nil {
		variants = append(variants, p.variants...)
	}
	variants = mergeCredentialVariants(variants, credentialVariants(authenticatedSecrets))
	walker := credentialSnapshotWalker{
		variants: variants,
		active:   make(map[credentialSnapshotVisit]struct{}),
	}
	snapshot, reason := walker.walk(reflect.ValueOf(value), 0)
	if reason != "" {
		return unavailableDiagnostic(reason)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return unavailableDiagnostic(CredentialProtectionFormattingFailed)
	}
	if len(encoded) > maxBytes {
		return unavailableDiagnostic(CredentialProtectionBudgetExceeded)
	}
	return ProtectedDiagnostic{Value: snapshot}
}

func unavailableDiagnostic(reason string) ProtectedDiagnostic {
	return ProtectedDiagnostic{UnavailableReason: reason}
}

type credentialSnapshotVisit struct {
	typ  reflect.Type
	kind reflect.Kind
	ptr  uintptr
	len  int
	cap  int
}

type credentialSnapshotWalker struct {
	variants []string
	active   map[credentialSnapshotVisit]struct{}
}

var errorType = reflect.TypeOf((*error)(nil)).Elem()

func (w *credentialSnapshotWalker) walk(value reflect.Value, depth int) (any, string) {
	if !value.IsValid() {
		return nil, ""
	}
	if depth > MaxCredentialProtectionDepth {
		return nil, CredentialProtectionDepthExceeded
	}
	if isNilSnapshotValue(value) {
		return nil, ""
	}
	if value.Kind() == reflect.Interface {
		return w.walk(value.Elem(), depth)
	}
	if value.Type().Implements(errorType) {
		if !value.CanInterface() {
			return nil, CredentialProtectionFormattingFailed
		}
		text, ok := safeErrorText(value.Interface().(error))
		if !ok {
			return nil, CredentialProtectionFormattingFailed
		}
		return w.walkString(text)
	}
	if value.Type() == reflect.TypeOf(json.Number("")) {
		number := value.String()
		protected := redactCredentialText(number, w.variants)
		if protected != number {
			return protected, ""
		}
		return json.Number(number), ""
	}

	switch value.Kind() {
	case reflect.Bool:
		return value.Bool(), ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int(), ""
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint(), ""
	case reflect.Float32, reflect.Float64:
		floatValue := value.Float()
		if math.IsNaN(floatValue) || math.IsInf(floatValue, 0) {
			return nil, CredentialProtectionFormattingFailed
		}
		return floatValue, ""
	case reflect.String:
		return w.walkString(value.String())
	case reflect.Map:
		return w.walkMap(value, depth)
	case reflect.Slice:
		return w.walkSlice(value, depth)
	case reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return w.walkBytes(value, depth)
		}
		return w.walkArray(value, depth)
	case reflect.Ptr:
		return w.walkPointer(value, depth)
	default:
		return nil, CredentialProtectionUnsupported
	}
}

func (w *credentialSnapshotWalker) walkString(text string) (any, string) {
	if !utf8.ValidString(text) {
		return nil, CredentialProtectionInvalidEncoding
	}
	return redactCredentialText(text, w.variants), ""
}

func (w *credentialSnapshotWalker) walkMap(value reflect.Value, depth int) (any, string) {
	if value.IsNil() {
		return nil, ""
	}
	if value.Type().Key().Kind() != reflect.String {
		return nil, CredentialProtectionUnsupported
	}
	if reason := w.enter(value); reason != "" {
		return nil, reason
	}
	defer w.leave(value)

	result := make(map[string]any, value.Len())
	iterator := value.MapRange()
	for iterator.Next() {
		rawKey := iterator.Key().String()
		if !utf8.ValidString(rawKey) {
			return nil, CredentialProtectionInvalidEncoding
		}
		key := redactCredentialText(rawKey, w.variants)
		if _, exists := result[key]; exists {
			return nil, CredentialProtectionFormattingFailed
		}
		child, reason := w.walk(iterator.Value(), depth+1)
		if reason != "" {
			return nil, reason
		}
		result[key] = child
	}
	return result, ""
}

func (w *credentialSnapshotWalker) walkSlice(value reflect.Value, depth int) (any, string) {
	if value.IsNil() {
		return nil, ""
	}
	if value.Type().Elem().Kind() == reflect.Uint8 {
		return w.walkBytes(value, depth)
	}
	if reason := w.enter(value); reason != "" {
		return nil, reason
	}
	defer w.leave(value)

	result := make([]any, value.Len())
	for index := 0; index < value.Len(); index++ {
		child, reason := w.walk(value.Index(index), depth+1)
		if reason != "" {
			return nil, reason
		}
		result[index] = child
	}
	return result, ""
}

func (w *credentialSnapshotWalker) walkArray(value reflect.Value, depth int) (any, string) {
	result := make([]any, value.Len())
	for index := 0; index < value.Len(); index++ {
		child, reason := w.walk(value.Index(index), depth+1)
		if reason != "" {
			return nil, reason
		}
		result[index] = child
	}
	return result, ""
}

func (w *credentialSnapshotWalker) walkPointer(value reflect.Value, depth int) (any, string) {
	if reason := w.enter(value); reason != "" {
		return nil, reason
	}
	defer w.leave(value)
	return w.walk(value.Elem(), depth+1)
}

func (w *credentialSnapshotWalker) walkBytes(value reflect.Value, depth int) (any, string) {
	raw := make([]byte, value.Len())
	for index := 0; index < value.Len(); index++ {
		raw[index] = byte(value.Index(index).Uint())
	}
	if !utf8.Valid(raw) {
		return nil, CredentialProtectionInvalidEncoding
	}
	text := string(raw)
	if json.Valid(raw) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			return nil, CredentialProtectionFormattingFailed
		}
		if _, err := decoder.Token(); err != io.EOF {
			return nil, CredentialProtectionFormattingFailed
		}
		return w.walk(reflect.ValueOf(decoded), depth)
	}
	return redactCredentialText(text, w.variants), ""
}

func (w *credentialSnapshotWalker) enter(value reflect.Value) string {
	visit := snapshotVisitFor(value)
	if visit.ptr == 0 {
		return ""
	}
	if _, exists := w.active[visit]; exists {
		return CredentialProtectionCycleDetected
	}
	w.active[visit] = struct{}{}
	return ""
}

func (w *credentialSnapshotWalker) leave(value reflect.Value) {
	visit := snapshotVisitFor(value)
	if visit.ptr != 0 {
		delete(w.active, visit)
	}
}

func snapshotVisitFor(value reflect.Value) credentialSnapshotVisit {
	visit := credentialSnapshotVisit{typ: value.Type(), kind: value.Kind()}
	switch value.Kind() {
	case reflect.Map, reflect.Ptr:
		visit.ptr = value.Pointer()
	case reflect.Slice:
		visit.ptr = value.Pointer()
		visit.len = value.Len()
		visit.cap = value.Cap()
	}
	return visit
}

func isNilSnapshotValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func safeErrorText(err error) (text string, ok bool) {
	if err == nil {
		return "", true
	}
	defer func() {
		if recover() != nil {
			text = ""
			ok = false
		}
	}()
	return err.Error(), true
}

func credentialVariants(secrets []string) []string {
	variants := make([]string, 0, len(secrets)*7)
	seen := make(map[string]struct{}, len(secrets)*7)
	for _, secret := range secrets {
		addCredentialVariant(seen, &variants, secret)
		if secret == "" {
			continue
		}
		if encoded, err := json.Marshal(secret); err == nil && len(encoded) >= 2 {
			addCredentialVariant(seen, &variants, string(encoded[1:len(encoded)-1]))
		}
		quoted := strconv.Quote(secret)
		if len(quoted) >= 2 {
			addCredentialVariant(seen, &variants, quoted[1:len(quoted)-1])
		}
		quotedASCII := strconv.QuoteToASCII(secret)
		if len(quotedASCII) >= 2 {
			addCredentialVariant(seen, &variants, quotedASCII[1:len(quotedASCII)-1])
		}
		for _, encoded := range []string{url.QueryEscape(secret), url.PathEscape(secret), userInfoEscape(secret)} {
			addCredentialVariant(seen, &variants, encoded)
			addCredentialVariant(seen, &variants, lowerPercentEscapes(encoded))
		}
	}
	sort.Slice(variants, func(left, right int) bool {
		if len(variants[left]) != len(variants[right]) {
			return len(variants[left]) > len(variants[right])
		}
		return variants[left] < variants[right]
	})
	return variants
}

func mergeCredentialVariants(existing, additional []string) []string {
	if len(additional) == 0 {
		return existing
	}
	merged := append([]string(nil), existing...)
	seen := make(map[string]struct{}, len(merged)+len(additional))
	for _, variant := range merged {
		seen[variant] = struct{}{}
	}
	for _, variant := range additional {
		if _, exists := seen[variant]; exists {
			continue
		}
		seen[variant] = struct{}{}
		merged = append(merged, variant)
	}
	sort.Slice(merged, func(left, right int) bool {
		if len(merged[left]) != len(merged[right]) {
			return len(merged[left]) > len(merged[right])
		}
		return merged[left] < merged[right]
	})
	return merged
}

func addCredentialVariant(seen map[string]struct{}, variants *[]string, variant string) {
	if variant == "" {
		return
	}
	if _, exists := seen[variant]; exists {
		return
	}
	seen[variant] = struct{}{}
	*variants = append(*variants, variant)
}

func userInfoEscape(secret string) string {
	encoded := url.UserPassword("credential", secret).String()
	separator := strings.IndexByte(encoded, ':')
	if separator < 0 || separator+1 >= len(encoded) {
		return ""
	}
	return encoded[separator+1:]
}

func lowerPercentEscapes(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] == '%' && index+2 < len(value) {
			builder.WriteByte('%')
			builder.WriteString(strings.ToLower(value[index+1 : index+3]))
			index += 2
			continue
		}
		builder.WriteByte(value[index])
	}
	return builder.String()
}

func redactCredentialText(text string, variants []string) string {
	if text == "" || len(variants) == 0 {
		return text
	}
	var builder strings.Builder
	changed := false
	for index := 0; index < len(text); {
		matched := ""
		for _, variant := range variants {
			if len(variant) <= len(text)-index && strings.HasPrefix(text[index:], variant) {
				matched = variant
				break
			}
		}
		if matched != "" {
			builder.WriteString(CredentialProtectionRedacted)
			index += len(matched)
			changed = true
			continue
		}
		_, size := utf8.DecodeRuneInString(text[index:])
		if size == 0 {
			break
		}
		builder.WriteString(text[index : index+size])
		index += size
	}
	if !changed {
		return text
	}
	return builder.String()
}
