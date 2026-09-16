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
	"unicode/utf16"
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
	variants []credentialVariant
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

	variants := make([]credentialVariant, 0)
	if p != nil {
		variants = append(variants, p.variants...)
	}
	variants = mergeCredentialVariants(variants, credentialVariants(authenticatedSecrets))
	if credentialMarkerCollides(variants) {
		return unavailableDiagnostic(CredentialProtectionFormattingFailed)
	}
	budget := &credentialSnapshotBudget{limit: maxBytes}
	walker := credentialSnapshotWalker{
		variants: variants,
		active:   make(map[credentialSnapshotVisit]struct{}),
	}
	snapshot, reason := walker.walk(reflect.ValueOf(value), 0, budget)
	if reason != "" {
		return unavailableDiagnostic(reason)
	}
	if budget.encoded > maxBytes {
		return unavailableDiagnostic(CredentialProtectionBudgetExceeded)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return unavailableDiagnostic(CredentialProtectionFormattingFailed)
	}
	if len(encoded) > maxBytes {
		return unavailableDiagnostic(CredentialProtectionBudgetExceeded)
	}
	if credentialTextContainsVariant(string(encoded), variants) {
		return unavailableDiagnostic(CredentialProtectionFormattingFailed)
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
	variants []credentialVariant
	active   map[credentialSnapshotVisit]struct{}
}

type credentialSnapshotBudget struct {
	limit     int
	processed int
	encoded   int
}

func (b *credentialSnapshotBudget) process(size int) bool {
	if size < 0 || b.processed > b.limit || size > b.limit-b.processed {
		return false
	}
	b.processed += size
	return true
}

func (b *credentialSnapshotBudget) reserveEncoded(size int) bool {
	if size < 0 || b.encoded > b.limit || size > b.limit-b.encoded {
		return false
	}
	b.encoded += size
	return true
}

func (b *credentialSnapshotBudget) remainingEncoded() int {
	if b.encoded >= b.limit {
		return 0
	}
	return b.limit - b.encoded
}

var errorType = reflect.TypeOf((*error)(nil)).Elem()

func (w *credentialSnapshotWalker) walk(value reflect.Value, depth int, budget *credentialSnapshotBudget) (any, string) {
	if !value.IsValid() {
		if !budget.reserveEncoded(len("null")) {
			return nil, CredentialProtectionBudgetExceeded
		}
		return nil, ""
	}
	if depth > MaxCredentialProtectionDepth {
		return nil, CredentialProtectionDepthExceeded
	}
	if isNilSnapshotValue(value) {
		if !budget.reserveEncoded(len("null")) {
			return nil, CredentialProtectionBudgetExceeded
		}
		return nil, ""
	}
	if value.Kind() == reflect.Interface {
		return w.walk(value.Elem(), depth, budget)
	}
	if value.Type().Implements(errorType) {
		if !value.CanInterface() {
			return nil, CredentialProtectionFormattingFailed
		}
		text, ok := safeErrorText(value.Interface().(error))
		if !ok {
			return nil, CredentialProtectionFormattingFailed
		}
		return w.walkString(text, budget)
	}
	if value.Type() == reflect.TypeOf(json.Number("")) {
		number := value.String()
		if !budget.process(len(number)) {
			return nil, CredentialProtectionBudgetExceeded
		}
		protected, reason := w.protectText(number, budget, true)
		if reason != "" {
			return nil, reason
		}
		if protected != number {
			encodedLength, ok := jsonEncodedStringLen(protected)
			if !ok || !budget.reserveEncoded(encodedLength) {
				return nil, CredentialProtectionBudgetExceeded
			}
			return protected, ""
		}
		if !budget.reserveEncoded(len(number)) {
			return nil, CredentialProtectionBudgetExceeded
		}
		return json.Number(number), ""
	}

	switch value.Kind() {
	case reflect.Bool:
		if !budget.reserveEncoded(len(strconv.FormatBool(value.Bool()))) {
			return nil, CredentialProtectionBudgetExceeded
		}
		return value.Bool(), ""
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if !budget.reserveEncoded(len(strconv.FormatInt(value.Int(), 10))) {
			return nil, CredentialProtectionBudgetExceeded
		}
		return value.Int(), ""
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if !budget.reserveEncoded(len(strconv.FormatUint(value.Uint(), 10))) {
			return nil, CredentialProtectionBudgetExceeded
		}
		return value.Uint(), ""
	case reflect.Float32, reflect.Float64:
		floatValue := value.Float()
		if math.IsNaN(floatValue) || math.IsInf(floatValue, 0) {
			return nil, CredentialProtectionFormattingFailed
		}
		encoded, err := json.Marshal(floatValue)
		if err != nil || !budget.reserveEncoded(len(encoded)) {
			return nil, CredentialProtectionBudgetExceeded
		}
		return floatValue, ""
	case reflect.String:
		return w.walkString(value.String(), budget)
	case reflect.Map:
		return w.walkMap(value, depth, budget)
	case reflect.Slice:
		return w.walkSlice(value, depth, budget)
	case reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return w.walkBytes(value, depth, budget)
		}
		return w.walkArray(value, depth, budget)
	case reflect.Ptr:
		return w.walkPointer(value, depth, budget)
	default:
		return nil, CredentialProtectionUnsupported
	}
}

func (w *credentialSnapshotWalker) walkString(text string, budget *credentialSnapshotBudget) (any, string) {
	protected, reason := w.protectText(text, budget, false)
	if reason != "" {
		return nil, reason
	}
	encodedLength, ok := jsonEncodedStringLen(protected)
	if !ok || !budget.reserveEncoded(encodedLength) {
		return nil, CredentialProtectionBudgetExceeded
	}
	return protected, ""
}

func (w *credentialSnapshotWalker) protectText(text string, budget *credentialSnapshotBudget, alreadyProcessed bool) (string, string) {
	if !alreadyProcessed && !budget.process(len(text)) {
		return "", CredentialProtectionBudgetExceeded
	}
	if !utf8.ValidString(text) {
		return "", CredentialProtectionInvalidEncoding
	}
	protected, ok := redactCredentialTextBounded(text, w.variants, budget.remainingEncoded())
	if !ok {
		return "", CredentialProtectionBudgetExceeded
	}
	if credentialTextContainsVariant(protected, w.variants) {
		return "", CredentialProtectionFormattingFailed
	}
	return protected, ""
}

func (w *credentialSnapshotWalker) walkMap(value reflect.Value, depth int, budget *credentialSnapshotBudget) (any, string) {
	if value.Type().Key().Kind() != reflect.String {
		return nil, CredentialProtectionUnsupported
	}
	if reason := w.enter(value); reason != "" {
		return nil, reason
	}
	defer w.leave(value)

	if !budget.reserveEncoded(1) {
		return nil, CredentialProtectionBudgetExceeded
	}
	result := make(map[string]any)
	first := true
	iterator := value.MapRange()
	for iterator.Next() {
		rawKey := iterator.Key().String()
		if !budget.process(len(rawKey)) {
			return nil, CredentialProtectionBudgetExceeded
		}
		key, reason := w.protectText(rawKey, budget, true)
		if reason != "" {
			return nil, reason
		}
		encodedKeyLength, ok := jsonEncodedStringLen(key)
		if !ok || !budget.reserveEncoded(encodedKeyLength) {
			return nil, CredentialProtectionBudgetExceeded
		}
		if !first && !budget.reserveEncoded(1) {
			return nil, CredentialProtectionBudgetExceeded
		}
		if !budget.reserveEncoded(1) {
			return nil, CredentialProtectionBudgetExceeded
		}
		if _, exists := result[key]; exists {
			return nil, CredentialProtectionFormattingFailed
		}
		child, reason := w.walk(iterator.Value(), depth+1, budget)
		if reason != "" {
			return nil, reason
		}
		result[key] = child
		first = false
	}
	if !budget.reserveEncoded(1) {
		return nil, CredentialProtectionBudgetExceeded
	}
	return result, ""
}

func (w *credentialSnapshotWalker) walkSlice(value reflect.Value, depth int, budget *credentialSnapshotBudget) (any, string) {
	if value.Type().Elem().Kind() == reflect.Uint8 {
		return w.walkBytes(value, depth, budget)
	}
	if reason := w.enter(value); reason != "" {
		return nil, reason
	}
	defer w.leave(value)

	if !budget.reserveEncoded(1) {
		return nil, CredentialProtectionBudgetExceeded
	}
	result := make([]any, 0)
	for index := 0; index < value.Len(); index++ {
		if index > 0 && !budget.reserveEncoded(1) {
			return nil, CredentialProtectionBudgetExceeded
		}
		child, reason := w.walk(value.Index(index), depth+1, budget)
		if reason != "" {
			return nil, reason
		}
		result = append(result, child)
	}
	if !budget.reserveEncoded(1) {
		return nil, CredentialProtectionBudgetExceeded
	}
	return result, ""
}

func (w *credentialSnapshotWalker) walkArray(value reflect.Value, depth int, budget *credentialSnapshotBudget) (any, string) {
	if !budget.reserveEncoded(1) {
		return nil, CredentialProtectionBudgetExceeded
	}
	result := make([]any, 0)
	for index := 0; index < value.Len(); index++ {
		if index > 0 && !budget.reserveEncoded(1) {
			return nil, CredentialProtectionBudgetExceeded
		}
		child, reason := w.walk(value.Index(index), depth+1, budget)
		if reason != "" {
			return nil, reason
		}
		result = append(result, child)
	}
	if !budget.reserveEncoded(1) {
		return nil, CredentialProtectionBudgetExceeded
	}
	return result, ""
}

func (w *credentialSnapshotWalker) walkPointer(value reflect.Value, depth int, budget *credentialSnapshotBudget) (any, string) {
	if reason := w.enter(value); reason != "" {
		return nil, reason
	}
	defer w.leave(value)
	return w.walk(value.Elem(), depth+1, budget)
}

func (w *credentialSnapshotWalker) walkBytes(value reflect.Value, depth int, budget *credentialSnapshotBudget) (any, string) {
	if !budget.process(value.Len()) {
		return nil, CredentialProtectionBudgetExceeded
	}
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
		return w.walk(reflect.ValueOf(decoded), depth, budget)
	}
	protected, reason := w.protectText(text, budget, true)
	if reason != "" {
		return nil, reason
	}
	encodedLength, ok := jsonEncodedStringLen(protected)
	if !ok || !budget.reserveEncoded(encodedLength) {
		return nil, CredentialProtectionBudgetExceeded
	}
	return protected, ""
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

type credentialVariant struct {
	text                 string
	foldPercentEscapes   bool
	foldUnicodeEscapes   bool
	allowPercentEncoding bool
	allowUnicodeEncoding bool
}

func credentialVariants(secrets []string) []credentialVariant {
	variants := make([]credentialVariant, 0, len(secrets)*7)
	seen := make(map[credentialVariant]struct{}, len(secrets)*7)
	for _, secret := range secrets {
		addCredentialVariant(seen, &variants, secret, false, false, true, true)
		if secret == "" {
			continue
		}
		if encoded, err := json.Marshal(secret); err == nil && len(encoded) >= 2 {
			addCredentialVariant(seen, &variants, string(encoded[1:len(encoded)-1]), false, true, false, false)
		}
		quoted := strconv.Quote(secret)
		if len(quoted) >= 2 {
			addCredentialVariant(seen, &variants, quoted[1:len(quoted)-1], false, true, false, false)
		}
		quotedASCII := strconv.QuoteToASCII(secret)
		if len(quotedASCII) >= 2 {
			addCredentialVariant(seen, &variants, quotedASCII[1:len(quotedASCII)-1], false, true, false, false)
		}
		for _, encoded := range []string{url.QueryEscape(secret), url.PathEscape(secret), userInfoEscape(secret)} {
			addCredentialVariant(seen, &variants, encoded, true, false, false, false)
			addCredentialVariant(seen, &variants, lowerPercentEscapes(encoded), true, false, false, false)
		}
	}
	sort.Slice(variants, func(left, right int) bool {
		if len(variants[left].text) != len(variants[right].text) {
			return len(variants[left].text) > len(variants[right].text)
		}
		if variants[left].text != variants[right].text {
			return variants[left].text < variants[right].text
		}
		if variants[left].allowPercentEncoding != variants[right].allowPercentEncoding {
			return variants[left].allowPercentEncoding
		}
		if variants[left].foldUnicodeEscapes != variants[right].foldUnicodeEscapes {
			return variants[left].foldUnicodeEscapes
		}
		if variants[left].allowUnicodeEncoding != variants[right].allowUnicodeEncoding {
			return variants[left].allowUnicodeEncoding
		}
		return !variants[left].foldPercentEscapes && variants[right].foldPercentEscapes
	})
	return variants
}

func mergeCredentialVariants(existing, additional []credentialVariant) []credentialVariant {
	if len(additional) == 0 {
		return existing
	}
	merged := append([]credentialVariant(nil), existing...)
	seen := make(map[credentialVariant]struct{}, len(merged)+len(additional))
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
		if len(merged[left].text) != len(merged[right].text) {
			return len(merged[left].text) > len(merged[right].text)
		}
		if merged[left].text != merged[right].text {
			return merged[left].text < merged[right].text
		}
		if merged[left].allowPercentEncoding != merged[right].allowPercentEncoding {
			return merged[left].allowPercentEncoding
		}
		if merged[left].foldUnicodeEscapes != merged[right].foldUnicodeEscapes {
			return merged[left].foldUnicodeEscapes
		}
		if merged[left].allowUnicodeEncoding != merged[right].allowUnicodeEncoding {
			return merged[left].allowUnicodeEncoding
		}
		return !merged[left].foldPercentEscapes && merged[right].foldPercentEscapes
	})
	return merged
}

func addCredentialVariant(seen map[credentialVariant]struct{}, variants *[]credentialVariant, text string, foldPercentEscapes, foldUnicodeEscapes, allowPercentEncoding, allowUnicodeEncoding bool) {
	if text == "" {
		return
	}
	variant := credentialVariant{
		text:                 text,
		foldPercentEscapes:   foldPercentEscapes,
		foldUnicodeEscapes:   foldUnicodeEscapes,
		allowPercentEncoding: allowPercentEncoding,
		allowUnicodeEncoding: allowUnicodeEncoding,
	}
	if _, exists := seen[variant]; exists {
		return
	}
	seen[variant] = struct{}{}
	*variants = append(*variants, variant)
}

func credentialMarkerCollides(variants []credentialVariant) bool {
	for index := 0; index < len(CredentialProtectionRedacted); index++ {
		if _, _, ok := credentialMatchAt(CredentialProtectionRedacted[index:], variants); ok {
			return true
		}
	}
	return false
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

func jsonEncodedStringLen(text string) (int, bool) {
	length := 2
	for index := 0; index < len(text); {
		runeValue, size := utf8.DecodeRuneInString(text[index:])
		if size == 0 || runeValue == utf8.RuneError && size == 1 {
			return 0, false
		}
		increment := size
		switch {
		case runeValue == '"' || runeValue == '\\' || runeValue == '\b' || runeValue == '\t' || runeValue == '\n' || runeValue == '\f' || runeValue == '\r':
			increment = 2
		case runeValue < 0x20 || runeValue == '<' || runeValue == '>' || runeValue == '&' || runeValue == '\u2028' || runeValue == '\u2029':
			increment = 6
		}
		if increment < 0 || length > int(^uint(0)>>1)-increment {
			return 0, false
		}
		length += increment
		index += size
	}
	if length < 2 {
		return 0, false
	}
	return length, true
}

func redactCredentialTextBounded(text string, variants []credentialVariant, maxOutput int) (string, bool) {
	if maxOutput < 0 {
		return "", false
	}
	if text == "" || len(variants) == 0 {
		return text, len(text) <= maxOutput
	}

	outputLength := 0
	changed := false
	for index := 0; index < len(text); {
		_, consumed, ok := credentialMatchAt(text[index:], variants)
		increment := 0
		if ok {
			increment = len(CredentialProtectionRedacted)
			index += consumed
			changed = true
		} else {
			_, size := utf8.DecodeRuneInString(text[index:])
			if size == 0 {
				return "", false
			}
			increment = size
			index += size
		}
		if outputLength > maxOutput-increment {
			return "", false
		}
		outputLength += increment
	}
	if !changed {
		return text, true
	}

	output := make([]byte, outputLength)
	outputIndex := 0
	for index := 0; index < len(text); {
		_, consumed, ok := credentialMatchAt(text[index:], variants)
		if ok {
			copy(output[outputIndex:], CredentialProtectionRedacted)
			outputIndex += len(CredentialProtectionRedacted)
			index += consumed
			continue
		}
		_, size := utf8.DecodeRuneInString(text[index:])
		copy(output[outputIndex:], text[index:index+size])
		outputIndex += size
		index += size
	}
	return string(output), true
}

func credentialTextContainsVariant(text string, variants []credentialVariant) bool {
	for index := 0; index < len(text); {
		if _, _, ok := credentialMatchAt(text[index:], variants); ok {
			return true
		}
		_, size := utf8.DecodeRuneInString(text[index:])
		if size == 0 {
			return true
		}
		index += size
	}
	return false
}

func credentialMatchAt(text string, variants []credentialVariant) (credentialVariant, int, bool) {
	for _, variant := range variants {
		if consumed, ok := credentialPrefix(text, variant); ok {
			return variant, consumed, true
		}
	}
	return credentialVariant{}, 0, false
}

func credentialPrefix(text string, variant credentialVariant) (int, bool) {
	if variant.allowPercentEncoding {
		return encodedCredentialPrefix(text, variant.text, true, variant.allowUnicodeEncoding)
	}
	if variant.allowUnicodeEncoding {
		return encodedCredentialPrefix(text, variant.text, false, true)
	}
	if len(variant.text) > len(text) {
		return 0, false
	}
	if !variant.foldPercentEscapes && !variant.foldUnicodeEscapes {
		if !strings.HasPrefix(text, variant.text) {
			return 0, false
		}
		return len(variant.text), true
	}
	for index := 0; index < len(variant.text); index++ {
		if variant.foldPercentEscapes && variant.text[index] == '%' && index+2 < len(variant.text) && isHexDigit(variant.text[index+1]) && isHexDigit(variant.text[index+2]) {
			if text[index] != '%' || !sameHexDigit(text[index+1], variant.text[index+1]) || !sameHexDigit(text[index+2], variant.text[index+2]) {
				return 0, false
			}
			index += 2
			continue
		}
		if variant.foldUnicodeEscapes && variant.text[index] == '\\' && index+5 < len(variant.text) && variant.text[index+1] == 'u' && isHexDigit(variant.text[index+2]) && isHexDigit(variant.text[index+3]) && isHexDigit(variant.text[index+4]) && isHexDigit(variant.text[index+5]) {
			if text[index] != '\\' || text[index+1] != 'u' || !sameHexDigit(text[index+2], variant.text[index+2]) || !sameHexDigit(text[index+3], variant.text[index+3]) || !sameHexDigit(text[index+4], variant.text[index+4]) || !sameHexDigit(text[index+5], variant.text[index+5]) {
				return 0, false
			}
			index += 5
			continue
		}
		if text[index] != variant.text[index] {
			return 0, false
		}
	}
	return len(variant.text), true
}

func encodedCredentialPrefix(text, variant string, allowPercentEncoding, allowUnicodeEncoding bool) (int, bool) {
	textIndex := 0
	for variantIndex := 0; variantIndex < len(variant); {
		if textIndex >= len(text) {
			return 0, false
		}
		if allowUnicodeEncoding {
			if decoded, consumed, ok := decodeGoByteEscape(text[textIndex:]); ok {
				if decoded != variant[variantIndex] {
					return 0, false
				}
				textIndex += consumed
				variantIndex++
				continue
			}
		}
		expected, size := utf8.DecodeRuneInString(variant[variantIndex:])
		if size == 0 {
			return 0, false
		}
		if allowUnicodeEncoding {
			if decoded, consumed, ok := decodeEscapedRune(text[textIndex:]); ok && decoded == expected {
				textIndex += consumed
				variantIndex += size
				continue
			}
		}
		for byteIndex := 0; byteIndex < size; byteIndex++ {
			if textIndex >= len(text) {
				return 0, false
			}
			if allowPercentEncoding && text[textIndex] == '%' && textIndex+2 < len(text) && isHexDigit(text[textIndex+1]) && isHexDigit(text[textIndex+2]) {
				if hexByte(text[textIndex+1], text[textIndex+2]) != variant[variantIndex+byteIndex] {
					return 0, false
				}
				textIndex += 3
				continue
			}
			if allowPercentEncoding && variant[variantIndex+byteIndex] == ' ' && text[textIndex] == '+' {
				textIndex++
				continue
			}
			if text[textIndex] != variant[variantIndex+byteIndex] {
				return 0, false
			}
			textIndex++
		}
		variantIndex += size
	}
	return textIndex, true
}

func decodeEscapedRune(text string) (rune, int, bool) {
	if len(text) < 2 || text[0] != '\\' {
		return 0, 0, false
	}
	switch text[1] {
	case '"', '\\', '\'', '/':
		return rune(text[1]), 2, true
	case 'a':
		return '\a', 2, true
	case 'b':
		return '\b', 2, true
	case 'f':
		return '\f', 2, true
	case 'n':
		return '\n', 2, true
	case 'r':
		return '\r', 2, true
	case 't':
		return '\t', 2, true
	case 'v':
		return '\v', 2, true
	case 'u':
		if len(text) < 6 || !isHexDigit(text[2]) || !isHexDigit(text[3]) || !isHexDigit(text[4]) || !isHexDigit(text[5]) {
			return 0, 0, false
		}
	case 'U':
		if len(text) < 10 || !isHexDigit(text[2]) || !isHexDigit(text[3]) || !isHexDigit(text[4]) || !isHexDigit(text[5]) || !isHexDigit(text[6]) || !isHexDigit(text[7]) || !isHexDigit(text[8]) || !isHexDigit(text[9]) {
			return 0, 0, false
		}
	default:
		return 0, 0, false
	}
	code := rune(hexDigit(text[2]))<<12 | rune(hexDigit(text[3]))<<8 | rune(hexDigit(text[4]))<<4 | rune(hexDigit(text[5]))
	if text[1] == 'U' {
		code = code<<16 | rune(hexDigit(text[6]))<<12 | rune(hexDigit(text[7]))<<8 | rune(hexDigit(text[8]))<<4 | rune(hexDigit(text[9]))
		if code > utf8.MaxRune || code >= 0xD800 && code <= 0xDFFF {
			return 0, 0, false
		}
		return code, 10, true
	}
	if code >= 0xD800 && code <= 0xDBFF {
		if len(text) >= 12 && text[6] == '\\' && text[7] == 'u' && isHexDigit(text[8]) && isHexDigit(text[9]) && isHexDigit(text[10]) && isHexDigit(text[11]) {
			low := rune(hexDigit(text[8]))<<12 | rune(hexDigit(text[9]))<<8 | rune(hexDigit(text[10]))<<4 | rune(hexDigit(text[11]))
			if low >= 0xDC00 && low <= 0xDFFF {
				return utf16.DecodeRune(code, low), 12, true
			}
		}
		return utf8.RuneError, 6, true
	}
	if code >= 0xDC00 && code <= 0xDFFF {
		return utf8.RuneError, 6, true
	}
	return code, 6, true
}

func decodeGoByteEscape(text string) (byte, int, bool) {
	if len(text) < 2 || text[0] != '\\' {
		return 0, 0, false
	}
	if text[1] == 'x' {
		if len(text) < 4 || !isHexDigit(text[2]) || !isHexDigit(text[3]) {
			return 0, 0, false
		}
		return hexByte(text[2], text[3]), 4, true
	}
	if text[1] < '0' || text[1] > '7' {
		return 0, 0, false
	}
	if len(text) < 4 || text[1] > '3' || text[2] < '0' || text[2] > '7' || text[3] < '0' || text[3] > '7' {
		return 0, 0, false
	}
	return (text[1]-'0')<<6 | (text[2]-'0')<<3 | (text[3] - '0'), 4, true
}

func isHexDigit(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func sameHexDigit(left, right byte) bool {
	if left >= 'A' && left <= 'F' {
		left += 'a' - 'A'
	}
	if right >= 'A' && right <= 'F' {
		right += 'a' - 'A'
	}
	return left == right
}

func hexByte(high, low byte) byte {
	return hexDigit(high)<<4 | hexDigit(low)
}

func hexDigit(value byte) byte {
	switch {
	case value >= '0' && value <= '9':
		return value - '0'
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10
	default:
		return value - 'A' + 10
	}
}
