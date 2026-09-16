package observability

import "unicode/utf8"

type credentialDecodedByte struct {
	value byte
	end   int
}

func decodedCredentialPrefix(text, variant string, allowPercentEncoding bool) (int, bool) {
	raw := rawCredentialPrefix(text, credentialRawByteLimit(len(variant)))
	decoded := decodeCredentialLayers(raw, allowPercentEncoding, true, false)
	return matchDecodedCredentialPrefix(decoded, variant)
}

func reverseDecodedCredentialPrefix(text, variant string) (int, bool) {
	raw := rawCredentialPrefix(text, credentialRawByteLimit(len(variant)))
	decoded := decodeCredentialLayers(raw, true, true, true)
	return matchDecodedCredentialPrefix(decoded, variant)
}

const maxCredentialDecodeLayers = 4

func decodeCredentialLayers(input []credentialDecodedByte, allowPercentEncoding, allowUnicodeEncoding, percentFirst bool) []credentialDecodedByte {
	decoded := input
	for layer := 0; layer < maxCredentialDecodeLayers; layer++ {
		before := decoded
		if percentFirst && allowPercentEncoding {
			decoded = decodeCredentialPercentLayer(decoded)
		}
		if allowUnicodeEncoding {
			decoded = decodeCredentialEscapeLayer(decoded)
		}
		if !percentFirst && allowPercentEncoding {
			decoded = decodeCredentialPercentLayer(decoded)
		}
		if credentialDecodedBytesEqual(before, decoded) {
			break
		}
	}
	return decoded
}

func credentialDecodedBytesEqual(left, right []credentialDecodedByte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].value != right[index].value || left[index].end != right[index].end {
			return false
		}
	}
	return true
}

func credentialRawByteLimit(variantLength int) int {
	const maxEncodingExpansion = 30
	maxInt := int(^uint(0) >> 1)
	if variantLength > maxInt/maxEncodingExpansion {
		return maxInt
	}
	return variantLength * maxEncodingExpansion
}

func rawCredentialPrefix(text string, maxBytes int) []credentialDecodedByte {
	if maxBytes <= 0 {
		return nil
	}
	capacity := maxBytes
	if capacity > len(text) {
		capacity = len(text)
	}
	raw := make([]credentialDecodedByte, 0, capacity)
	for textIndex := 0; textIndex < len(text) && len(raw) < maxBytes; {
		_, size := utf8.DecodeRuneInString(text[textIndex:])
		if size == 0 {
			break
		}
		for index := 0; index < size && len(raw) < maxBytes; index++ {
			raw = append(raw, credentialDecodedByte{value: text[textIndex+index], end: textIndex + size})
		}
		textIndex += size
	}
	return raw
}

func decodeCredentialPercentLayer(input []credentialDecodedByte) []credentialDecodedByte {
	decoded := make([]credentialDecodedByte, 0, len(input))
	for index := 0; index < len(input); {
		if input[index].value == '%' && index+2 < len(input) && isHexDigit(input[index+1].value) && isHexDigit(input[index+2].value) {
			decoded = append(decoded, credentialDecodedByte{
				value: hexByte(input[index+1].value, input[index+2].value),
				end:   input[index+2].end,
			})
			index += 3
			continue
		}
		if input[index].value == '+' {
			decoded = append(decoded, credentialDecodedByte{value: ' ', end: input[index].end})
			index++
			continue
		}
		decoded = append(decoded, input[index])
		index++
	}
	return decoded
}

func decodeCredentialEscapeLayer(input []credentialDecodedByte) []credentialDecodedByte {
	if len(input) == 0 {
		return nil
	}
	raw := make([]byte, len(input))
	for index, value := range input {
		raw[index] = value.value
	}
	text := string(raw)
	decoded := make([]credentialDecodedByte, 0, len(input))
	for index := 0; index < len(input); {
		if escaped, consumed, ok := decodeGoByteEscape(text[index:]); ok {
			decoded = append(decoded, credentialDecodedByte{value: escaped, end: input[index+consumed-1].end})
			index += consumed
			continue
		}
		if escaped, consumed, ok := decodeEscapedRune(text[index:]); ok {
			var encoded [utf8.UTFMax]byte
			encodedSize := utf8.EncodeRune(encoded[:], escaped)
			end := input[index+consumed-1].end
			for encodedIndex := 0; encodedIndex < encodedSize; encodedIndex++ {
				decoded = append(decoded, credentialDecodedByte{value: encoded[encodedIndex], end: end})
			}
			index += consumed
			continue
		}
		_, size := utf8.DecodeRuneInString(text[index:])
		if size == 0 {
			break
		}
		for encodedIndex := 0; encodedIndex < size; encodedIndex++ {
			decoded = append(decoded, input[index+encodedIndex])
		}
		index += size
	}
	return decoded
}

func matchDecodedCredentialPrefix(decoded []credentialDecodedByte, variant string) (int, bool) {
	if len(decoded) < len(variant) {
		return 0, false
	}
	for index := 0; index < len(variant); index++ {
		if decoded[index].value != variant[index] {
			return 0, false
		}
	}
	return decoded[len(variant)-1].end, true
}
