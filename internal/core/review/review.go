package review

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"
)

// ValidateContent rejects binary data while allowing normal text control
// characters. The review sandbox never executes the file; this check only
// prevents dumping large binary payloads into a model context.
func ValidateContent(data []byte) error {
	if bytes.IndexByte(data, 0) >= 0 {
		return errors.New("review input contains NUL bytes and is not text")
	}
	if !utf8.Valid(data) {
		return errors.New("review input is not valid UTF-8 text")
	}
	for _, value := range data {
		if value == 0x7f {
			return fmt.Errorf("review input contains a binary control byte 0x%02x", value)
		}
		if value >= 0x20 || value == '\t' || value == '\n' || value == '\r' || value == '\f' || value == '\b' {
			continue
		}
		return fmt.Errorf("review input contains a binary control byte 0x%02x", value)
	}
	return nil
}

// ValidateSize checks the configured document limit.
func ValidateSize(size, limit int64) error {
	if size < 0 {
		return errors.New("review input size is invalid")
	}
	if limit <= 0 {
		return errors.New("review size limit is not configured")
	}
	if size > limit {
		return fmt.Errorf("review input is %d bytes; the limit is %d bytes", size, limit)
	}
	return nil
}
