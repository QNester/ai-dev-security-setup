package review

import "testing"

func TestValidateContentAcceptsText(t *testing.T) {
	for _, value := range [][]byte{
		nil,
		[]byte("hello\n"),
		[]byte("package main\n"),
		[]byte("emoji: \u2603\n"),
		[]byte("tabs\tand\r\nnewlines\n"),
	} {
		if err := ValidateContent(value); err != nil {
			t.Fatalf("%q: %v", value, err)
		}
	}
}

func TestValidateContentRejectsBinary(t *testing.T) {
	for _, value := range [][]byte{
		{0},
		[]byte("hello\x00world"),
		[]byte{0xff, 0xfe, 0xfd},
		[]byte("bell\x07"),
		[]byte("delete\x7f"),
	} {
		if err := ValidateContent(value); err == nil {
			t.Fatalf("binary input was accepted: %v", value)
		}
	}
}

func TestValidateSize(t *testing.T) {
	if err := ValidateSize(10, 10); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSize(11, 10); err == nil {
		t.Fatal("oversized input was accepted")
	}
	if err := ValidateSize(0, 0); err == nil {
		t.Fatal("zero limit was accepted")
	}
}
