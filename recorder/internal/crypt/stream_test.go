package crypt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"testing"
)

func testCipher(t *testing.T) interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
} {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	gcm, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return gcm
}

func roundTrip(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	gcm := testCipher(t)

	var buf bytes.Buffer
	sw := NewStreamWriter(&buf, gcm)
	if _, err := sw.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sr := NewStreamReader(&buf, gcm)
	got, err := io.ReadAll(sr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return got
}

func TestStream_RoundTrip_EmptyInput(t *testing.T) {
	got := roundTrip(t, nil)
	if len(got) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(got))
	}
}

func TestStream_RoundTrip_SmallInput(t *testing.T) {
	want := []byte("hello, this is a small recording chunk")
	got := roundTrip(t, want)
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestStream_RoundTrip_ExactlyOneChunk(t *testing.T) {
	want := bytes.Repeat([]byte("x"), chunkSize)
	got := roundTrip(t, want)
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch for exact-chunk-size input (len %d vs %d)", len(got), len(want))
	}
}

func TestStream_RoundTrip_OneByteOverChunkBoundary(t *testing.T) {
	want := bytes.Repeat([]byte("y"), chunkSize+1)
	got := roundTrip(t, want)
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch for chunk+1 input (len %d vs %d)", len(got), len(want))
	}
}

func TestStream_RoundTrip_OneByteUnderChunkBoundary(t *testing.T) {
	want := bytes.Repeat([]byte("z"), chunkSize-1)
	got := roundTrip(t, want)
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch for chunk-1 input (len %d vs %d)", len(got), len(want))
	}
}

func TestStream_RoundTrip_MultiChunkInput(t *testing.T) {
	want := bytes.Repeat([]byte("abcdefgh"), chunkSize) // ~256KB, several chunks
	got := roundTrip(t, want)
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch for multi-chunk input (len %d vs %d)", len(got), len(want))
	}
}

func TestStream_RoundTrip_IncrementalWrites(t *testing.T) {
	gcm := testCipher(t)
	var buf bytes.Buffer
	sw := NewStreamWriter(&buf, gcm)

	var want []byte
	for i := 0; i < 500; i++ {
		chunk := []byte("incremental-write-chunk-")
		want = append(want, chunk...)
		if _, err := sw.Write(chunk); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sr := NewStreamReader(&buf, gcm)
	got, err := io.ReadAll(sr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch for incremental writes (len %d vs %d)", len(got), len(want))
	}
}

func TestStream_CorruptedChunkFailsCleanlyWithoutPanic(t *testing.T) {
	gcm := testCipher(t)
	var buf bytes.Buffer
	sw := NewStreamWriter(&buf, gcm)
	if _, err := sw.Write([]byte("sensitive terminal output")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	corrupted := buf.Bytes()
	if len(corrupted) > 20 {
		corrupted[20] ^= 0xFF
	}

	sr := NewStreamReader(bytes.NewReader(corrupted), gcm)
	_, err := io.ReadAll(sr)
	if err == nil {
		t.Fatal("expected decryption error for corrupted chunk, got nil")
	}
}

func TestStream_WrongKeyFailsCleanly(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	gcm1, _ := NewCipher(key1)
	gcm2, _ := NewCipher(key2)

	var buf bytes.Buffer
	sw := NewStreamWriter(&buf, gcm1)
	if _, err := sw.Write([]byte("secret")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sr := NewStreamReader(&buf, gcm2)
	_, err := io.ReadAll(sr)
	if err == nil {
		t.Fatal("expected decryption error when reading with the wrong key, got nil")
	}
}

func TestNewCipher_RejectsWrongKeyLength(t *testing.T) {
	if _, err := NewCipher("dG9vc2hvcnQ="); err == nil {
		t.Fatal("expected error for a too-short key")
	}
}

func TestNewCipher_RejectsDegenerateKey(t *testing.T) {
	allZero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := NewCipher(allZero); err == nil {
		t.Fatal("expected error for an all-zero key")
	}

	allFF := make([]byte, 32)
	for i := range allFF {
		allFF[i] = 0xFF
	}
	if _, err := NewCipher(base64.StdEncoding.EncodeToString(allFF)); err == nil {
		t.Fatal("expected error for an all-0xFF key")
	}

	// A real random key must still be accepted.
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := NewCipher(key); err != nil {
		t.Fatalf("expected a genuinely random key to be accepted, got %v", err)
	}
}

func writeMultiChunk(t *testing.T, gcm interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	sw := NewStreamWriter(&buf, gcm)
	plaintext := bytes.Repeat([]byte("A"), chunkSize*2+10)
	if _, err := sw.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func chunkOffsets(t *testing.T, data []byte) []int {
	t.Helper()
	var offsets []int
	pos := streamIDSize
	for pos < len(data) {
		offsets = append(offsets, pos)
		pos += nonceSize
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4 + length
	}
	return offsets
}

func TestStream_ChunkSplicedFromAnotherFileFailsToDecrypt(t *testing.T) {
	gcm := testCipher(t)

	fileA := writeMultiChunk(t, gcm)
	fileB := writeMultiChunk(t, gcm)

	offsetsA := chunkOffsets(t, fileA)
	offsetsB := chunkOffsets(t, fileB)
	if len(offsetsA) < 2 || len(offsetsB) < 2 {
		t.Fatalf("expected at least 2 chunks per file, got %d and %d", len(offsetsA), len(offsetsB))
	}

	spliced := append([]byte(nil), fileB...)
	chunkALen := offsetsA[1] - offsetsA[0]
	chunkBLen := offsetsB[1] - offsetsB[0]
	if chunkALen != chunkBLen {
		t.Fatalf("chunk length mismatch, splice precondition violated: %d vs %d", chunkALen, chunkBLen)
	}
	copy(spliced[offsetsB[0]:offsetsB[1]], fileA[offsetsA[0]:offsetsA[1]])

	sr := NewStreamReader(bytes.NewReader(spliced), gcm)
	_, err := io.ReadAll(sr)
	if err == nil {
		t.Fatal("expected decryption to fail for a chunk spliced in from a different file, got nil error")
	}
}

func TestStream_ReorderedChunksFailToDecrypt(t *testing.T) {
	gcm := testCipher(t)
	data := writeMultiChunk(t, gcm)

	offsets := chunkOffsets(t, data)
	if len(offsets) < 3 {
		t.Fatalf("expected at least 3 chunks, got %d", len(offsets))
	}

	c0 := append([]byte(nil), data[offsets[0]:offsets[1]]...)
	c1 := append([]byte(nil), data[offsets[1]:offsets[2]]...)
	if len(c0) != len(c1) {
		t.Fatalf("chunk length mismatch, swap precondition violated: %d vs %d", len(c0), len(c1))
	}

	swapped := append([]byte(nil), data...)
	copy(swapped[offsets[0]:offsets[1]], c1)
	copy(swapped[offsets[1]:offsets[2]], c0)

	sr := NewStreamReader(bytes.NewReader(swapped), gcm)
	_, err := io.ReadAll(sr)
	if err == nil {
		t.Fatal("expected decryption to fail for reordered chunks, got nil error")
	}
}

func TestStream_OversizedChunkLengthRejected(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(make([]byte, streamIDSize)) // stream id header
	buf.Write(make([]byte, nonceSize))    // nonce
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 0xFFFFFFFE)
	buf.Write(lenBuf[:])

	gcm := testCipher(t)
	sr := NewStreamReader(&buf, gcm)
	_, err := io.ReadAll(sr)
	if err == nil {
		t.Fatal("expected an error for an oversized chunk length, got nil")
	}
}
