package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// chunkSize is the plaintext size per encrypted chunk.
	chunkSize = 32 * 1024
	nonceSize = 12 // standard GCM nonce size
	// streamIDSize is the per-file random ID length used in chunkAAD.
	streamIDSize = 16
	// maxChunkCiphertextLen caps chunk allocation so a bad length can't force ~4GiB.
	maxChunkCiphertextLen = chunkSize + 64
)

type StreamWriter struct {
	w    io.Writer
	gcm  cipher.AEAD
	buf  []byte
	done bool

	streamID      [streamIDSize]byte
	chunkIndex    uint64
	headerWritten bool
}

type StreamReader struct {
	r   io.Reader
	gcm cipher.AEAD
	buf []byte
	eof bool

	streamID   [streamIDSize]byte
	chunkIndex uint64
	headerRead bool
}

// chunkAAD ties each chunk to its file and index, blocking reorder and splice attacks.
func chunkAAD(streamID [streamIDSize]byte, index uint64) []byte {
	aad := make([]byte, streamIDSize+8)
	copy(aad, streamID[:])
	binary.BigEndian.PutUint64(aad[streamIDSize:], index)
	return aad
}

func NewCipher(base64Key string) (cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}
	if isDegenerateKey(key) {
		return nil, fmt.Errorf("encryption key is all one repeated byte, which is never a real key — check it was generated and passed correctly")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return gcm, nil
}

// isDegenerateKey catches placeholder keys whose bytes are all identical.
func isDegenerateKey(key []byte) bool {
	for _, b := range key[1:] {
		if b != key[0] {
			return false
		}
	}
	return true
}

func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func NewStreamWriter(w io.Writer, gcm cipher.AEAD) *StreamWriter {
	return &StreamWriter{w: w, gcm: gcm, buf: make([]byte, 0, chunkSize)}
}

func (sw *StreamWriter) Write(p []byte) (int, error) {
	if sw.done {
		return 0, fmt.Errorf("write to closed stream writer")
	}

	total := len(p)
	for len(p) > 0 {
		room := chunkSize - len(sw.buf)
		n := room
		if n > len(p) {
			n = len(p)
		}
		sw.buf = append(sw.buf, p[:n]...)
		p = p[n:]

		if len(sw.buf) == chunkSize {
			if err := sw.flush(); err != nil {
				return total - len(p), err
			}
		}
	}
	return total, nil
}

// flush seals and writes the buffer, then resets it. No-op when empty, so
// Close doesn't emit an empty final chunk.
func (sw *StreamWriter) flush() error {
	if len(sw.buf) == 0 {
		return nil
	}

	if !sw.headerWritten {
		if _, err := io.ReadFull(rand.Reader, sw.streamID[:]); err != nil {
			return fmt.Errorf("generate stream id: %w", err)
		}
		if _, err := sw.w.Write(sw.streamID[:]); err != nil {
			return fmt.Errorf("write stream id: %w", err)
		}
		sw.headerWritten = true
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := sw.gcm.Seal(nil, nonce, sw.buf, chunkAAD(sw.streamID, sw.chunkIndex))
	sw.chunkIndex++

	if _, err := sw.w.Write(nonce); err != nil {
		return fmt.Errorf("write chunk nonce: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext))) //nolint:gosec
	if _, err := sw.w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write chunk length: %w", err)
	}
	if _, err := sw.w.Write(ciphertext); err != nil {
		return fmt.Errorf("write chunk ciphertext: %w", err)
	}

	sw.buf = sw.buf[:0]
	return nil
}

// Close flushes any remaining buffered plaintext as a final chunk
func (sw *StreamWriter) Close() error {
	if sw.done {
		return nil
	}
	sw.done = true
	return sw.flush()
}

func NewStreamReader(r io.Reader, gcm cipher.AEAD) *StreamReader {
	return &StreamReader{r: r, gcm: gcm}
}

func (sr *StreamReader) Read(p []byte) (int, error) {
	if len(sr.buf) == 0 {
		if sr.eof {
			return 0, io.EOF
		}
		if err := sr.readChunk(); err != nil {
			return 0, err
		}
	}

	n := copy(p, sr.buf)
	sr.buf = sr.buf[n:]
	return n, nil
}

func (sr *StreamReader) readChunk() error {
	if !sr.headerRead {
		if _, err := io.ReadFull(sr.r, sr.streamID[:]); err != nil {
			if err == io.EOF {
				sr.eof = true
				return io.EOF
			}
			return fmt.Errorf("read stream id: %w", err)
		}
		sr.headerRead = true
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(sr.r, nonce); err != nil {
		if err == io.EOF {
			sr.eof = true
			return io.EOF
		}
		return fmt.Errorf("read chunk nonce: %w", err)
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(sr.r, lenBuf[:]); err != nil {
		return fmt.Errorf("read chunk length: %w", err)
	}
	ciphertextLen := binary.BigEndian.Uint32(lenBuf[:])
	if ciphertextLen > maxChunkCiphertextLen {
		return fmt.Errorf("chunk ciphertext length %d exceeds maximum %d: corrupt or truncated file", ciphertextLen, maxChunkCiphertextLen)
	}

	ciphertext := make([]byte, ciphertextLen)
	if _, err := io.ReadFull(sr.r, ciphertext); err != nil {
		return fmt.Errorf("read chunk ciphertext: %w", err)
	}

	plaintext, err := sr.gcm.Open(nil, nonce, ciphertext, chunkAAD(sr.streamID, sr.chunkIndex))
	if err != nil {
		return fmt.Errorf("decrypt chunk: %w", err)
	}
	sr.chunkIndex++
	sr.buf = plaintext
	return nil
}
