package server

import (
	"errors"
	"runtime"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// validateTransferPath checks a path a local caller asked the daemon to read
// from or write into, before the daemon touches the filesystem with it.
func validateTransferPath(p string) error {
	if err := validateTransferPathFor(runtime.GOOS, p); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if err := checkLocalVolume(p); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return nil
}

func validateTransferPathFor(goos, p string) error {
	if p == "" {
		return errors.New("a path is required")
	}
	if goos != "windows" {
		if !strings.HasPrefix(p, "/") {
			return errors.New("path must be absolute")
		}
		return nil
	}

	if len(p) < 3 || !isASCIILetter(p[0]) || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return errors.New(`path must be an absolute path on a local drive, such as C:\Users\you\file.txt`)
	}
	if strings.Contains(p[2:], ":") {
		return errors.New("path must not contain ':' after the drive letter")
	}
	return nil
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
