//go:build !windows

package server

func checkLocalVolume(string) error { return nil }
