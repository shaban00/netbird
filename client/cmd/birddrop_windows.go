//go:build windows

package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cfUnicodeText = 13

	gmemMoveable = 0x0002
	gmemZeroInit = 0x0040
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")

	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")

	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalFree   = kernel32.NewProc("GlobalFree")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
)

func readClipboardText(ctx context.Context) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := openClipboard(ctx); err != nil {
		return "", err
	}
	defer closeClipboard()

	available, _, _ := procIsClipboardFormatAvailable.Call(cfUnicodeText)
	if available == 0 {
		return "", nil
	}

	handle, _, err := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return "", windowsClipboardError("get clipboard data", err)
	}

	ptr, err := lockedUTF16Pointer(handle)
	if err != nil {
		return "", err
	}
	defer procGlobalUnlock.Call(handle)

	return windows.UTF16PtrToString(ptr), nil
}

func writeClipboardText(ctx context.Context, text string) error {
	utf16Text, err := windows.UTF16FromString(text)
	if err != nil {
		return fmt.Errorf("encode clipboard text: %w", err)
	}

	size := uintptr(len(utf16Text) * 2)

	handle, _, err := procGlobalAlloc.Call(
		gmemMoveable|gmemZeroInit,
		size,
	)
	if handle == 0 {
		return windowsClipboardError("allocate clipboard memory", err)
	}

	ownsMemory := true
	defer func() {
		if ownsMemory {
			procGlobalFree.Call(handle)
		}
	}()

	ptr, err := lockedUTF16Pointer(handle)
	if err != nil {
		return err
	}

	copy(
		unsafe.Slice(ptr, len(utf16Text)),
		utf16Text,
	)

	procGlobalUnlock.Call(handle)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := openClipboard(ctx); err != nil {
		return err
	}
	defer closeClipboard()

	ok, _, err := procEmptyClipboard.Call()
	if ok == 0 {
		return windowsClipboardError("empty clipboard", err)
	}

	result, _, err := procSetClipboardData.Call(cfUnicodeText, handle)
	if result == 0 {
		return windowsClipboardError("set clipboard data", err)
	}

	// SetClipboardData transfers ownership of the HGLOBAL to Windows.
	ownsMemory = false

	return nil
}

func lockedUTF16Pointer(handle uintptr) (*uint16, error) {
	ptr, _, err := procGlobalLock.Call(handle)
	if ptr == 0 {
		return nil, windowsClipboardError("lock clipboard memory", err)
	}

	return (*uint16)(unsafe.Pointer(ptr)), nil //nolint:unsafeptr
}

func openClipboard(ctx context.Context) error {
	var lastErr error

	for range 40 {
		ok, _, err := procOpenClipboard.Call(0)
		if ok != 0 {
			return nil
		}

		lastErr = windowsClipboardError("open clipboard", err)

		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()

		case <-timer.C:
		}
	}

	return lastErr
}

func closeClipboard() {
	procCloseClipboard.Call()
}

func windowsClipboardError(operation string, err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return fmt.Errorf("%s failed", operation)
	}

	return fmt.Errorf("%s: %w", operation, err)
}

func richConsole() bool {
	if os.Getenv("WT_SESSION") == "" {
		return false
	}
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setConsoleOutputCP := kernel32.NewProc("SetConsoleOutputCP")
	const cpUTF8 = 65001
	if r, _, _ := setConsoleOutputCP.Call(uintptr(cpUTF8)); r == 0 {
		return false
	}
	return true
}

// terminalWidth returns the console width in columns, or 0 if it cannot be determined.
func terminalWidth() int {
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(os.Stderr.Fd()), &info); err != nil {
		return 0
	}
	w := int(info.Window.Right - info.Window.Left + 1)
	if w < 0 {
		return 0
	}
	return w
}
