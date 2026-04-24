//go:build !windows

package fido2

// winHelloDescriptors returns Windows Hello device descriptors.
// Always empty on non-Windows platforms.
func winHelloDescriptors() []DeviceDescriptor { return nil }

// openWinHelloPath attempts to open a Windows Hello virtual device by path.
// Always returns (nil, nil) on non-Windows platforms.
func openWinHelloPath(_ string) (*Device, error) { return nil, nil }
