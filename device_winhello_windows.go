//go:build windows

package fido2

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/geirra/go-fido2/protocol/ctap2"
	"github.com/geirra/go-fido2/transport/winhello"
)

// winHelloDescriptors returns a Windows Hello device descriptor when the
// platform authenticator is available.
func winHelloDescriptors() []DeviceDescriptor {
	if !winhello.IsAvailable() {
		return nil
	}
	return []DeviceDescriptor{{
		Path:         winhello.DevicePath,
		Manufacturer: "Microsoft",
		Product:      "Windows Hello",
	}}
}

// openWinHelloPath opens a Windows Hello virtual device when path matches
// the well-known winhello:// sentinel.  Returns (nil, nil) for any other path.
func openWinHelloPath(path string) (*Device, error) {
	if path != winhello.DevicePath {
		return nil, nil
	}

	client, err := winhello.NewClient(0) // 0 = top-level dialog
	if err != nil {
		return nil, fmt.Errorf("failed to open Windows Hello authenticator: %w", err)
	}

	info, err := client.GetInfo()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to get Windows Hello info: %w", err)
	}

	return newDeviceFromClient(client, info), nil
}

// newDeviceFromClient creates a Device from an already-initialised ctap2.Client.
func newDeviceFromClient(client ctap2.Client, info *ctap2.AuthenticatorGetInfoResponse) *Device {
	encMode, _ := cbor.CTAP2EncOptions().EncMode()
	return &Device{
		ctapClient:  client,
		cborEncMode: encMode,
		info:        info,
	}
}
