//go:build !windows

package winhello

import (
	"errors"
	"iter"

	"github.com/ldclabs/cose/key"
	"github.com/geirra/go-fido2/protocol/ctap2"
	"github.com/geirra/go-fido2/protocol/webauthn"
)

// DevicePath is the virtual path used to identify the Windows Hello authenticator.
const DevicePath = ""

var errNotSupported = errors.New("winhello: not supported on this platform")

// IsAvailable always returns false on non-Windows platforms.
func IsAvailable() bool { return false }

// Client is a stub on non-Windows platforms.
type Client struct{}

// NewClient always returns an error on non-Windows platforms.
func NewClient(_ uintptr) (*Client, error) {
	return nil, errNotSupported
}

func (c *Client) Close() error { return nil }

func (c *Client) GetInfo() (*ctap2.AuthenticatorGetInfoResponse, error) {
	return nil, errNotSupported
}

func (c *Client) MakeCredential(
	_ ctap2.PinUvAuthProtocolType, _ []byte, _ []byte,
	_ webauthn.PublicKeyCredentialRpEntity,
	_ webauthn.PublicKeyCredentialUserEntity,
	_ []webauthn.PublicKeyCredentialParameters,
	_ []webauthn.PublicKeyCredentialDescriptor,
	_ *ctap2.CreateExtensionInputs,
	_ map[ctap2.Option]bool, _ uint,
	_ []webauthn.AttestationStatementFormatIdentifier,
) (*ctap2.AuthenticatorMakeCredentialResponse, error) {
	return nil, errNotSupported
}

func (c *Client) GetAssertion(
	_ ctap2.PinUvAuthProtocolType, _ []byte,
	_ string, _ []byte,
	_ []webauthn.PublicKeyCredentialDescriptor,
	_ *ctap2.GetExtensionInputs,
	_ map[ctap2.Option]bool,
) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(*ctap2.AuthenticatorGetAssertionResponse, error) bool) {
		yield(nil, errNotSupported)
	}
}

func (c *Client) GetPINRetries(_ ctap2.PinUvAuthProtocolType) (uint, bool, error) {
	return 0, false, errNotSupported
}
func (c *Client) GetKeyAgreement(_ ctap2.PinUvAuthProtocolType) (key.Key, error) {
	return nil, errNotSupported
}
func (c *Client) SetPIN(_ ctap2.PinUvAuthProtocolType, _ key.Key, _ string) error {
	return errNotSupported
}
func (c *Client) ChangePIN(_ ctap2.PinUvAuthProtocolType, _ key.Key, _, _ string) error {
	return errNotSupported
}
func (c *Client) GetPinToken(_ ctap2.PinUvAuthProtocolType, _ key.Key, _ string) ([]byte, error) {
	return nil, errNotSupported
}
func (c *Client) GetPinUvAuthTokenUsingUvWithPermissions(
	_ ctap2.PinUvAuthProtocolType, _ key.Key, _ ctap2.Permission, _ string,
) ([]byte, error) {
	return nil, errNotSupported
}
func (c *Client) GetUVRetries() (uint, error) { return 0, errNotSupported }
func (c *Client) GetPinUvAuthTokenUsingPinWithPermissions(
	_ ctap2.PinUvAuthProtocolType, _ key.Key, _ string, _ ctap2.Permission, _ string,
) ([]byte, error) {
	return nil, errNotSupported
}
func (c *Client) GetBioModality(_ bool) (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	return nil, errNotSupported
}
func (c *Client) GetFingerprintSensorInfo(_ bool) (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	return nil, errNotSupported
}
func (c *Client) BeginEnroll(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte, _ uint,
) (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	return nil, errNotSupported
}
func (c *Client) EnrollCaptureNextSample(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte, _ []byte, _ uint,
) (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	return nil, errNotSupported
}
func (c *Client) CancelCurrentEnrollment(_ bool) error { return errNotSupported }
func (c *Client) EnumerateEnrollments(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte,
) (*ctap2.AuthenticatorBioEnrollmentResponse, error) {
	return nil, errNotSupported
}
func (c *Client) SetFriendlyName(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte, _ []byte, _ string,
) error {
	return errNotSupported
}
func (c *Client) RemoveEnrollment(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte, _ []byte,
) error {
	return errNotSupported
}
func (c *Client) GetCredsMetadata(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte,
) (*ctap2.AuthenticatorCredentialManagementResponse, error) {
	return nil, errNotSupported
}
func (c *Client) EnumerateRPs(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte,
) iter.Seq2[*ctap2.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*ctap2.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(nil, errNotSupported)
	}
}
func (c *Client) EnumerateCredentials(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte, _ []byte,
) iter.Seq2[*ctap2.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*ctap2.AuthenticatorCredentialManagementResponse, error) bool) {
		yield(nil, errNotSupported)
	}
}
func (c *Client) DeleteCredential(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte, _ webauthn.PublicKeyCredentialDescriptor,
) error {
	return errNotSupported
}
func (c *Client) UpdateUserInformation(
	_ bool, _ ctap2.PinUvAuthProtocolType, _ []byte,
	_ webauthn.PublicKeyCredentialDescriptor,
	_ webauthn.PublicKeyCredentialUserEntity,
) error {
	return errNotSupported
}
func (c *Client) LargeBlobs(
	_ ctap2.PinUvAuthProtocolType, _ []byte, _ uint, _ []byte, _ uint, _ uint,
) (*ctap2.AuthenticatorLargeBlobsResponse, error) {
	return nil, errNotSupported
}
func (c *Client) EnableEnterpriseAttestation(_ ctap2.PinUvAuthProtocolType, _ []byte) error {
	return errNotSupported
}
func (c *Client) ToggleAlwaysUV(_ ctap2.PinUvAuthProtocolType, _ []byte) error {
	return errNotSupported
}
func (c *Client) SetMinPINLength(
	_ ctap2.PinUvAuthProtocolType, _ []byte, _ uint, _ []string, _ bool, _ bool,
) error {
	return errNotSupported
}
func (c *Client) Selection() error { return errNotSupported }
func (c *Client) Reset() error     { return errNotSupported }
