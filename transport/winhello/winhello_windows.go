//go:build windows

package winhello

import (
	"errors"
	"fmt"
	"iter"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/ldclabs/cose/key"
	"github.com/geirra/go-fido2/protocol/ctap2"
	"github.com/geirra/go-fido2/protocol/webauthn"
)

// DevicePath is the virtual path used to identify the Windows Hello authenticator.
const DevicePath = "winhello://"

// Errors.
var (
	// ErrNotAvailable is returned when webauthn.dll is not found or is too old.
	ErrNotAvailable = errors.New("winhello: webauthn.dll not available (requires Windows 10 1903+)")
	// ErrWebAuthNFailed is returned when a webauthn.dll call returns a non-S_OK HRESULT.
	ErrWebAuthNFailed = errors.New("winhello: call failed")

	errNotSupported = errors.New("winhello: operation not supported by the Windows Hello transport")
)

// ---------------------------------------------------------------------------
// Win32 struct definitions mirroring webauthn.h on Windows x64.
//
// Each struct below is laid out with exactly the same fields and natural
// alignment as the corresponding C typedef, so that an unsafe.Pointer cast
// between the Go struct and the C struct is valid.
// ---------------------------------------------------------------------------

// _webauthnClientData mirrors WEBAUTHN_CLIENT_DATA.
//
//	cbSize(4) cbClientDataJSON(4) pbClientDataJSON(ptr) pwszHashAlgId(ptr)
//	Total: 24 bytes
type _webauthnClientData struct {
	cbSize           uint32  // offset  0
	cbClientDataJSON uint32  // offset  4
	pbClientDataJSON uintptr // offset  8  (Go inserts 0 pad – already 8-aligned)
	pwszHashAlgId    uintptr // offset 16
}

// _webauthnRPEntityInfo mirrors WEBAUTHN_RP_ENTITY_INFORMATION.
//
//	cbSize(4) [4pad] pwszId(ptr) pwszName(ptr) pwszIcon(ptr)
//	Total: 32 bytes
type _webauthnRPEntityInfo struct {
	cbSize   uint32  // offset  0
	pwszId   uintptr // offset  8  (Go inserts 4 pad at 4)
	pwszName uintptr // offset 16
	pwszIcon uintptr // offset 24
}

// _webauthnUserEntityInfo mirrors WEBAUTHN_USER_ENTITY_INFORMATION.
//
//	cbSize(4) cbId(4) pbId(ptr) pwszName(ptr) pwszIcon(ptr) pwszDisplayName(ptr)
//	Total: 40 bytes
type _webauthnUserEntityInfo struct {
	cbSize          uint32  // offset  0
	cbId            uint32  // offset  4
	pbId            uintptr // offset  8
	pwszName        uintptr // offset 16
	pwszIcon        uintptr // offset 24
	pwszDisplayName uintptr // offset 32
}

// _webauthnCoseCredParam mirrors WEBAUTHN_COSE_CREDENTIAL_PARAMETER.
//
//	cbSize(4) [4pad] pwszCredentialType(ptr) lAlg(4) [4pad]
//	Total: 24 bytes
type _webauthnCoseCredParam struct {
	cbSize             uint32  // offset  0
	pwszCredentialType uintptr // offset  8  (Go inserts 4 pad at 4)
	lAlg               int32   // offset 16
	// 4 bytes trailing pad → struct size = 24
}

// _webauthnCoseCredParams mirrors WEBAUTHN_COSE_CREDENTIAL_PARAMETERS.
//
//	cCredentialParameters(4) [4pad] pCredentialParameters(ptr)
//	Total: 16 bytes
type _webauthnCoseCredParams struct {
	cCredentialParameters uint32  // offset  0
	pCredentialParameters uintptr // offset  8  (Go inserts 4 pad at 4)
}

// _webauthnCredential mirrors WEBAUTHN_CREDENTIAL.
//
//	cbSize(4) cbId(4) pbId(ptr) pwszCredentialType(ptr)
//	Total: 24 bytes
type _webauthnCredential struct {
	cbSize             uint32  // offset  0
	cbId               uint32  // offset  4
	pbId               uintptr // offset  8
	pwszCredentialType uintptr // offset 16
}

// _webauthnMakeCredentialOptionsV1 mirrors
// WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS at version 1.
//
// v1 fields (cbSize = sizeof this struct = 64 bytes):
//
//	cbSize(4) dwTimeoutMilliseconds(4)
//	[inline WEBAUTHN_CREDENTIALS] cCredentials(4) [4pad] pCredentials(ptr)
//	[inline WEBAUTHN_EXTENSIONS]  cExtensions(4)  [4pad] pExtensions(ptr)
//	dwAuthenticatorAttachment(4) bRequireResidentKey(4)
//	dwUserVerificationRequirement(4) dwAttestationConveyancePreference(4) dwFlags(4)
//	[4 trailing pad]
//	Total: 64 bytes
type _webauthnMakeCredentialOptionsV1 struct {
	cbSize                           uint32  // offset  0
	dwTimeoutMilliseconds            uint32  // offset  4
	cCredentials                     uint32  // offset  8   (CredentialList.cCredentials)
	pCredentials                     uintptr // offset 16   (CredentialList.pCredentials; 4 pad at 12)
	cExtensions                      uint32  // offset 24   (Extensions.cExtensions)
	pExtensions                      uintptr // offset 32   (Extensions.pExtensions; 4 pad at 28)
	dwAuthenticatorAttachment        uint32  // offset 40
	bRequireResidentKey              int32   // offset 44
	dwUserVerificationRequirement    uint32  // offset 48
	dwAttestationConveyancePreference uint32 // offset 52
	dwFlags                          uint32  // offset 56
	// 4 bytes trailing pad → struct size = 64
}

// _webauthnGetAssertionOptionsV1 mirrors
// WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS at version 1.
//
// v1 fields (cbSize = sizeof this struct = 56 bytes):
//
//	cbSize(4) dwTimeoutMilliseconds(4)
//	[inline WEBAUTHN_CREDENTIALS] cCredentials(4) [4pad] pCredentials(ptr)
//	[inline WEBAUTHN_EXTENSIONS]  cExtensions(4)  [4pad] pExtensions(ptr)
//	dwAuthenticatorAttachment(4) dwUserVerificationRequirement(4) dwFlags(4)
//	[4 trailing pad]
//	Total: 56 bytes
type _webauthnGetAssertionOptionsV1 struct {
	cbSize                        uint32  // offset  0
	dwTimeoutMilliseconds         uint32  // offset  4
	cCredentials                  uint32  // offset  8   (CredentialList.cCredentials)
	pCredentials                  uintptr // offset 16   (CredentialList.pCredentials; 4 pad at 12)
	cExtensions                   uint32  // offset 24   (Extensions.cExtensions)
	pExtensions                   uintptr // offset 32   (Extensions.pExtensions; 4 pad at 28)
	dwAuthenticatorAttachment     uint32  // offset 40
	dwUserVerificationRequirement uint32  // offset 44
	dwFlags                       uint32  // offset 48
	// 4 bytes trailing pad → struct size = 56
}

// _webauthnAssertion mirrors WEBAUTHN_ASSERTION (output from GetAssertion).
//
// Fields through v2 (Extensions):
//
//	cbSize(4) cbAuthenticatorData(4) pbAuthenticatorData(ptr)
//	cbSignature(4) [4pad] pbSignature(ptr)
//	[inline WEBAUTHN_CREDENTIAL] credCbSize(4) credCbId(4) credPbId(ptr) credPwszType(ptr)
//	cbUserId(4) [4pad] pbUserId(ptr)
//	[v2 inline WEBAUTHN_EXTENSIONS] cExtensions(4) [4pad] pExtensions(ptr)
type _webauthnAssertion struct {
	cbSize              uint32  // offset  0
	cbAuthenticatorData uint32  // offset  4
	pbAuthenticatorData uintptr // offset  8
	cbSignature         uint32  // offset 16
	pbSignature         uintptr // offset 24   (4 pad at 20)
	// WEBAUTHN_CREDENTIAL inline:
	credCbSize  uint32  // offset 32
	credCbId    uint32  // offset 36
	credPbId    uintptr // offset 40   (no pad needed: 40 is 8-aligned)
	credPwszType uintptr // offset 48
	// user info:
	cbUserId uint32  // offset 56
	pbUserId uintptr // offset 64   (4 pad at 60)
	// WEBAUTHN_EXTENSIONS inline (v2+):
	cExtensions uint32  // offset 72
	pExtensions uintptr // offset 80   (4 pad at 76)
}

// _webauthnCredentialAttestation mirrors WEBAUTHN_CREDENTIAL_ATTESTATION
// (output from MakeCredential) for the fields present since version 1.
type _webauthnCredentialAttestation struct {
	cbSize                  uint32  // offset  0
	pwszFormatType          uintptr // offset  8   (4 pad at 4)
	cbAuthenticatorData     uint32  // offset 16
	pbAuthenticatorData     uintptr // offset 24   (4 pad at 20)
	cbAttestation           uint32  // offset 32
	pbAttestation           uintptr // offset 40   (4 pad at 36)
	dwAttestationDecodeType uint32  // offset 48
	pvAttestationDecode     uintptr // offset 56   (4 pad at 52)
	cbAttestationObject     uint32  // offset 64
	pbAttestationObject     uintptr // offset 72   (4 pad at 68)
	cbCredentialId          uint32  // offset 80
	pbCredentialId          uintptr // offset 88   (4 pad at 84)
}

// ---------------------------------------------------------------------------
// webauthn.dll user-verification-requirement constants
// ---------------------------------------------------------------------------

const (
	_webauthnUVAny         uint32 = 0
	_webauthnUVRequired    uint32 = 1
	_webauthnUVPreferred   uint32 = 2
	_webauthnUVDiscouraged uint32 = 3

	_webauthnAttestationNone uint32 = 3

	_webauthnAPIVersionMin uint32 = 1
)

// ---------------------------------------------------------------------------
// Lazy-loaded DLL procs
// ---------------------------------------------------------------------------

var (
	_webauthnDLL = syscall.NewLazyDLL("webauthn.dll")

	_procGetApiVersion     = _webauthnDLL.NewProc("WebAuthNGetApiVersionNumber")
	_procIsPlatformAvail   = _webauthnDLL.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	_procMakeCredential    = _webauthnDLL.NewProc("WebAuthNAuthenticatorMakeCredential")
	_procGetAssertion      = _webauthnDLL.NewProc("WebAuthNAuthenticatorGetAssertion")
	_procFreeAttestation   = _webauthnDLL.NewProc("WebAuthNFreeCredentialAttestation")
	_procFreeAssertion     = _webauthnDLL.NewProc("WebAuthNFreeAssertion")
	_procGetErrorName      = _webauthnDLL.NewProc("WebAuthNGetErrorName")
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// IsAvailable returns true when webauthn.dll is present and has a sufficient
// API version (Windows 10 v1903 or later).
func IsAvailable() bool {
	if err := _webauthnDLL.Load(); err != nil {
		return false
	}
	ver, _, _ := _procGetApiVersion.Call()
	return uint32(ver) >= _webauthnAPIVersionMin
}

// Client implements ctap2.Client by delegating to the Windows Hello
// platform authenticator via webauthn.dll.  PIN / UV are handled
// transparently by the OS; callers do not pass a pinUvAuthToken.
type Client struct {
	hwnd uintptr // parent HWND; 0 = top-level dialog
	info *ctap2.AuthenticatorGetInfoResponse
}

// NewClient creates a new Windows Hello Client.
// hwnd is the parent window handle; pass 0 to create a top-level dialog.
func NewClient(hwnd uintptr) (*Client, error) {
	if !IsAvailable() {
		return nil, ErrNotAvailable
	}
	c := &Client{hwnd: hwnd}
	c.info = c.buildInfo()
	return c, nil
}

// Close is a no-op; there is no persistent connection to close.
func (c *Client) Close() error { return nil }

// GetInfo returns synthetic CTAP2 authenticator info for Windows Hello.
func (c *Client) GetInfo() (*ctap2.AuthenticatorGetInfoResponse, error) {
	return c.info, nil
}

// buildInfo constructs a synthetic AuthenticatorGetInfoResponse that
// matches the capabilities of the Windows Hello platform authenticator.
func (c *Client) buildInfo() *ctap2.AuthenticatorGetInfoResponse {
	// Well-known AAGUID for the Windows Hello software authenticator.
	aaguid, _ := uuid.Parse("6028b017-b1d4-4c02-b4b3-afcdafc96bb2")
	return &ctap2.AuthenticatorGetInfoResponse{
		Versions: []ctap2.Version{ctap2.Fido2_0, ctap2.Fido2_1},
		AAGUID:   aaguid,
		Options: map[ctap2.Option]bool{
			ctap2.OptionPlatformDevice:              true,
			ctap2.OptionResidentKeys:                true,
			ctap2.OptionUserPresence:                true,
			ctap2.OptionUserVerification:            true,
			ctap2.OptionMakeCredentialUvNotRequired: true, // UV handled by platform
		},
		// Provide a dummy protocol so device.go's PinUvAuthProtocols[0] access
		// does not panic when called without a pinUvAuthToken.
		PinUvAuthProtocols: []ctap2.PinUvAuthProtocolType{ctap2.PinUvAuthProtocolTypeTwo},
		Transports:         []string{"internal"},
	}
}

// ---------------------------------------------------------------------------
// MakeCredential
// ---------------------------------------------------------------------------

// MakeCredential calls WebAuthNAuthenticatorMakeCredential and returns the
// attestation object parsed into an AuthenticatorMakeCredentialResponse.
// The pinUvAuthProtocolType and pinUvAuthToken parameters are ignored;
// Windows Hello manages PIN / UV internally.
func (c *Client) MakeCredential(
	_ ctap2.PinUvAuthProtocolType,
	_ []byte,
	clientData []byte,
	rp webauthn.PublicKeyCredentialRpEntity,
	user webauthn.PublicKeyCredentialUserEntity,
	pubKeyCredParams []webauthn.PublicKeyCredentialParameters,
	excludeList []webauthn.PublicKeyCredentialDescriptor,
	_ *ctap2.CreateExtensionInputs,
	options map[ctap2.Option]bool,
	_ uint,
	_ []webauthn.AttestationStatementFormatIdentifier,
) (*ctap2.AuthenticatorMakeCredentialResponse, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// --- WEBAUTHN_CLIENT_DATA ---
	hashAlgW, err := syscall.UTF16PtrFromString("SHA-256")
	if err != nil {
		return nil, err
	}
	pinner.Pin(hashAlgW)

	cd := _webauthnClientData{
		cbSize:           uint32(unsafe.Sizeof(_webauthnClientData{})),
		cbClientDataJSON: uint32(len(clientData)),
		pbClientDataJSON: uintptr(unsafe.Pointer(&clientData[0])),
		pwszHashAlgId:    uintptr(unsafe.Pointer(hashAlgW)),
	}

	// --- WEBAUTHN_RP_ENTITY_INFORMATION ---
	rpIdW, err := syscall.UTF16PtrFromString(rp.ID)
	if err != nil {
		return nil, err
	}
	rpNameW, err := syscall.UTF16PtrFromString(rp.Name)
	if err != nil {
		return nil, err
	}
	pinner.Pin(rpIdW)
	pinner.Pin(rpNameW)

	rpInfo := _webauthnRPEntityInfo{
		cbSize:   uint32(unsafe.Sizeof(_webauthnRPEntityInfo{})),
		pwszId:   uintptr(unsafe.Pointer(rpIdW)),
		pwszName: uintptr(unsafe.Pointer(rpNameW)),
	}

	// --- WEBAUTHN_USER_ENTITY_INFORMATION ---
	if len(user.ID) == 0 {
		return nil, fmt.Errorf("winhello: user.ID must not be empty")
	}
	userNameW, err := syscall.UTF16PtrFromString(user.Name)
	if err != nil {
		return nil, err
	}
	userDisplayNameW, err := syscall.UTF16PtrFromString(user.DisplayName)
	if err != nil {
		return nil, err
	}
	pinner.Pin(userNameW)
	pinner.Pin(userDisplayNameW)
	pinner.Pin(&user.ID[0])

	userInfo := _webauthnUserEntityInfo{
		cbSize:          uint32(unsafe.Sizeof(_webauthnUserEntityInfo{})),
		cbId:            uint32(len(user.ID)),
		pbId:            uintptr(unsafe.Pointer(&user.ID[0])),
		pwszName:        uintptr(unsafe.Pointer(userNameW)),
		pwszDisplayName: uintptr(unsafe.Pointer(userDisplayNameW)),
	}

	// --- WEBAUTHN_COSE_CREDENTIAL_PARAMETERS ---
	credTypeW, err := syscall.UTF16PtrFromString("public-key")
	if err != nil {
		return nil, err
	}
	pinner.Pin(credTypeW)

	credParams := make([]_webauthnCoseCredParam, len(pubKeyCredParams))
	for i, p := range pubKeyCredParams {
		credParams[i] = _webauthnCoseCredParam{
			cbSize:             uint32(unsafe.Sizeof(_webauthnCoseCredParam{})),
			pwszCredentialType: uintptr(unsafe.Pointer(credTypeW)),
			lAlg:               int32(p.Algorithm),
		}
	}
	pinner.Pin(&credParams[0])

	pubKeyParams := _webauthnCoseCredParams{
		cCredentialParameters: uint32(len(credParams)),
		pCredentialParameters: uintptr(unsafe.Pointer(&credParams[0])),
	}

	// --- Exclude list (v1 WEBAUTHN_CREDENTIALS) ---
	excludeArr := makeCredentialArray(excludeList, credTypeW, &pinner)
	var pExclude uintptr
	if len(excludeArr) > 0 {
		pExclude = uintptr(unsafe.Pointer(&excludeArr[0]))
	}

	// --- WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS (v1) ---
	opts := _webauthnMakeCredentialOptionsV1{
		cbSize:                            uint32(unsafe.Sizeof(_webauthnMakeCredentialOptionsV1{})),
		dwTimeoutMilliseconds:             60_000,
		cCredentials:                      uint32(len(excludeArr)),
		pCredentials:                      pExclude,
		dwUserVerificationRequirement:     uvRequirement(options),
		dwAttestationConveyancePreference: _webauthnAttestationNone,
	}
	if options[ctap2.OptionResidentKeys] {
		opts.bRequireResidentKey = 1
	}

	// --- Call WebAuthNAuthenticatorMakeCredential ---
	var pAttestation uintptr
	hr, _, _ := _procMakeCredential.Call(
		c.hwnd,
		uintptr(unsafe.Pointer(&rpInfo)),
		uintptr(unsafe.Pointer(&userInfo)),
		uintptr(unsafe.Pointer(&pubKeyParams)),
		uintptr(unsafe.Pointer(&cd)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&pAttestation)),
	)
	if hr != 0 {
		return nil, fmt.Errorf("%w: %s (hr=0x%08x)", ErrWebAuthNFailed, errorName(hr), uint32(hr))
	}
	defer _procFreeAttestation.Call(pAttestation)

	// --- Parse WEBAUTHN_CREDENTIAL_ATTESTATION output ---
	att := (*_webauthnCredentialAttestation)(unsafe.Pointer(pAttestation))

	// The attestation object is a CBOR map with WebAuthn text keys.
	attObjBytes := unsafeBytes(att.pbAttestationObject, att.cbAttestationObject)

	var waObj struct {
		Fmt      string         `cbor:"fmt"`
		AuthData []byte         `cbor:"authData"`
		AttStmt  map[string]any `cbor:"attStmt"`
	}
	if err := cbor.Unmarshal(attObjBytes, &waObj); err != nil {
		return nil, fmt.Errorf("winhello: failed to parse attestation object: %w", err)
	}

	authDataParsed, err := ctap2.ParseMakeCredentialAuthData(waObj.AuthData)
	if err != nil {
		return nil, fmt.Errorf("winhello: failed to parse auth data: %w", err)
	}

	resp := &ctap2.AuthenticatorMakeCredentialResponse{
		Format:               webauthn.AttestationStatementFormatIdentifier(waObj.Fmt),
		AuthDataRaw:          waObj.AuthData,
		AuthData:             authDataParsed,
		AttestationStatement: waObj.AttStmt,
		ExtensionOutputs:     new(webauthn.CreateAuthenticationExtensionsClientOutputs),
	}
	return resp, nil
}

// ---------------------------------------------------------------------------
// GetAssertion
// ---------------------------------------------------------------------------

// GetAssertion calls WebAuthNAuthenticatorGetAssertion.
// The pinUvAuthProtocolType and pinUvAuthToken parameters are ignored;
// Windows Hello manages PIN / UV internally.
//
// Windows Hello returns exactly one assertion per call.  The iterator
// always yields at most one item.
func (c *Client) GetAssertion(
	_ ctap2.PinUvAuthProtocolType,
	_ []byte,
	rpID string,
	clientData []byte,
	allowList []webauthn.PublicKeyCredentialDescriptor,
	_ *ctap2.GetExtensionInputs,
	options map[ctap2.Option]bool,
) iter.Seq2[*ctap2.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(*ctap2.AuthenticatorGetAssertionResponse, error) bool) {
		resp, err := c.getAssertion(rpID, clientData, allowList, options)
		yield(resp, err)
	}
}

func (c *Client) getAssertion(
	rpID string,
	clientData []byte,
	allowList []webauthn.PublicKeyCredentialDescriptor,
	options map[ctap2.Option]bool,
) (*ctap2.AuthenticatorGetAssertionResponse, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	// --- WEBAUTHN_CLIENT_DATA ---
	hashAlgW, err := syscall.UTF16PtrFromString("SHA-256")
	if err != nil {
		return nil, err
	}
	pinner.Pin(hashAlgW)
	pinner.Pin(&clientData[0])

	cd := _webauthnClientData{
		cbSize:           uint32(unsafe.Sizeof(_webauthnClientData{})),
		cbClientDataJSON: uint32(len(clientData)),
		pbClientDataJSON: uintptr(unsafe.Pointer(&clientData[0])),
		pwszHashAlgId:    uintptr(unsafe.Pointer(hashAlgW)),
	}

	// --- Allow list (v1 WEBAUTHN_CREDENTIALS) ---
	credTypeW, err := syscall.UTF16PtrFromString("public-key")
	if err != nil {
		return nil, err
	}
	pinner.Pin(credTypeW)

	allowArr := makeCredentialArray(allowList, credTypeW, &pinner)
	var pAllow uintptr
	if len(allowArr) > 0 {
		pinner.Pin(&allowArr[0])
		pAllow = uintptr(unsafe.Pointer(&allowArr[0]))
	}

	// --- RP ID as UTF-16 ---
	rpIDW, err := syscall.UTF16PtrFromString(rpID)
	if err != nil {
		return nil, err
	}
	pinner.Pin(rpIDW)

	// --- WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS (v1) ---
	opts := _webauthnGetAssertionOptionsV1{
		cbSize:                        uint32(unsafe.Sizeof(_webauthnGetAssertionOptionsV1{})),
		dwTimeoutMilliseconds:         60_000,
		cCredentials:                  uint32(len(allowArr)),
		pCredentials:                  pAllow,
		dwUserVerificationRequirement: uvRequirement(options),
	}

	// --- Call WebAuthNAuthenticatorGetAssertion ---
	var pAssertion uintptr
	hr, _, _ := _procGetAssertion.Call(
		c.hwnd,
		uintptr(unsafe.Pointer(rpIDW)),
		uintptr(unsafe.Pointer(&cd)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&pAssertion)),
	)
	if hr != 0 {
		return nil, fmt.Errorf("%w: %s (hr=0x%08x)", ErrWebAuthNFailed, errorName(hr), uint32(hr))
	}
	defer _procFreeAssertion.Call(pAssertion)

	// --- Parse WEBAUTHN_ASSERTION output ---
	a := (*_webauthnAssertion)(unsafe.Pointer(pAssertion))

	authDataRaw := copyBytes(a.pbAuthenticatorData, a.cbAuthenticatorData)
	sig := copyBytes(a.pbSignature, a.cbSignature)
	credID := copyBytes(a.credPbId, a.credCbId)

	authData, err := ctap2.ParseGetAssertionAuthData(authDataRaw)
	if err != nil {
		return nil, fmt.Errorf("winhello: failed to parse auth data: %w", err)
	}

	resp := &ctap2.AuthenticatorGetAssertionResponse{
		Credential: webauthn.PublicKeyCredentialDescriptor{
			Type: webauthn.PublicKeyCredentialTypePublicKey,
			ID:   credID,
		},
		AuthDataRaw:      authDataRaw,
		AuthData:         authData,
		Signature:        sig,
		ExtensionOutputs: new(webauthn.GetAuthenticationExtensionsClientOutputs),
	}

	if a.cbUserId > 0 {
		resp.User = &webauthn.PublicKeyCredentialUserEntity{
			ID: copyBytes(a.pbUserId, a.cbUserId),
		}
	}

	return resp, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeCredentialArray converts a slice of WebAuthn credential descriptors to
// an array of _webauthnCredential structs, pinning all ID byte slices.
func makeCredentialArray(
	creds []webauthn.PublicKeyCredentialDescriptor,
	credTypeW *uint16,
	pinner *runtime.Pinner,
) []_webauthnCredential {
	if len(creds) == 0 {
		return nil
	}
	arr := make([]_webauthnCredential, len(creds))
	for i, cred := range creds {
		if len(cred.ID) == 0 {
			continue
		}
		pinner.Pin(&cred.ID[0])
		arr[i] = _webauthnCredential{
			cbSize:             uint32(unsafe.Sizeof(_webauthnCredential{})),
			cbId:               uint32(len(cred.ID)),
			pbId:               uintptr(unsafe.Pointer(&cred.ID[0])),
			pwszCredentialType: uintptr(unsafe.Pointer(credTypeW)),
		}
	}
	return arr
}

// uvRequirement maps CTAP2 option flags to a webauthn.dll UV requirement constant.
func uvRequirement(options map[ctap2.Option]bool) uint32 {
	if uv, ok := options[ctap2.OptionUserVerification]; ok {
		if uv {
			return _webauthnUVRequired
		}
		return _webauthnUVDiscouraged
	}
	return _webauthnUVPreferred
}

// errorName asks webauthn.dll for a human-readable name for an HRESULT.
func errorName(hr uintptr) string {
	p, _, _ := _procGetErrorName.Call(hr)
	if p == 0 {
		return "unknown error"
	}
	return syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(p)), 256))
}

// copyBytes copies length bytes from an OS-owned buffer into a fresh Go slice.
func copyBytes(ptr uintptr, length uint32) []byte {
	if ptr == 0 || length == 0 {
		return nil
	}
	dst := make([]byte, length)
	copy(dst, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length))
	return dst
}

// unsafeBytes returns a Go slice backed by an OS-owned buffer.
// The slice MUST NOT be used after the OS buffer is freed.
func unsafeBytes(ptr uintptr, length uint32) []byte {
	if ptr == 0 || length == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length)
}

// ---------------------------------------------------------------------------
// Unsupported ctap2.Client methods
// Windows Hello handles PIN / UV / bio internally; these operations have no
// equivalent in the webauthn.dll API.
// ---------------------------------------------------------------------------

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
