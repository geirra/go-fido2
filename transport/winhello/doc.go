// Package winhello provides a FIDO2 transport that delegates to the
// Windows Hello platform authenticator via Microsoft's webauthn.dll API
// (available on Windows 10 v1903 and later).
//
// Unlike the raw HID transport, this transport needs no elevated privileges
// and works with USB security keys, platform biometrics, and PIN - using the
// same OS dialog the browser uses.
//
// On non-Windows platforms the package exports stub symbols that always
// return errors so that callers can import the package unconditionally.
package winhello
