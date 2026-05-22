//go:build windows

package selfprotect

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certQueryObjectFile                  = 1
	certQueryContentFlagPKCS7SignedEmbed = 0x00000400
	certQueryFormatFlagBinary            = 0x00000002

	oidMicrosoftAntimalware = "1.3.6.1.4.1.311.61.4.1"
)

type authenticodeProbe struct {
	Signed         bool
	Subject        string
	AntimalwareEKU bool
}

var (
	crypt32                        = windows.NewLazySystemDLL("crypt32.dll")
	procCryptQueryObject           = crypt32.NewProc("CryptQueryObject")
	procCertFreeCertificateContext = crypt32.NewProc("CertFreeCertificateContext")
)

type rawCertContext struct {
	encodingType uint32
	pbEncoded    *byte
	cbEncoded    uint32
}

func probeAuthenticode(path string) authenticodeProbe {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return authenticodeProbe{}
	}
	var store, ctx uintptr
	r, _, _ := procCryptQueryObject.Call(
		uintptr(certQueryObjectFile),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(certQueryContentFlagPKCS7SignedEmbed),
		uintptr(certQueryFormatFlagBinary),
		uintptr(0),
		0, 0, 0,
		uintptr(unsafe.Pointer(&store)),
		uintptr(unsafe.Pointer(&ctx)),
		0,
	)
	if r == 0 || ctx == 0 {
		return authenticodeProbe{}
	}
	defer procCertFreeCertificateContext.Call(ctx)

	raw := (*rawCertContext)(unsafe.Pointer(ctx))
	if raw.pbEncoded == nil || raw.cbEncoded == 0 {
		return authenticodeProbe{Signed: true}
	}
	der := unsafe.Slice(raw.pbEncoded, raw.cbEncoded)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return authenticodeProbe{Signed: true}
	}
	return authenticodeProbe{
		Signed:         true,
		Subject:        cert.Subject.String(),
		AntimalwareEKU: certificateHasAntimalwareEKU(cert),
	}
}

func certificateHasAntimalwareEKU(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.String() == oidMicrosoftAntimalware {
			return true
		}
	}
	for _, ext := range cert.Extensions {
		if ext.Id.String() != "2.5.29.37" {
			continue
		}
		var eku pkix.Extension
		eku = ext
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(eku.Value, &oids); err == nil {
			for _, oid := range oids {
				if oid.String() == oidMicrosoftAntimalware {
					return true
				}
			}
		}
	}
	return false
}
