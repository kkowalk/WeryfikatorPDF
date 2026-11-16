package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidRSAPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

const (
	oidMessageDigest = "1.2.840.113549.1.9.4"
	oidSigningTime   = "1.2.840.113549.1.9.5"
	oidSigningCertV1 = "1.2.840.113549.1.9.16.2.12"
	oidSigningCertV2 = "1.2.840.113549.1.9.16.2.47"
	oidSigTimestamp  = "1.2.840.113549.1.9.16.2.14"
	oidAdbeRevInfo   = "1.2.840.113583.1.1.8"
)

var hashByOID = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	"2.16.840.1.101.3.4.2.4": crypto.SHA224,
}

// RFC 5652 structures. Implicit [n] fields are RawValues: .Bytes holds the content.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContent     encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue // SET OF
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	SerialNumber *big.Int
	GenTime      time.Time `asn1:"generalized"`
	// trailing optional fields ignored (encoding/asn1 allows extra elements)
}

type cmsSig struct {
	si       signerInfo
	certs    []*x509.Certificate
	signer   *x509.Certificate
	eType    asn1.ObjectIdentifier
	eContent []byte
	signed   map[string]asn1.RawValue
	unsigned map[string]asn1.RawValue
	crlsRaw  []byte
}

// ponytail: DER only; BER-encoded (indefinite length) CMS is rejected with a clear error.
func parseCMS(der []byte) (*cmsSig, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("nieprawidłowa struktura CMS (obsługiwane jest kodowanie DER): %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errors.New("zawartość nie jest CMS SignedData")
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("nieprawidłowa struktura SignedData: %w", err)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("oczekiwano jednego SignerInfo, jest %d", len(sd.SignerInfos))
	}
	c := &cmsSig{si: sd.SignerInfos[0], eType: sd.EncapContent.EContentType, crlsRaw: sd.CRLs.FullBytes}
	for rest := sd.Certificates.Bytes; len(rest) > 0; {
		var v asn1.RawValue
		r, err := asn1.Unmarshal(rest, &v)
		if err != nil {
			break
		}
		rest = r
		if cert, err := x509.ParseCertificate(v.FullBytes); err == nil {
			c.certs = append(c.certs, cert)
		}
	}
	if b := sd.EncapContent.EContent.Bytes; len(b) > 0 {
		if _, err := asn1.Unmarshal(b, &c.eContent); err != nil {
			return nil, fmt.Errorf("nieprawidłowa zawartość eContent: %w", err)
		}
	}
	c.signed = parseAttrs(c.si.SignedAttrs.Bytes)
	c.unsigned = parseAttrs(c.si.UnsignedAttrs.Bytes)
	if c.signer = findSigner(c.si.SID, c.certs); c.signer == nil {
		return nil, errors.New("certyfikat podpisującego nie jest dołączony do podpisu")
	}
	return c, nil
}

func parseAttrs(b []byte) map[string]asn1.RawValue {
	m := map[string]asn1.RawValue{}
	for len(b) > 0 {
		var a attribute
		r, err := asn1.Unmarshal(b, &a)
		if err != nil {
			break
		}
		b = r
		m[a.Type.String()] = a.Values
	}
	return m
}

// firstValue returns the DER of the first element of an attribute's SET.
func firstValue(set asn1.RawValue) []byte {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(set.Bytes, &v); err != nil {
		return nil
	}
	return v.FullBytes
}

func findSigner(sid asn1.RawValue, certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs {
		if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
			if bytes.Equal(sid.Bytes, c.SubjectKeyId) {
				return c
			}
			continue
		}
		var ias struct {
			Issuer asn1.RawValue
			Serial *big.Int
		}
		if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err == nil &&
			bytes.Equal(ias.Issuer.FullBytes, c.RawIssuer) && ias.Serial.Cmp(c.SerialNumber) == 0 {
			return c
		}
	}
	return nil
}

func digest(h crypto.Hash, parts ...[]byte) []byte {
	w := h.New()
	for _, p := range parts {
		w.Write(p)
	}
	return w.Sum(nil)
}

// verify checks messageDigest against content (concatenated parts) and the signature over signed attributes.
func (c *cmsSig) verify(content ...[]byte) error {
	h, ok := hashByOID[c.si.DigestAlgorithm.Algorithm.String()]
	if !ok {
		return fmt.Errorf("nieobsługiwany algorytm skrótu %s", c.si.DigestAlgorithm.Algorithm)
	}
	d := digest(h, content...)
	pss := c.si.SignatureAlgorithm.Algorithm.Equal(oidRSAPSS)
	if len(c.si.SignedAttrs.FullBytes) == 0 {
		return verifyPub(c.signer.PublicKey, h, pss, d, c.si.Signature)
	}
	var md []byte
	if _, err := asn1.Unmarshal(firstValue(c.signed[oidMessageDigest]), &md); err != nil || !bytes.Equal(md, d) {
		return errors.New("skrót podpisanych danych (messageDigest) nie zgadza się z treścią — dane zmienione po podpisaniu")
	}
	sa := bytes.Clone(c.si.SignedAttrs.FullBytes)
	sa[0] = 0x31 // signature is computed over the attributes encoded as SET OF
	if err := verifyPub(c.signer.PublicKey, h, pss, digest(h, sa), c.si.Signature); err != nil {
		return fmt.Errorf("weryfikacja kryptograficzna podpisu nie powiodła się: %w", err)
	}
	return nil
}

func verifyPub(pub any, h crypto.Hash, pss bool, d, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if pss {
			return rsa.VerifyPSS(k, h, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
		}
		return rsa.VerifyPKCS1v15(k, h, d, sig)
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, d, sig) {
			return nil
		}
		return errors.New("nieprawidłowy podpis ECDSA")
	}
	return fmt.Errorf("nieobsługiwany typ klucza %T", pub)
}

var x509Hash = map[x509.SignatureAlgorithm]crypto.Hash{
	x509.SHA1WithRSA: crypto.SHA1, x509.ECDSAWithSHA1: crypto.SHA1,
	x509.SHA256WithRSA: crypto.SHA256, x509.ECDSAWithSHA256: crypto.SHA256, x509.SHA256WithRSAPSS: crypto.SHA256,
	x509.SHA384WithRSA: crypto.SHA384, x509.ECDSAWithSHA384: crypto.SHA384, x509.SHA384WithRSAPSS: crypto.SHA384,
	x509.SHA512WithRSA: crypto.SHA512, x509.ECDSAWithSHA512: crypto.SHA512, x509.SHA512WithRSAPSS: crypto.SHA512,
}

// checkSigned verifies a certificate/CRL signature by parent. Unlike
// CheckSignatureFrom it accepts SHA-1, which historical (pre-2016) chains need.
func checkSigned(parent *x509.Certificate, alg x509.SignatureAlgorithm, tbs, sig []byte) error {
	h, ok := x509Hash[alg]
	if !ok {
		return fmt.Errorf("nieobsługiwany algorytm %v", alg)
	}
	pss := alg == x509.SHA256WithRSAPSS || alg == x509.SHA384WithRSAPSS || alg == x509.SHA512WithRSAPSS
	return verifyPub(parent.PublicKey, h, pss, digest(h, tbs), sig)
}

// checkESS verifies the signing-certificate(-v2) binding. present=false if the attribute is missing.
func (c *cmsSig) checkESS() (present bool, err error) {
	if v, ok := c.signed[oidSigningCertV2]; ok {
		var sc struct {
			Certs []struct {
				Alg  pkix.AlgorithmIdentifier `asn1:"optional"`
				Hash []byte
			}
		}
		if _, err := asn1.Unmarshal(firstValue(v), &sc); err != nil || len(sc.Certs) == 0 {
			return true, errors.New("nieprawidłowy atrybut signing-certificate-v2")
		}
		h := crypto.SHA256 // DEFAULT per RFC 5035
		if len(sc.Certs[0].Alg.Algorithm) > 0 {
			if h, ok = hashByOID[sc.Certs[0].Alg.Algorithm.String()]; !ok {
				return true, errors.New("nieobsługiwany algorytm w signing-certificate-v2")
			}
		}
		if !bytes.Equal(digest(h, c.signer.Raw), sc.Certs[0].Hash) {
			return true, errors.New("skrót certyfikatu w atrybucie signing-certificate-v2 nie zgadza się z certyfikatem podpisującego")
		}
		return true, nil
	}
	if v, ok := c.signed[oidSigningCertV1]; ok {
		var sc struct{ Certs []struct{ Hash []byte } }
		if _, err := asn1.Unmarshal(firstValue(v), &sc); err != nil || len(sc.Certs) == 0 {
			return true, errors.New("nieprawidłowy atrybut signing-certificate")
		}
		if !bytes.Equal(digest(crypto.SHA1, c.signer.Raw), sc.Certs[0].Hash) {
			return true, errors.New("skrót certyfikatu w atrybucie signing-certificate nie zgadza się z certyfikatem podpisującego")
		}
		return true, nil
	}
	return false, nil
}

func (c *cmsSig) signingTime() (time.Time, bool) {
	var t time.Time
	if v, ok := c.signed[oidSigningTime]; ok {
		if _, err := asn1.Unmarshal(firstValue(v), &t); err == nil {
			return t, true
		}
	}
	return t, false
}

type tsResult struct {
	GenTime time.Time
	TSA     *x509.Certificate
	Certs   []*x509.Certificate
	Err     error
}

// parseTimestamp validates an RFC 3161 token over data (signature value or document byte range).
func parseTimestamp(token []byte, data ...[]byte) *tsResult {
	c, err := parseCMS(token)
	if err != nil {
		return &tsResult{Err: err}
	}
	r := &tsResult{TSA: c.signer, Certs: c.certs}
	if !c.eType.Equal(oidTSTInfo) {
		r.Err = errors.New("token nie zawiera TSTInfo")
		return r
	}
	var ti tstInfo
	if _, err := asn1.Unmarshal(c.eContent, &ti); err != nil {
		r.Err = fmt.Errorf("nieprawidłowy TSTInfo: %w", err)
		return r
	}
	r.GenTime = ti.GenTime
	if err := c.verify(c.eContent); err != nil {
		r.Err = fmt.Errorf("podpis znacznika czasu: %w", err)
		return r
	}
	h, ok := hashByOID[ti.MessageImprint.HashAlgorithm.Algorithm.String()]
	if !ok || !bytes.Equal(digest(h, data...), ti.MessageImprint.HashedMessage) {
		r.Err = errors.New("znacznik czasu nie dotyczy tych danych (messageImprint niezgodny)")
	}
	return r
}
