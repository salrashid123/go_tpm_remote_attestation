package certparser

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"oid"
	"regexp"

	"golang.org/x/crypto/cryptobyte"
)

var (
	versionRE         = regexp.MustCompile("^id:[0-9a-fA-F]{8}$")
	infineonVersionRE = regexp.MustCompile("^id:[0-9a-fA-F]{4}$")
	nuvotonVersionRE  = regexp.MustCompile("^id:[0-9a-fA-F]{2}$")
)

type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type tpmSpecification struct {
	Family   string
	Level    int
	Revision int
}

type GCEInstanceID struct {
	Zone          string
	ProjectNumber int
	ProjectID     string
	InstanceID    int
	InstanceName  string
}

type EKCertificate struct {
	*x509.Certificate
	tpmManufacturer, tpmModel, tpmVersion string
	tpmSpecification                      tpmSpecification
	gceInstanceID                         GCEInstanceID
}

// Fingerprint returns a unique representation of an EK certificate.
func (e EKCertificate) Fingerprint() string {
	b := sha256.Sum256(e.Raw)
	return hex.EncodeToString(b[:])
}

// Manufacturer returns the TPM manufacturer.
func (e EKCertificate) Manufacturer() string {
	return e.tpmManufacturer
}

// Model returns the TPM model.
func (e EKCertificate) Model() string {
	return e.tpmModel
}

// Version returns the TPM firmware version.
func (e EKCertificate) Version() string {
	return e.tpmVersion
}

// SpecificationFamily returns the TPM specification family.
func (e EKCertificate) SpecificationFamily() string {
	return e.tpmSpecification.Family
}

// SpecificationLevel returns the TPM specification level.
func (e EKCertificate) SpecificationLevel() int {
	return e.tpmSpecification.Level
}

// SpecificationRevision returns the TPM specification revision.
func (e EKCertificate) SpecificationRevision() int {
	return e.tpmSpecification.Revision
}

// GCEInstanceID ...
func (e EKCertificate) GCEInstanceID() GCEInstanceID {
	return e.gceInstanceID
}

// ToPEM returns the EK certificate PEM encoded.
func (e EKCertificate) ToPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CERTIFICATE", Bytes: e.Raw}))
}

func parseSubjectAltName(ext pkix.Extension) (dirName pkix.RDNSequence, otherName cryptobyte.String, err error) {
	err = forEachSAN(ext.Value, func(tag int, data []byte) error {
		switch tag {
		case 0:
			otherName = cryptobyte.String(data)
		case 4:
			if _, err := asn1.Unmarshal(data, &dirName); err != nil {
				return err
			}
		default:
			return fmt.Errorf("expected tag %d", tag)
		}
		return nil
	})
	return
}

// Borrowed from the x509 package.
func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.Bytes); err != nil {
			return err
		}
	}

	return nil
}

func parseName(name pkix.RDNSequence) (string, string, string, error) {
	var tpmManufacturer, tpmModel, tpmVersion string
	var err error
	for _, rdn := range name {
		for _, attr := range rdn {
			if attr.Type.Equal(oid.TPMManufacturer) {
				tpmManufacturer = fmt.Sprintf("%v", attr.Value)
				continue
			}
			if attr.Type.Equal(oid.TPMModel) {
				tpmModel = fmt.Sprintf("%v", attr.Value)
				continue
			}
			if attr.Type.Equal(oid.TPMVersion) {
				if tpmVersion, err = versionFix(fmt.Sprintf("%v", attr.Value)); err != nil {
					return tpmManufacturer, tpmModel, tpmVersion, err
				}
				continue
			}
			return tpmManufacturer, tpmModel, tpmVersion, fmt.Errorf("unknown attribute type: %v", attr.Type)
		}
	}
	return tpmManufacturer, tpmModel, tpmVersion, nil
}

func versionFix(tpmVersion string) (string, error) {
	if infineonVersionRE.MatchString(tpmVersion) {
		major, err := hex.DecodeString(tpmVersion[3:5])
		if err != nil {
			return "", err
		}
		minor, err := hex.DecodeString(tpmVersion[5:7])
		if err != nil {
			return "", err
		}
		tpmVersion = fmt.Sprintf("id:%04X%04X", major, minor)
	}
	if nuvotonVersionRE.MatchString(tpmVersion) {
		major, err := hex.DecodeString(tpmVersion[3:5])
		if err != nil {
			return "", err
		}
		tpmVersion = fmt.Sprintf("id:%04X0000", major)
	}
	return tpmVersion, nil
}

func parseGCEInstanceID(ext pkix.Extension) (out GCEInstanceID, err error) {
	_, err = asn1.Unmarshal(ext.Value, &out)
	return
}

func parseTPMSpecification(SubjectDirectoryAttributes []attributeTypeAndValue) (tpmSpecification, error) {
	for _, attr := range SubjectDirectoryAttributes {
		if attr.Type.Equal(oid.TPMSpecification) {
			var spec tpmSpecification
			rest, err := asn1.Unmarshal(attr.Value.Bytes, &spec)
			if err != nil {
				return tpmSpecification{}, err
			}
			if len(rest) != 0 {
				return tpmSpecification{}, errors.New("trailing data after TPMSpecification")
			}
			return spec, nil
		}
	}
	return tpmSpecification{}, errors.New("TPMSpecification not present")
}

func parseSubjectDirectoryAttributes(ext pkix.Extension) ([]attributeTypeAndValue, error) {
	var attrs []attributeTypeAndValue
	rest, err := asn1.Unmarshal(ext.Value, &attrs)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after X.509 extension")
	}
	return attrs, nil
}
func ParseEKCertificate(asn1Data []byte) (*EKCertificate, error) {
	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return nil, err
	}
	return NewEKCertificate(cert)
}

func NewEKCertificate(cert *x509.Certificate) (*EKCertificate, error) {
	var spec tpmSpecification
	var tpmManufacturer, tpmModel, tpmVersion string
	var gceInstanceID GCEInstanceID
	var err error
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid.SubjectAltName) {
			directoryName, _, err := parseSubjectAltName(ext)
			if err != nil {
				return nil, err
			}
			tpmManufacturer, tpmModel, tpmVersion, err = parseName(directoryName)
			if err != nil {
				return nil, err
			}
		}
		if ext.Id.Equal(oid.SubjectDirectoryAttributes) {
			subjectDirectoryAttributes, err := parseSubjectDirectoryAttributes(ext)
			if err != nil {
				return nil, err
			}
			if spec, err = parseTPMSpecification(subjectDirectoryAttributes); err != nil {
				return nil, err
			}
		}
		if ext.Id.Equal(oid.CloudComputeInstanceIdentifier) {
			if gceInstanceID, err = parseGCEInstanceID(ext); err != nil {
				return nil, err
			}
		}
	}
	if !versionRE.MatchString(tpmVersion) {
		return nil, fmt.Errorf("invalid TPM version %q", tpmVersion)
	}
	return &EKCertificate{cert, tpmManufacturer, tpmModel, tpmVersion, spec, gceInstanceID}, nil
}
