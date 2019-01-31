package certgen

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"time"
)

//We aim to build certs compatible with
// https://tools.ietf.org/html/rfc3779

type IpAdressFamily struct {
	AddressFamily []byte
	Addresses     []asn1.BitString
}

var oidIPAddressDelegation = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 7}
var ipV4FamilyEncoding = []byte{0, 1, 1}

//For now ipv4 only
func encodeIpAddressChoice(netBlock net.IPNet) (asn1.BitString, error) {
	ones, bits := netBlock.Mask.Size()
	if bits != 32 {
		return asn1.BitString{}, errors.New("not an ipv4 address")
	}
	//unusedLen = uint8(ones) % 8
	var output []byte
	len := ((ones + 7) / 8)
	//log.Printf("len=%d, ones=%d", len, ones)
	output = make([]byte, len, len)
	for i := 0; i < len; i++ {
		output[i] = netBlock.IP[12+i]
	}
	//log.Printf("%+v", output)
	bitString := asn1.BitString{
		Bytes:     output,
		BitLength: ones,
		//BitLength: len * 8, //Len is in bits, however it gets the lengt for the output?
	}

	return bitString, nil
}

func genDelegationExtension(ipv4Netblocks []net.IPNet) (*pkix.Extension, error) {
	ipv4AddressFamily := IpAdressFamily{
		AddressFamily: ipV4FamilyEncoding,
	}
	for _, netblock := range ipv4Netblocks {
		encodedNetBlock, err := encodeIpAddressChoice(netblock)
		if err != nil {
			return nil, err
		}
		ipv4AddressFamily.Addresses = append(ipv4AddressFamily.Addresses, encodedNetBlock)
	}
	addressFamilyList := []IpAdressFamily{ipv4AddressFamily}

	encodedAddressFamily, err := asn1.Marshal(addressFamilyList)
	if err != nil {
		return nil, err
	}
	ipDelegationExtension := pkix.Extension{
		Id:    oidIPAddressDelegation,
		Value: encodedAddressFamily,
	}
	return &ipDelegationExtension, nil
}

func decodeIPV4AddressChoice(encodedBlock asn1.BitString) (net.IPNet, error) {
	var encodedIP [4]byte
	for i := 0; (i * 8) < encodedBlock.BitLength; i++ {
		encodedIP[i] = encodedBlock.Bytes[i]
	}
	netBlock := net.IPNet{
		IP:   net.IPv4(encodedIP[0], encodedIP[1], encodedIP[2], encodedIP[3]),
		Mask: net.CIDRMask(encodedBlock.BitLength, 32),
	}
	return netBlock, nil
}

// returns an x509 cert that has the username in the common name,
// optionally if a kerberos Realm is present it will also add a kerberos
// SAN exention for pkinit
func GenIPRestrictedX509Cert(userName string, userPub interface{},
	caCert *x509.Certificate, caPriv crypto.Signer,
	ipv4Netblocks []net.IPNet, duration time.Duration,
	crlURL []string, OCPServer []string) ([]byte, error) {
	//// Now do the actual work...
	notBefore := time.Now()
	notAfter := notBefore.Add(duration)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	subject := pkix.Name{
		CommonName: userName,
	}

	ipDelegationExtension, err := genDelegationExtension(ipv4Netblocks)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IssuingCertificateURL: crlURL,
		OCSPServer:            OCPServer,
		BasicConstraintsValid: true,
		IsCA: false,
	}
	if ipDelegationExtension != nil {
		template.ExtraExtensions = append(template.ExtraExtensions,
			*ipDelegationExtension)
	}
	return x509.CreateCertificate(rand.Reader, &template, caCert, userPub, caPriv)
}

func VerifyIPRestrictedX509CertIP(userCert *x509.Certificate, remoteAddr string) (bool, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false, err
	}
	remoteIP := net.ParseIP(host)

	//log.Printf("+%v")
	var extension *pkix.Extension = nil
	for _, certExtension := range userCert.Extensions {
		if certExtension.Id.Equal(oidIPAddressDelegation) {
			extension = &certExtension
			break
		}
	}
	if extension == nil {
		return false, nil
	}
	//log.Printf("extension=%+v", *extension)
	var ipAddressFamilyList []IpAdressFamily
	_, err = asn1.Unmarshal(extension.Value, &ipAddressFamilyList)
	if err != nil {
		return false, err
	}
	//log.Printf("%+v", addressFamilyList)
	for _, addressList := range ipAddressFamilyList {
		if !bytes.Equal(addressList.AddressFamily, ipV4FamilyEncoding) {
			continue
		}
		for _, encodedNetblock := range addressList.Addresses {
			decoded, err := decodeIPV4AddressChoice(encodedNetblock)
			if err != nil {
				return false, err
			}
			if decoded.Contains(remoteIP) {
				return true, nil
			}
		}
	}
	return false, nil
}
