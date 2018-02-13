// Package acme provides a means of performing Let's Encrypt DNS challenges via a DNSConfig
package acme

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/miekg/dns/dnsutil"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/xenolf/lego/acme"
)

type Client interface {
	IssueOrRenewCert(name string, sans []string, renewUnder int) (bool, error)
}

type certManager struct {
	directory      string
	email          string
	acmeDirectory  string
	cfg            *models.DNSConfig
	checkedDomains map[string]bool

	account *account
	client  *acme.Client
}

func New(cfg *models.DNSConfig, directory string, email string) (Client, error) {
	return NewWithServer(cfg, directory, email, LetsEncryptStage)
}

const (
	LetsEncryptMain  = "https://acme-v01.api.letsencrypt.org/directory"
	LetsEncryptStage = "https://acme-staging.api.letsencrypt.org/directory"
)

func NewWithServer(cfg *models.DNSConfig, directory string, email string, server string) (Client, error) {
	c := &certManager{
		directory:      directory,
		email:          email,
		acmeDirectory:  server,
		cfg:            cfg,
		checkedDomains: map[string]bool{},
	}
	if err := c.loadOrCreateAccount(); err != nil {
		return nil, err
	}
	c.client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
	c.client.SetChallengeProvider(acme.DNS01, c)
	c.client.AgreeToTOS()
	return c, nil
}

// IssueOrRenewCert will obtain a certificate with the given name if it does not exist,
// or renew it if it is close enough to the expiration date.
// It will return true if it issued or updated the certificate.
func (c *certManager) IssueOrRenewCert(name string, sans []string, renewUnder int) (bool, error) {
	// to silence acme logging, uncomment this
	acme.Logger = log.New(ioutil.Discard, "", 0)

	log.Printf("Checking certificate [%s]", name)

	existing, err := c.readCertificate(name)
	if err != nil {
		return false, err
	}
	var action = func() (acme.CertificateResource, map[string]error) {
		return c.client.ObtainCertificate(sans, true, nil, true)
	}
	if existing != nil {
		names, daysLeft, err := readCert(existing.Certificate)
		if err != nil {
			return false, err
		}
		log.Printf("Found existing cert. %d days remaining.", daysLeft)
		namesOK := dnsNamesEqual(sans, names)
		if daysLeft >= renewUnder && namesOK {
			log.Println("Nothing to do")
			//nothing to do
			return false, nil
		}
		if !namesOK {
			log.Println("DNS Names don't match expected set. Reissuing.")
		} else {
			log.Println("Renewing cert")
			action = func() (acme.CertificateResource, map[string]error) {
				cr, err := c.client.RenewCertificate(*existing, true, true)
				m := map[string]error{}
				if err != nil {
					m[""] = err
				}
				return cr, m
			}
		}
	} else {
		log.Println("No existing cert found. Issuing new...")
	}

	certResource, failures := action()
	if len(failures) > 0 {
		fails := []string{}
		for _, f := range failures {
			fails = append(fails, f.Error())
		}
		return false, fmt.Errorf(strings.Join(fails, "\n"))
	}
	fmt.Println("GOT A CERT!!!")
	return true, c.writeCertificate(name, &certResource)
}

func (c *certManager) certFile(name, ext string) string {
	return filepath.Join(c.directory, name+"."+ext)
}

func (c *certManager) writeCertificate(name string, cr *acme.CertificateResource) error {
	jDAt, err := json.MarshalIndent(cr, "", "  ")
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(c.certFile(name, "json"), jDAt, perms); err != nil {
		return err
	}
	if err = ioutil.WriteFile(c.certFile(name, "crt"), cr.Certificate, perms); err != nil {
		return err
	}
	if err = ioutil.WriteFile(c.certFile(name, "key"), cr.PrivateKey, perms); err != nil {
		return err
	}
	return nil
}

func readCert(pemBytes []byte) (names []string, remaining int, err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, 0, fmt.Errorf("Invalid certificate pem data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, 0, err
	}
	return cert.DNSNames, 42, nil
}

func dnsNamesEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i, s := range a {
		if b[i] != s {
			return false
		}
	}
	return true
}

func (c *certManager) readCertificate(name string) (*acme.CertificateResource, error) {
	f, err := os.Open(c.certFile(name, "json"))
	if err != nil && os.IsNotExist(err) {
		// if json does not exist, nothing does
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	cr := &acme.CertificateResource{}
	if err = dec.Decode(cr); err != nil {
		return nil, err
	}
	// load cert
	crtBytes, err := ioutil.ReadFile(c.certFile(name, "crt"))
	if err != nil {
		return nil, err
	}
	cr.Certificate = crtBytes
	// load key
	keyBytes, err := ioutil.ReadFile(c.certFile(name, "key"))
	if err != nil {
		return nil, err
	}
	cr.PrivateKey = keyBytes
	return cr, nil
}

func (c *certManager) Present(domain, token, keyAuth string) error {
	d := c.cfg.DomainContainingFQDN(domain)
	// copy now so we can add txt record safely, and just run unmodified version later to cleanup
	d, err := d.Copy()
	if err != nil {
		return err
	}
	if err := c.ensureNoPendingCorrections(d); err != nil {
		return err
	}
	fqdn, val, _ := acme.DNS01Record(domain, keyAuth)
	fmt.Println(fqdn, val)
	txt := &models.RecordConfig{
		NameFQDN: strings.TrimSuffix(fqdn, "."),
		Name:     dnsutil.TrimDomainName(fqdn, d.Name),
		Type:     "TXT",
		Target:   val,
	}
	d.Records = append(d.Records, txt)
	getAndRunCorrections(d)
	return nil
}

func (c *certManager) ensureNoPendingCorrections(d *models.DomainConfig) error {
	// only need to check a domain once per app run
	if c.checkedDomains[d.Name] {
		return nil
	}
	corrections, err := getCorrections(d)
	if err != nil {
		return err
	}
	if len(corrections) != 0 {
		// TODO: maybe allow forcing through this check.
		for _, c := range corrections {
			fmt.Println(c.Msg)
		}
		return fmt.Errorf("Found %d pending corrections for %s. Not going to proceed issuing certificates", len(corrections), d.Name)
	}
	return nil
}

func getCorrections(d *models.DomainConfig) ([]*models.Correction, error) {
	cs := []*models.Correction{}
	for _, p := range d.DNSProviderInstances {
		if p.NumberOfNameservers == 0 {
			continue // only registered dns providers need fill challenge
		}
		dc, err := d.Copy()
		if err != nil {
			return nil, err
		}
		corrections, err := p.Driver.GetDomainCorrections(dc)
		if err != nil {
			return nil, err
		}
		cs = append(cs, corrections...)
	}
	return cs, nil
}

func getAndRunCorrections(d *models.DomainConfig) error {
	cs, err := getCorrections(d)
	for _, c := range cs {
		fmt.Printf("Running [%s]\n", c.Msg)
		err = c.F()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *certManager) CleanUp(domain, token, keyAuth string) error {
	d := c.cfg.DomainContainingFQDN(domain)
	return getAndRunCorrections(d)
}
