// Package acme provides a means of performing Let's Encrypt DNS challenges via a DNSConfig
package acme

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
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
	certResource, failures := c.client.ObtainCertificate(sans, true, nil, true)
	if len(failures) > 0 {
		return false, fmt.Errorf("FAILURES")
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

func (c *certManager) Present(domain, token, keyAuth string) error {
	fmt.Println("PRESENT!", domain)
	d := c.cfg.DomainContainingFQDN(domain)
	// copy now so we can add txt record safely
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
		return fmt.Errorf("Found %d pending corrections for %s. Not going to proceed issuing certificates", len(corrections), d.Name)
	}
	return nil
}

func getCorrections(d *models.DomainConfig) ([]*models.Correction, error) {
	cs := []*models.Correction{}
	for _, p := range d.DNSProviderInstances {
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
