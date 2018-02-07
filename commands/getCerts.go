package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/StackExchange/dnscontrol/pkg/normalize"
	"github.com/urfave/cli"
)

var _ = cmd(catUtils, func() *cli.Command {
	var args GetCertsArgs
	return &cli.Command{
		Name:  "get-certs",
		Usage: "Issue certificates via let's encrypt",
		Action: func(c *cli.Context) error {
			return exit(GetCerts(args))
		},
		Flags: args.flags(),
	}
}())

type GetCertsArgs struct {
	GetDNSConfigArgs
	GetCredentialsArgs

	ACMEServer     string
	CertsFile      string
	RenewUnderDays int
	CertDirectory  string
	Email          string
	AgreeTOS       bool

	UpdateHook string
}

func (args *GetCertsArgs) flags() []cli.Flag {
	flags := args.GetDNSConfigArgs.flags()
	flags = append(flags, args.GetCredentialsArgs.flags()...)

	flags = append(flags, cli.StringFlag{
		Name:        "acme",
		Destination: &args.ACMEServer,
		Value:       "staging",
		Usage:       `ACME server to issue against. Give full directory endpoint. Can also use 'staging' or 'live' for standard Let's Encrpyt endpoints.`,
	})
	flags = append(flags, cli.IntFlag{
		Name:        "renew",
		Destination: &args.RenewUnderDays,
		Value:       15,
		Usage:       `Renew certs with less than this many days remaining`,
	})
	flags = append(flags, cli.StringFlag{
		Name:        "dir",
		Destination: &args.CertDirectory,
		Value:       "certs",
		Usage:       `Directory to store certificates and other data`,
	})
	flags = append(flags, cli.StringFlag{
		Name:        "certConfig",
		Destination: &args.CertsFile,
		Value:       "certs.json",
		Usage:       `Json file containing list of certificates to issue`,
	})
	flags = append(flags, cli.StringFlag{
		Name:        "email",
		Destination: &args.Email,
		Value:       "",
		Usage:       `Email to register with let's encrypt`,
	})
	flags = append(flags, cli.BoolFlag{
		Name:        "agreeTOS",
		Destination: &args.AgreeTOS,
		Usage:       `Must provide this to agree to Let's Encrypt terms of service`,
	})
	flags = append(flags, cli.StringFlag{
		Name:        "hook",
		Destination: &args.UpdateHook,
		Value:       "hook",
		Usage:       `Command to execute after a certificate is issued or renewed. Name of cert will be given as first argument`,
	})

	return flags
}

func GetCerts(args GetCertsArgs) error {
	// check agree flag
	if !args.AgreeTOS {
		return fmt.Errorf("You must agree to the Let's Encrypt Terms of Service by using -agreeTOS")
	}
	// load dns config
	cfg, err := GetDNSConfig(args.GetDNSConfigArgs)
	if err != nil {
		return err
	}
	errs := normalize.NormalizeAndValidateConfig(cfg)
	if PrintValidationErrors(errs) {
		return fmt.Errorf("Exiting due to validation errors")
	}
	_, err = InitializeProviders(args.CredsFile, cfg, false)
	if err != nil {
		return err
	}
	// load cert list
	certList := map[string][]string{}
	f, err := os.Open(args.CertsFile)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	err = dec.Decode(certList)
	if err != nil {
		return err
	}
	// make sure we have valid LE account
	// issue challenges
	// fill them
	return nil
}
