package models

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
	"github.com/pkg/errors"
)

// RecordConfig stores a DNS record.
// Valid types:
//   Official:
//     A
//     AAAA
//     ANAME  // Technically not an official rtype yet.
//     CAA
//     CNAME
//     MX
//     NS
//     PTR
//     SRV
//     TLSA
//     TXT
//   Pseudo-Types:
//     ALIAS
//     CF_REDIRECT
//     CF_TEMP_REDIRECT
//     FRAME
//     IMPORT_TRANSFORM
//     NAMESERVER
//     NO_PURGE
//     PAGE_RULE
//     PURGE
//     URL
//     URL301
//
// Notes about the fields:
//
// Name:
//    This is the shortname i.e. the NameFQDN without the origin suffix.
//    It should never have a trailing "."
//    It should never be null. The apex (naked domain) is stored as "@".
//    If the origin is "foo.com." and Name is "foo.com", this literally means
//        the intended FQDN is "foo.com.foo.com." (which may look odd)
// NameFQDN:
//    This is the FQDN version of Name.
//    It should never have a trailiing ".".
//    NOTE: Eventually we will unexport Name/NameFQDN. Please start using
//      the setters (SetLabel/SetLabelFromFQDN) and getters (GetLabel/GetLabelFQDN).
//      as they will always work.
// Target:
//   This is the host or IP address of the record, with
//     the other related paramters (weight, priority, etc.) stored in individual
//     fields.
//   NOTE: Eventually we will unexport Target. Please start using the
//     setters (SetTarget*) and getters (GetTarget*) as they will always work.
//
// Idioms:
//  rec.Label() == "@"   // Is this record at the apex?
//
type RecordConfig struct {
	Type             string            `json:"type"` // All caps rtype name.
	name             string            // The short name. See above.
	nameFQDN         string            // Must end with ".$origin". See above.
	target           string            // If a name, must end with "."
	TTL              uint32            `json:"ttl,omitempty"`
	Metadata         map[string]string `json:"meta,omitempty"`
	MxPreference     uint16            `json:"mxpreference,omitempty"`
	SrvPriority      uint16            `json:"srvpriority,omitempty"`
	SrvWeight        uint16            `json:"srvweight,omitempty"`
	SrvPort          uint16            `json:"srvport,omitempty"`
	CaaTag           string            `json:"caatag,omitempty"`
	CaaFlag          uint8             `json:"caaflag,omitempty"`
	TlsaUsage        uint8             `json:"tlsausage,omitempty"`
	TlsaSelector     uint8             `json:"tlsaselector,omitempty"`
	TlsaMatchingType uint8             `json:"tlsamatchingtype,omitempty"`
	TxtStrings       []string          `json:"txtstrings,omitempty"` // TxtStrings stores all strings (including the first). Target stores only the first one.
	R53Alias         map[string]string `json:"r53_alias,omitempty"`

	Original interface{} `json:"-"` // Store pointer to provider-specific record object. Used in diffing.
}

// RecordConfigAlias is an alias of RecordConfig. We use an alias because aliases
// are stripped of any functions and we need a struct without
// MarshalJSON/UnmarshalJSON defined, otherwise we'd get a recursive defintion.
type RecordConfigAlias RecordConfig

// RecordConfigJSON represents out we represent RecordConfig to the JSON package.
type RecordConfigJSON struct {
	*RecordConfigAlias // All the exported fields.
	// The unexported fields all have equivalents here:
	Name   string `json:"name"`
	Target string `json:"target"`
}

// MarshalJSON marshals a RecordConfig. (struct to JSON)
func (rc *RecordConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(&RecordConfigJSON{
		RecordConfigAlias: (*RecordConfigAlias)(rc),
		// Unexported or custom-formatted fields are listed here:
		Name:   rc.name,
		Target: rc.target,
	})
}

// UnmarshalJSON unmarshals a RecordConfig. (JSON to struct)
func (rc *RecordConfig) UnmarshalJSON(data []byte) error {
	temp := &RecordConfigJSON{
		RecordConfigAlias: (*RecordConfigAlias)(rc),
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Copy the exported fields:
	*rc = (RecordConfig)(*(temp).RecordConfigAlias)
	// Each unexported field must be copied and/or converted individually:
	rc.name = temp.Name
	rc.target = temp.Target

	return nil
}

// Copy returns a deep copy of a RecordConfig.
func (rc *RecordConfig) Copy() (*RecordConfig, error) {
	newR := &RecordConfig{}
	err := copyObj(rc, newR)
	return newR, err
}

// SetLabel sets the .Name/.NameFQDN fields given a short name and origin.
// origin must not have a trailing dot: The entire code base
//   maintains dc.Name without the trailig dot. Finding a dot here means
//   something is very wrong.
// short must not have a training dot: That would mean you have
//   a FQDN, and shouldn't be using SetLabel().  Maybe SetLabelFromFQDN()?
func (rc *RecordConfig) SetLabel(short, origin string) {

	// Assertions that make sure the function is being used correctly:
	if strings.HasSuffix(origin, ".") {
		panic(errors.Errorf("origin (%s) is not supposed to end with a dot", origin))
	}
	if strings.HasSuffix(short, ".") {
		panic(errors.Errorf("short (%s) is not supposed to end with a dot", origin))
	}

	// TODO(tlim): We should add more validation here or in a separate validation
	// module.  We might want to check things like (\w+\.)+

	short = strings.ToLower(short)
	origin = strings.ToLower(origin)
	if short == "" || short == "@" {
		rc.name = "@"
		rc.nameFQDN = origin
	} else {
		rc.name = short
		rc.nameFQDN = dnsutil.AddOrigin(short, origin)
	}
}

// UnsafeSetLabelNull sets the label to "". Normally the FQDN is denoted by .Name being
// "@" however this can be used to violate that assertion. It should only be used
// on copies of a RecordConfig that is being used for non-standard things like
// Marshalling yaml.
func (rc *RecordConfig) UnsafeSetLabelNull() {
	rc.name = ""
}

// SetLabelFromFQDN sets the .Name/.NameFQDN fields given a FQDN and origin.
// fqdn may have a trailing "." but it is not required.
// origin may not have a trailing dot.
func (rc *RecordConfig) SetLabelFromFQDN(fqdn, origin string) {

	// Assertions that make sure the function is being used correctly:
	if strings.HasSuffix(origin, ".") {
		panic(errors.Errorf("origin (%s) is not supposed to end with a dot", origin))
	}
	if strings.HasSuffix(fqdn, "..") {
		panic(errors.Errorf("fqdn (%s) is not supposed to end with double dots", origin))
	}

	if strings.HasSuffix(fqdn, ".") {
		// Trim off a trailing dot.
		fqdn = fqdn[:len(fqdn)-1]
	}

	fqdn = strings.ToLower(fqdn)
	origin = strings.ToLower(origin)
	rc.name = dnsutil.TrimDomainName(fqdn, origin)
	rc.nameFQDN = fqdn
}

// GetLabel returns the shortname of the label associated with this RecordConfig.
// It will never end with "."
// It does not need further shortening (i.e. if it returns "foo.com" and the
//   domain is "foo.com" then the FQDN is actually "foo.com.foo.com").
// It will never be "" (the apex is returned as "@").
func (rc *RecordConfig) GetLabel() string {
	return rc.name
}

// GetLabelFQDN returns the FQDN of the label associated with this RecordConfig.
// It will not end with ".".
func (rc *RecordConfig) GetLabelFQDN() string {
	return rc.nameFQDN
}

// ToRR converts a RecordConfig to a dns.RR.
func (rc *RecordConfig) ToRR() dns.RR {

	// Don't call this on fake types.
	rdtype, ok := dns.StringToType[rc.Type]
	if !ok {
		log.Fatalf("No such DNS type as (%#v)\n", rc.Type)
	}

	// Magicallly create an RR of the correct type.
	rr := dns.TypeToRR[rdtype]()

	// Fill in the header.
	rr.Header().Name = rc.nameFQDN + "."
	rr.Header().Rrtype = rdtype
	rr.Header().Class = dns.ClassINET
	rr.Header().Ttl = rc.TTL
	if rc.TTL == 0 {
		rr.Header().Ttl = DefaultTTL
	}

	// Fill in the data.
	switch rdtype { // #rtype_variations
	case dns.TypeA:
		rr.(*dns.A).A = rc.GetTargetIP()
	case dns.TypeAAAA:
		rr.(*dns.AAAA).AAAA = rc.GetTargetIP()
	case dns.TypeCNAME:
		rr.(*dns.CNAME).Target = rc.GetTargetField()
	case dns.TypePTR:
		rr.(*dns.PTR).Ptr = rc.GetTargetField()
	case dns.TypeMX:
		rr.(*dns.MX).Preference = rc.MxPreference
		rr.(*dns.MX).Mx = rc.GetTargetField()
	case dns.TypeNS:
		fmt.Printf("DEBUG: ToRR NS: %v\n", rc.GetTargetField())
		rr.(*dns.NS).Ns = rc.GetTargetField()
	case dns.TypeSOA:
		t := strings.Replace(rc.GetTargetField(), `\ `, ` `, -1)
		parts := strings.Fields(t)
		rr.(*dns.SOA).Ns = parts[0]
		rr.(*dns.SOA).Mbox = parts[1]
		rr.(*dns.SOA).Serial = atou32(parts[2])
		rr.(*dns.SOA).Refresh = atou32(parts[3])
		rr.(*dns.SOA).Retry = atou32(parts[4])
		rr.(*dns.SOA).Expire = atou32(parts[5])
		rr.(*dns.SOA).Minttl = atou32(parts[6])
	case dns.TypeSRV:
		rr.(*dns.SRV).Priority = rc.SrvPriority
		rr.(*dns.SRV).Weight = rc.SrvWeight
		rr.(*dns.SRV).Port = rc.SrvPort
		rr.(*dns.SRV).Target = rc.GetTargetField()
	case dns.TypeCAA:
		rr.(*dns.CAA).Flag = rc.CaaFlag
		rr.(*dns.CAA).Tag = rc.CaaTag
		rr.(*dns.CAA).Value = rc.GetTargetField()
	case dns.TypeTLSA:
		rr.(*dns.TLSA).Usage = rc.TlsaUsage
		rr.(*dns.TLSA).MatchingType = rc.TlsaMatchingType
		rr.(*dns.TLSA).Selector = rc.TlsaSelector
		rr.(*dns.TLSA).Certificate = rc.GetTargetField()
	case dns.TypeTXT:
		rr.(*dns.TXT).Txt = rc.TxtStrings
	default:
		panic(fmt.Sprintf("ToRR: Unimplemented rtype %v", rc.Type))
		// We panic so that we quickly find any switch statements
		// that have not been updated for a new RR type.
	}

	return rr
}

// RecordKey represents a resource record in a format used by some systems.
type RecordKey struct {
	Name string
	Type string
}

// Key converts a RecordConfig into a RecordKey.
func (rc *RecordConfig) Key() RecordKey {
	return RecordKey{rc.GetLabel(), rc.Type}
}

// Records is a list of *RecordConfig.
type Records []*RecordConfig

// Grouped returns a map of keys to records.
func (r Records) Grouped() map[RecordKey]Records {
	groups := map[RecordKey]Records{}
	for _, rec := range r {
		groups[rec.Key()] = append(groups[rec.Key()], rec)
	}
	return groups
}

// GroupedByLabel returns a map of keys to records, and their original key order.
func (r Records) GroupedByLabel() ([]string, map[string]Records) {
	order := []string{}
	groups := map[string]Records{}
	for _, rec := range r {
		if _, found := groups[rec.GetLabel()]; !found {
			order = append(order, rec.GetLabel())
		}
		groups[rec.GetLabel()] = append(groups[rec.GetLabel()], rec)
	}
	return order, groups
}

// PostProcessRecords does any post-processing of the downloaded DNS records.
func PostProcessRecords(recs []*RecordConfig) {
	downcase(recs)
}

// Downcase converts all labels and targets to lowercase in a list of RecordConfig.
func downcase(recs []*RecordConfig) {
	for _, r := range recs {
		r.name = strings.ToLower(r.name)
		r.nameFQDN = strings.ToLower(r.nameFQDN)
		switch r.Type {
		case "ANAME", "CNAME", "MX", "NS", "PTR":
			r.target = strings.ToLower(r.target)
		case "A", "AAAA", "ALIAS", "CAA", "IMPORT_TRANSFORM", "SRV", "TLSA", "TXT", "SOA", "CF_REDIRECT", "CF_TEMP_REDIRECT":
			// Do nothing.
		default:
			// TODO: we'd like to panic here, but custom record types complicate things.
		}
	}
	return
}