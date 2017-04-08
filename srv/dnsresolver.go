package srv

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// DefaultResolvConfPath is a default resolv.conf file path that is used if
// NewDNSResolverFromResolvFile() resolvConfFilePath is set to an empty string
const DefaultResolvConfPath = "/etc/resolv.conf"

// NewDNSResolver is a resolver that uses github.com/miekg/dns dns client
// with a given DNS server list
func NewDNSResolver(defaultTTL uint32, dnsServers []string) Resolver {
	client := &dns.Client{}
	return &dnsResolver{
		client:     client,
		dnsServers: dnsServers,
		defaultTTL: defaultTTL,
	}
}

// NewDNSResolverFromResolvFile is a resolver that uses github.com/miekg/dns dns client
// and a provided resolv.conf file path ("" defaults to /etc/resolv.conf) to retrieve
// available DNS servers
func NewDNSResolverFromResolvFile(defaultTTL uint32, resolvConfFilePath string) (Resolver, error) {
	if resolvConfFilePath == "" {
		resolvConfFilePath = DefaultResolvConfPath
	}
	cfg, err := dns.ClientConfigFromFile(resolvConfFilePath)
	if err != nil {
		return nil, err
	}

	servers := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		servers = append(servers, fmt.Sprintf("%s:%s", s, cfg.Port))
	}

	client := &dns.Client{}
	return &dnsResolver{
		client:     client,
		dnsServers: servers,
		defaultTTL: defaultTTL,
	}, nil
}

type dnsResolver struct {
	client     *dns.Client
	dnsServers []string
	defaultTTL uint32
}

func (r *dnsResolver) Lookup(name string) ([]*Target, error) {
	var (
		tgs []*Target
		err error
	)
	for _, rs := range r.dnsServers {
		tgs, err = r.resolve(rs, name)
		if err != nil {
			continue
		}

		if len(tgs) > 0 {
			break
		}
	}

	// got error during resolve (so return the last one)
	if err != nil {
		return nil, err
	}

	// no entries found
	if len(tgs) == 0 {
		return nil, errors.New("failed resolving hostnames for SRV entries")
	}

	return tgs, nil
}

func (r *dnsResolver) resolve(server string, name string) ([]*Target, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(name), dns.TypeSRV)

	resp, _, err := r.client.Exchange(msg, server)
	if err != nil {
		return nil, err
	}

	if len(resp.Answer) == 0 {
		return nil, nil
	}

	// for fqdn to IP mapping
	nim := make(map[string]net.IP)
	for _, ra := range resp.Extra {
		if a, ok := ra.(*dns.A); ok {
			nim[a.Hdr.Name] = a.A
		}
	}

	ttgs := make([]*Target, 0, len(resp.Answer))
	for _, ra := range resp.Answer {
		if srv, ok := ra.(*dns.SRV); ok {
			t := Target{}
			// try using IP address instead of hostname
			if ip, ok := nim[srv.Target]; ok {
				t.DialAddr = fmt.Sprintf("%v:%v", ip.String(), srv.Port)
			} else {
				t.DialAddr = fmt.Sprintf("%v:%v", srv.Target, srv.Port)
			}

			// we do want ttl do be > 0 for the LB updates
			if srv.Hdr.Ttl == 0 {
				t.Ttl = time.Duration(r.defaultTTL) * time.Second
			} else {
				t.Ttl = time.Duration(srv.Hdr.Ttl) * time.Second
			}

			ttgs = append(ttgs, &t)
		}
	}

	return ttgs, err
}
