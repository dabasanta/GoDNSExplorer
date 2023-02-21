package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/likexian/whois"
	"github.com/miekg/dns"
)

func banner() {
	fmt.Println()
	fmt.Printf("\033[91m" +
		"        ▓█████▄  ███▄    █   ██████ ▓█████ ▒██   ██▒ ██▓███   ██▓     ▒█████   ██▀███  ▓█████  ██▀███  \n" +
		"        ▒██▀ ██▌ ██ ▀█   █ ▒██    ▒ ▓█   ▀ ▒▒ █ █ ▒░▓██░  ██▒▓██▒    ▒██▒  ██▒▓██ ▒ ██▒▓█   ▀ ▓██ ▒ ██▒\n" +
		"        ░██   █▌▓██  ▀█ ██▒░ ▓██▄   ▒███   ░░  █   ░▓██░ ██▓▒▒██░    ▒██░  ██▒▓██ ░▄█ ▒▒███   ▓██ ░▄█ ▒\n" +
		"        ░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒▒▓█  ▄  ░ █ █ ▒ ▒██▄█▓▒ ▒▒██░    ▒██   ██░▒██▀▀█▄  ▒▓█  ▄ ▒██▀▀█▄  \n" +
		"        ░▒████▓ ▒██░   ▓██░▒██████▒▒░▒████▒▒██▒ ▒██▒▒██▒ ░  ░░██████▒░ ████▓▒░░██▓ ▒██▒░▒████▒░██▓ ▒██▒\n" +
		"        ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░░ ▒░ ░▒▒ ░ ░▓ ░▒▓▒░ ░  ░░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░░ ▒░ ░░ ▒▓ ░▒▓░\n" +
		"        ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░ ░ ░  ░░░   ░▒ ░░▒ ░     ░ ░ ▒  ░  ░ ▒ ▒░   ░▒ ░ ▒░ ░ ░  ░  ░▒ ░ ▒░\n" +
		"        ░ ░  ░    ░   ░ ░ ░  ░  ░     ░    ░    ░  ░░         ░ ░   ░ ░ ░ ▒    ░░   ░    ░     ░░   ░ \n" +
		"        ░             ░       ░     ░  ░ ░    ░               ░  ░    ░ ░     ░        ░  ░   ░     \n" +
		"        ░ v:2.0     ░ By: Danilo Basanta {https://github.com/dabasanta/}\n" +
		"			[https://www.linkedin.com/in/danilobasanta/]\n")
	fmt.Println()
}

func help() {
	fmt.Println()
	fmt.Printf("\033[91m %s\n", " ▐██▌     ██░ ██ ▓█████  ██▓     ██▓███      ▐██▌ ")
	fmt.Printf("\033[91m %s\n", " ▐██▌    ▓██░ ██▒▓█   ▀ ▓██▒    ▓██░  ██▒    ▐██▌ ")
	fmt.Printf("\033[91m %s\n", " ▐██▌    ▒██▀▀██░▒███   ▒██░    ▓██░ ██▓▒    ▐██▌ ")
	fmt.Printf("\033[91m %s\n", " ▓██▒    ░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██▄█▓▒ ▒    ▓██▒ ")
	fmt.Printf("\033[91m %s\n", " ▒▄▄     ░▓█▒░██▓░▒████▒░██████▒▒██▒ ░  ░    ▒▄▄  ")
	fmt.Printf("\033[91m %s\n", " ░▀▀▒     ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░▒▓▒░ ░  ░    ░▀▀▒ ")
	fmt.Printf("\033[91m %s\n", " ░  ░     ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░▒ ░         ░  ░ ")
	fmt.Printf("\033[91m %s\n", "    ░     ░  ░░ ░   ░     ░ ░   ░░              ░ ")
	fmt.Printf("\033[91m %s\n", " ░        ░  ░  ░   ░  ░    ░  ░             ░    ")
	fmt.Printf("\033[91m %s\n", "                                                  ")
	fmt.Printf("\033[33m %s\n", "                                                  ")
	fmt.Printf("\033[33m %s\n", "Keep calm and use: ./DNSExplorer -d <domain name>\033[0m")
	os.Exit(1)
}

func transferZone(nameserver, domain string) bool {
	nameserver = strings.TrimRight(nameserver, ".")
	nameserver = nameserver + ":53"
	domainname := domain + "."
	transfer := new(dns.Transfer)
	msg := new(dns.Msg)
	msg.SetAxfr(domainname)
	records, err := transfer.In(msg, nameserver)
	if err == nil {
		for record := range records {
			fmt.Printf("\033[36m[¬]\033[0m Trying DNS zone transfer with %s server:\n%s", nameserver, record)
			fmt.Println()
		}
		fmt.Println()
		return true
	}
	return false
}

func whoisLookup(domain, whoisServer string) {

	keys := []string{
		"Domain Name",
		"Registrar WHOIS Server",
		"Registrar URL",
		"Updated Date",
		"Creation Date",
		"Registry Expiry Date",
		"Registrar",
		"Registrar IANA ID",
		"Registrar Abuse Contact Email",
		"Registrar Abuse Contact Phone",
		"Name Server",
		"DNSSEC",
	}

	// WHOIS Query
	result, err := whois.Whois(domain)
	if err == nil {
		fmt.Println("\n\n\033[36m[+]\033[0m \033[32mWHOIS info\n\033[0m")
		lines := strings.Split(result, "\n")
		info := make(map[string]string)

		for _, line := range lines {
			parts := strings.Split(line, ": ")
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				info[key] = value
			}
		}

		for _, key := range keys {
			value, ok := info[key]
			if ok {
				fmt.Printf("\033[36m[¬] %s: \033[37m%s\033[0m\n", key, value)
			}
		}
		fmt.Println()
	} else {
		fmt.Println("\033[31m[-]\033[0m Error querying information with the whois server")
	}
}

func initRecon(domainName string) {
	fmt.Println("\033[36m[+]\033[0m \033[32mBasic Recon\033[0m")
	// Print IPv6 address
	addr6, err := net.ResolveIPAddr("ip6", domainName)
	if err == nil {
		fmt.Println("\n\033[32m[~] IPv6 address:\033[0m\n", addr6.IP)
	}

	// Print IPv4 address
	addr4, err := net.LookupIP(domainName)
	if err != nil {
		panic(err)
	}
	for _, addr4 := range addr4 {
		if addr4.To4() != nil {
			fmt.Println("\n\033[32m[~] Direcciones IPv4:\033[0m")
			fmt.Println(addr4)
		}
	}

	// Print NS records
	nsRecords, err := net.LookupNS(domainName)
	if err == nil {
		fmt.Println("\n\033[32m[~] NS records for " + domainName + ":\033[0m")
		for _, ns := range nsRecords {
			fmt.Println(ns.Host)
			transferZone(ns.Host, domainName)
		}
	}

	// Print MX records
	mxRecords, err := net.LookupMX(domainName)
	if err == nil {
		// Sort by priority
		sort.Slice(mxRecords, func(i, j int) bool {
			return mxRecords[i].Pref < mxRecords[j].Pref
		})

		fmt.Printf("\n\033[32m[~] MX record for %s:\n", domainName+"\033[0m")
		for _, mx := range mxRecords {
			fmt.Printf("%s %d\n", mx.Host, mx.Pref)
			fmt.Println()
		}
	}

	// Print TXT records
	txtRecords, err := net.LookupTXT(domainName)
	if err == nil {
		fmt.Printf("\n\033[32m[~] TXT records for %s:\n", domainName+"\033[0m")
		for _, txt := range txtRecords {
			fmt.Println(txt)
		}
		fmt.Println()
	}

	// Print CNAME records
	cname, err := net.LookupCNAME(domainName)
	if err == nil {
		fmt.Printf("\n\033[32m[~] CNAME record for %s:\033[0m\n", domainName)
		fmt.Println(cname)
		fmt.Println()
	}

	// WHOIS info
	whoisLookup(domainName, "xx")
}

func main() {
	var domain string
	flag.StringVar(&domain, "d", "domain", "Target domain")
	flag.Usage = help
	flag.Parse()

	if domain == "domain" {
		help()
	} else {
		banner()
		initRecon(domain)
	}

}
