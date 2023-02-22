package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
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

type CrtShResult struct {
	CommonName string `json:"common_name"`
}

func crtsh(domainName string) {

	subdomainfile := domainName + "-subdomains.txt"
	webserversfile := domainName + "-webserver.txt"

	subdomainsFile, err := os.Create(subdomainfile)
	if err != nil {
		fmt.Println("\033[31m[-]\033[0m Error creating file ", subdomainfile)
		os.Exit(1)
	}
	defer subdomainsFile.Close()

	swebsrvsFile, err := os.Create(webserversfile)
	if err != nil {
		fmt.Println("\033[31m[-]\033[0m Error creating file ", webserversfile)
		os.Exit(1)
	}
	defer swebsrvsFile.Close()

	subdomainsSlice := []string{}

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domainName)

	resp, err := http.Get(url)
	if err == nil {
		defer resp.Body.Close()

		var results []CrtShResult
		err = json.NewDecoder(resp.Body).Decode(&results)
		if err == nil {
			fmt.Println("\n\033[36m[+]\033[0m \033[32mCRTSH Recon\n\033[0m")
			for _, result := range results {
				fmt.Println(result.CommonName)
				uriSubdomain := strings.Replace(result.CommonName, "*.", "", -1)
				subdomainsSlice = append(subdomainsSlice, uriSubdomain)
			}
			count := len(results)
			fmt.Printf("\n\033[36m[¬] Total: \033[37m%d\033[0m\n\n", count)
			httpDiscover(subdomainsSlice, subdomainsFile, swebsrvsFile)
		} else {
			fmt.Println("\033[31m[-]\033[0m Error decoding domain information on crt.sh")
		}

	} else {
		fmt.Println("\033[31m[-]\033[0m Error querying domain information on crt.sh")
	}
}

// Create another slice of existing webservers and save them in a file at the end of the function execution
// Implement threading in the httpDiscover function call
// Use sort to sort the list of subdomains before passing it to the httpDiscover function
// Keep only unique records in the slices to avoid duplicates

func httpDiscover(subdomains []string, subdomainsFile, swebsrvsFile *os.File) {

	for _, subdomain := range subdomains {
		URI := fmt.Sprintf("https://%s/", subdomain)
		_, err := subdomainsFile.WriteString(subdomain + "\n")
		if err != nil {
			fmt.Println("\033[31m[-]\033[0m Error writing to file " + subdomainsFile.Name())
			return
		}

		resp, err := http.Get(URI)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 100 && resp.StatusCode <= 500 {
				fmt.Printf("\033[36m[¬] Webserver found on\033[32m %s\033[36m with response code\033[0m %d\033[0m\n\n", URI, resp.StatusCode)
				_, err = swebsrvsFile.WriteString(URI + "\n")
				if err != nil {
					fmt.Println("\033[31m[-]\033[0m Error writing to file " + swebsrvsFile.Name())
					return
				}
			} else {
				fmt.Println("error en la linea 129: ", err)
			}
		} else {
			fmt.Println("error en la linea 132", err)
		}
	}
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
		}
		fmt.Println()
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
		crtsh(domain)
	}

}
