package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gammazero/workerpool"
	"github.com/projectdiscovery/goflags"
)

var urls []string
var options *Options
var extensions = []string{".rar", ".zip", ".tar.gz", ".tar", ".gz", ".jar", ".7z", ".bz2", ".sql", ".backup", ".war", ".bak", ".tmp", ".db", ".old"}

var mime_types = []string{
	"application/octet-stream",
	"application/x-bzip",
	"application/x-bzip2",
	"application/gzip",
	"application/java-archive",
	"application/vnd.rar",
	"application/x-sh",
	"application/x-tar",
	"application/zip",
	"application/x-7z-compressed",
}

func main() {
	banner()
	options = ParseOptions()

	if options.file != "" {
		readFromFile()
	} else {
		fi, _ := os.Stdin.Stat()
		if fi.Mode()&os.ModeNamedPipe == 0 {
			fmt.Println("[!] No data found in pipe. urls must given using pipe or f parameter!")
			os.Exit(1)
		} else {
			readFromStdin()
		}
	}

	if options.extension != "" {
		extensions = strings.Split(options.extension, ",")
	}

	timeInfo("starting")
	defer timeInfo("ending")

	wp := workerpool.New(options.worker)

	for _, url := range urls {
		url := url
		wp.Submit(func() {
			start(url)
		})
	}
	wp.StopWait()
}

func start(domain string) {
	var rgx = regexp.MustCompile(options.exclude)
	if len(domain) < options.domain_length+8 {
		if !rgx.MatchString(domain) {
			getAllCombination(domain, options.method)
		}
	}
}

func getAllCombination(domain string, m string) {
	generate_wordlist := []string{}

	if options.method == "all" {
		m = "regular,withoutdots,withoutvowels,reverse,mixed,withoutdv,shuffle"
	}

	method := strings.Split(m, ",")
	for _, method := range method {
		switch method {
		case "regular":
			regularDomain(domain, &generate_wordlist)
		case "withoutdots":
			withoutDots(domain, &generate_wordlist)
		case "withoutvowels":
			withoutVowels(domain, &generate_wordlist)
		case "reverse":
			reverseDomain(domain, &generate_wordlist)
		case "mixed":
			mixedSubdomain(domain, &generate_wordlist)
		case "withoutdv":
			withoutVowelsAndDots(domain, &generate_wordlist)
		case "shuffle":
			shuffle(domain, &generate_wordlist)
		default:
			shuffle(domain, &generate_wordlist)
		}
	}

	headRequest(domain, generate_wordlist)

}

func timeInfo(t string) {
	ctime := fmt.Sprintf("[*] Scan "+t+" time: %s", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println(string("\033[36m") + ctime + string("\033[0m"))
}

func regularDomain(domain string, wordlist *[]string) {
	generatePossibilities(domain, wordlist)
}

func withoutDots(domain string, wordlist *[]string) {
	without_dot := strings.ReplaceAll(domain, ".", "")
	generatePossibilities(without_dot, wordlist)
}

func withoutVowels(domain string, wordlist *[]string) {
	clear_vowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "")
	domain_without_vowel := clear_vowel.Replace(domain)
	generatePossibilities(domain_without_vowel, wordlist)
}

func withoutVowelsAndDots(domain string, wordlist *[]string) {
	clear_vowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "", ".", "")
	without_vowel_dot := clear_vowel.Replace(domain)
	generatePossibilities(without_vowel_dot, wordlist)
}

func mixedSubdomain(domain string, wordlist *[]string) {
	clear_domain := strings.Split(domain, "://")[1]
	split := strings.Split(clear_domain, ".")

	for sindex := range split {
		for eindex := range split {
			generatePossibilities("http://"+split[sindex]+"."+split[eindex], wordlist)
		}
	}
}

func reverseDomain(domain string, wordlist *[]string) {
	clear_domain := strings.Split(domain, "://")[1]
	split := strings.Split(clear_domain, ".")
	split_reverse := reverseSlice(split)
	reverse_domain := "http://" + strings.Join(split_reverse, ".")
	generatePossibilities(reverse_domain, wordlist)
	withoutDots(reverse_domain, wordlist)
	withoutVowels(reverse_domain, wordlist)
	withoutVowelsAndDots(reverse_domain, wordlist)
}

func shuffle(domain string, wordlist *[]string) {
	clear_domain := strings.Split(domain, "://")[1]
	split := strings.Split(clear_domain, ".")
	split_reverse := reverseSlice(split)
	reverse_domain := "http://" + strings.Join(split_reverse, ".")
	shuffleSubdomain(domain, wordlist)
	shuffleSubdomain(reverse_domain, wordlist)
}

func shuffleSubdomain(domain string, wordlist *[]string) {
	clear_domain := strings.Split(domain, "://")[1]
	splt := strings.Split(clear_domain, ".")
	for id1, _ := range splt {
		for id2, _ := range splt[id1:] {
			p := strings.Join(splt[id1:id1+id2+1], ".")
			addShuffleSubdomain(p, wordlist)
			if id2 >= 2 {
				p = splt[id1] + "." + splt[id1+id2]
				addShuffleSubdomain(p, wordlist)
			}
		}
	}
}

func addShuffleSubdomain(domain string, wordlist *[]string) {
	if !contains(*wordlist, domain) {
		*wordlist = append(*wordlist, domain)
	}

	clear_vowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "")
	domain_without_vowel := clear_vowel.Replace(domain)
	if !contains(*wordlist, domain_without_vowel) {
		*wordlist = append(*wordlist, domain_without_vowel)
	}

	without_dot := strings.ReplaceAll(domain, ".", "")
	if !contains(*wordlist, without_dot) {
		*wordlist = append(*wordlist, without_dot)
	}

	clear_voweldot := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "", ".", "")
	without_vowel_dot := clear_voweldot.Replace(domain)
	if !contains(*wordlist, without_vowel_dot) {
		*wordlist = append(*wordlist, without_vowel_dot)
	}
}

func contains(slice []string, elements string) bool {
	for _, s := range slice {
		if elements == s {
			return true
		}
	}
	return false
}

func reverseSlice(slice []string) []string {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
}

func generatePossibilities(domain string, possibilities *[]string) {
	just_domain := strings.Split(domain, "://")[1]
	for first, _ := range just_domain {
		for last, _ := range just_domain[first:] {
			p := just_domain[first : first+last+1]
			if !contains(*possibilities, p) {
				*possibilities = append(*possibilities, p)
			}
		}
	}
}

func readFromStdin() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
}

func readFromFile() {
	file, err := os.Open(options.file)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
}

func requestBuilder(url string) *http.Request {
	req, _ := http.NewRequest("HEAD", url, nil)
	req.Header.Add("User-Agent", options.user_agent)
	return req

}

func httpClient(proxy string) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     time.Second,
		DisableKeepAlives:   true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 10,
			KeepAlive: time.Second,
		}).DialContext,
	}

	if proxy != "" {
		if p, err := url.Parse(options.proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}

	return &http.Client{
		Transport: tr,
		Timeout:   time.Second * 10,
	}

}

func headRequest(domain string, wordlist []string) {
	for _, w := range wordlist {
		for _, e := range extensions {
			url := domain + "/" + options.prefix + w + options.suffix + e

			if options.print {
				fmt.Println("[-]", url)
			}

			client := httpClient(options.proxy)
			resp, err := client.Do(requestBuilder(url))

			if err, ok := err.(net.Error); ok && err.Timeout() {
				fmt.Println(string("\033[33m")+"[!] Timeout. Skipping :: "+url, string("\033[0m"))
				continue
			} else if err != nil {
				fmt.Println(string("\033[31m")+"[!] Something went wrong. Exiting :: "+url, string("\033[0m"))
				os.Exit(1)
			}

			if _, ok := resp.Header["Content-Length"]; ok {
				content_length, _ := strconv.Atoi(resp.Header["Content-Length"][0])
				if _, ok := resp.Header["Content-Type"]; ok {
					content_type := resp.Header["Content-Type"][0]
					is_found := contains(mime_types, content_type)
					if content_length > options.min_content_length && is_found && resp.StatusCode == options.status_code {
						info := fmt.Sprintf("[+] Possible sensitive file was found. URL: [%s] CT: [%s] CL: [%d] SC: [%d]", url, content_type, content_length, resp.StatusCode)
						fmt.Println(string("\033[32m")+info, string("\033[0m"))
					}
				}
			}
		}
	}
}

type Options struct {
	content_type       string
	extension          string
	exclude            string
	replace            string
	method             string
	prefix             string
	suffix             string
	remove             string
	output             string
	file               string
	proxy              string
	user_agent         string
	worker             int
	timeout            int
	status_code        int
	domain_length      int
	min_content_length int
	version            bool
	verbose            bool
	print              bool
	help               bool
}

func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`fuzzuli is a fuzzing tool that aims to find critical backup files by creating a dynamic wordlist based on the domain.`)

	createGroup(flagSet, "General Options", "GENERAL OPTIONS",
		flagSet.IntVar(&options.worker, "w", 16, "worker count"),
		flagSet.StringVar(&options.file, "f", "", "input file containing list of host/domain"),
		flagSet.BoolVar(&options.print, "p", false, "print urls that sent request"),
		flagSet.BoolVar(&options.version, "v", false, "print version"),
		flagSet.BoolVar(&options.help, "help", false, "print this"),
	)

	createGroup(flagSet, "wordlist options", "WORDLIST OPTIONS",
		flagSet.StringVar(&options.method, "mt", "", "methods. avaible methods: regular, withoutdots, withoutvowels, reverse, mixed, withoutdv, shuffle"),
		flagSet.StringVar(&options.suffix, "sf", "", "suffix"),
		flagSet.StringVar(&options.prefix, "pf", "", "prefix"),
		flagSet.StringVar(&options.extension, "ex", "", "file extension. default (rar, zip, tar.gz, tar, gz, jar, 7z, bz2, sql, backup, war)"),
		flagSet.StringVar(&options.replace, "rp", "", "replace specified char"),
		flagSet.StringVar(&options.remove, "rm", "", "remove specified char"),
	)

	createGroup(flagSet, "domain options", "DOMAIN OPTIONS",
		flagSet.StringVar(&options.exclude, "es", "#", "exclude domain that contains specified string or char. e.g. for OR operand google|bing|yahoo"),
		flagSet.IntVar(&options.domain_length, "dl", 40, "match domain length that specified."),
	)

	createGroup(flagSet, "matcher options", "MATCHER OPTIONS",
		flagSet.StringVar(&options.content_type, "ct", "", "match response with specified content type"),
		flagSet.IntVar(&options.status_code, "sc", 200, "match response with specified status code"),
		flagSet.IntVar(&options.min_content_length, "cl", 100, "match response with specified minimum content length. e.g. >100"),
	)

	createGroup(flagSet, "http options", "HTTP OPTIONS",
		flagSet.IntVar(&options.timeout, "to", 10, "timeout in seconds."),
		flagSet.StringVar(&options.user_agent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0", "user agent"),
		flagSet.StringVar(&options.proxy, "px", "", "http proxy to use"),
	)

	_ = flagSet.Parse()

	Version := "0.0.2"
	if options.version {
		fmt.Println("Current Version:", Version)
		os.Exit(0)
	}

	return options
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

func banner() {
	fmt.Println(`
  __                               _   _ 
 / _|                             | | (_)
| |_   _   _   ____  ____  _   _  | |  _ 
|  _| | | | | |_  / |_  / | | | | | | | |
| |   | |_| |  / /   / /  | |_| | | | | |
|_|    \__,_| /___| /___|  \__,_| |_| |_|

musana.net | @musana
-------------------------------------------- `)

}
