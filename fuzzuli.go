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
	"github.com/hashicorp/go-retryablehttp"
	"github.com/projectdiscovery/goflags"
	"github.com/schollz/progressbar/v3"
)

var urls, paths, methods []string

var options *Options
var extensions = []string{".rar", ".zip", ".tar.gz", ".tar", ".gz", ".jar", ".7z", ".bz2", ".sql", ".backup", ".war", ".bak"}

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

var bar = progressbar.Default(-1, "request count")

func main() {

	options = ParseOptions()

	if options.banner {
		banner()
		os.Exit(0)
	}

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

	if options.method == "all" {
		m := "regular,withoutdots,withoutvowels,reverse,mixed,withoutdv,shuffle"
		methods = strings.Split(m, ",")
	} else {
		methods = strings.Split(options.method, ",")
	}

	if options.paths != "/" {
		paths = strings.Split(options.paths, ",")
	} else {
		paths = strings.Split(options.paths, "")
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
			getAllCombination(domain)
		}
	}
}

func getAllCombination(domain string) {
	generate_wordlist := []string{}

	for _, method := range methods {
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

	wpx := workerpool.New(16)

	for _, word := range generate_wordlist {
		word := word
		wpx.Submit(func() {
			headRequest(domain, word)
		})
	}
	wpx.StopWait()

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

	req, _ := http.NewRequest(options.http_method, url, nil)
	req.Header.Add("User-Agent", options.user_agent)
	return req

}

func httpClient(proxy string) *http.Client {

	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     time.Second * 5,
		DisableKeepAlives:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Second * 10,
			KeepAlive: time.Second * 10,
		}).DialContext,
	}

	if proxy != "" {
		if p, err := url.Parse(options.proxy); err == nil {
			tr.Proxy = http.ProxyURL(p)
		}
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.RetryWaitMax = time.Second * 3
	retryClient.Logger = nil
	retryClient.HTTPClient.Transport = tr
	httpClient := retryClient.StandardClient()

	return httpClient

}

func headRequest(domain string, word string) {
	for _, e := range extensions {
		for _, path := range paths {
			url := domain + path + options.prefix + word + options.suffix + e

			if options.print {
				fmt.Println("[-]", url)
			}

			client := httpClient(options.proxy)
			resp, err := client.Do(requestBuilder(url))

			if options.http_method == "GET" {
				defer resp.Body.Close()
			}

			bar.Add(1)

			if err == nil {
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
}

func timeInfo(t string) {
	ctime := fmt.Sprintf("\n[*] Scan "+t+" time: %s", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println(string("\033[36m") + ctime + string("\033[0m"))
}

type Options struct {
	content_type       string
	http_method        string
	user_agent         string
	extension          string
	exclude            string
	replace            string
	method             string
	prefix             string
	suffix             string
	remove             string
	paths              string
	file               string
	proxy              string
	worker             int
	timeout            int
	status_code        int
	domain_length      int
	min_content_length int
	version            bool
	banner             bool
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
		flagSet.StringVar(&options.paths, "pt", "/", "paths. separate with commas to use multiple paths. e.g. /,/db/,/old/"),
		flagSet.BoolVar(&options.print, "p", false, "print urls that is sent request"),
		flagSet.BoolVar(&options.version, "v", false, "print version"),
		flagSet.BoolVar(&options.help, "help", false, "print this"),
		flagSet.BoolVar(&options.banner, "banner", false, "print banner"),
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
		flagSet.StringVar(&options.http_method, "hm", "HEAD", "HTTP Method."),
		flagSet.StringVar(&options.proxy, "px", "", "http proxy to use"),
	)

	_ = flagSet.Parse()

	Version := "v1.1.1"
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
