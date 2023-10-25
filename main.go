// Copyright 2020 Akamai Technologies, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"

	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	edgegrid "github.com/akamai/AkamaiOPEN-edgegrid-golang/edgegrid"
	"gopkg.in/yaml.v2"
)

const (
	defaultlistenaddress = ":9801"
	namespace            = "edgedns_traffic"
	//MinsInHour            = 60
	HoursInDay = 24
	//DaysInWeek            = 7
	trafficReportInterval = 5 // mins
	lookbackDefaultDays   = 1
	//intervalsPerDay       = (MinsInHour / trafficReportInterval) * HoursInDay
)

var (
	configFile           = kingpin.Flag("config.file", "Edge DNS Traffic exporter configuration file. Default: ./edgedns.yml").Default("edgedns.yml").String()
	listenAddress        = kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests.").Default(defaultlistenaddress).String()
	edgegridHost         = kingpin.Flag("edgedns.edgegrid-host", "The Akamai Edgegrid host auth credential.").String()
	edgegridClientSecret = kingpin.Flag("edgedns.edgegrid-client-secret", "The Akamai Edgegrid client_secret credential.").String()
	edgegridClientToken  = kingpin.Flag("edgedns.edgegrid-client-token", "The Akamai Edgegrid client_token credential.").String()
	edgegridAccessToken  = kingpin.Flag("edgedns.edgegrid-access-token", "The Akamai Edgegrid access_token credential.").String()
	dnsstats             DNSStats
	//include_estimates	= kingpin.Flag("edgedns.end-time", "Flag to include estimates in traffic reports.").Bool()
	//time_zone		= kingpin.Flag("edgedns.time-zone", "The timezone to use for start and end time.").String()

	// invalidMetricChars    = regexp.MustCompile("[^a-zA-Z0-9_:]")
	lookbackDuration = time.Hour * HoursInDay * lookbackDefaultDays
	//edgednsErrorDesc  = prometheus.NewDesc("akamai_edgedns_traffic__error", "Error collecting metrics", nil, nil)
)

// Exporter config
type EdgednsTrafficConfig struct {
	Zones         []string `yaml:"zones"`
	EdgercPath    string   `yaml:"edgerc_path"`
	EdgercSection string   `yaml:"edgerc_section"`
	SummaryWindow string   `yaml:"summary_window"`    // mins, hours, days, [weeks]. Default lookbackDefaultDays
	TSLabel       bool     `yaml:"timestamp_label"`   // Creates time series with traffic timestamp as label
	UseTimestamp  bool     `yaml:"traffic_timestamp"` // Create time series with traffic timestamp
}

type EdgednsTrafficExporter struct {
	TrafficExporterConfig EdgednsTrafficConfig
	LastTimestamp         map[string]time.Time // index by zone name
}

type DNSStats struct {
	mu         sync.Mutex
	dnsreports map[string]DNSReport
	nxdreports map[string]DNSReport
}

func NewEdgednsTrafficExporter(edgednsConfig EdgednsTrafficConfig, lastTimestamp map[string]time.Time) *EdgednsTrafficExporter {
	return &EdgednsTrafficExporter{
		TrafficExporterConfig: edgednsConfig,
		LastTimestamp:         lastTimestamp,
	}
}

// Metric Definitions
// Summaries map by zone
var dnsSummaryMap map[string]prometheus.Summary = make(map[string]prometheus.Summary)
var nxdSummaryMap map[string]prometheus.Summary = make(map[string]prometheus.Summary)

// Interval Hits map by zone
var dnsHitsMap map[string][]int64 = make(map[string][]int64)
var nxdHitsMap map[string][]int64 = make(map[string][]int64)
var hitsMapCap int

// Initialize Akamai Edgegrid Config. Priority order:
// 1. Command line
// 2. Edgerc path
// 3. Environment
// 4. Default
func initAkamaiConfig(trafficExporterConfig EdgednsTrafficConfig) error {

	if *edgegridHost != "" && *edgegridClientSecret != "" && *edgegridClientToken != "" && *edgegridAccessToken != "" {
		edgeconf := edgegrid.Config{}
		edgeconf.Host = *edgegridHost
		edgeconf.ClientToken = *edgegridClientToken
		edgeconf.ClientSecret = *edgegridClientSecret
		edgeconf.AccessToken = *edgegridAccessToken
		edgeconf.MaxBody = 131072
		return edgeInit(edgeconf)
	} else if *edgegridHost != "" || *edgegridClientSecret != "" || *edgegridClientToken != "" || *edgegridAccessToken != "" {
		log.Warnf("Command line Auth Keys are incomplete. Looking for alternate definitions.")
	}

	// Edgegrid will also check for environment variables ...
	err := EdgegridInit(trafficExporterConfig.EdgercPath, trafficExporterConfig.EdgercSection)
	if err != nil {
		log.Fatalf("Error initializing Akamai Edgegrid config: %s", err.Error())
		return err
	}

	log.Debugf("Edgegrid config: [%v]", edgegridConfig)

	return nil

}

// Initialize locally maintained maps
func createZoneMaps(zones []string) {
	for _, zone := range zones {
		labels := prometheus.Labels{"zone": zone}

		dnsSummaryMap[zone] = prometheus.NewSummary(
			prometheus.SummaryOpts{
				Namespace:   namespace,
				Name:        "dns_hits_per_interval_summary",
				Help:        "Number of DNS hits per 5 minute interval (per zone)",
				MaxAge:      lookbackDuration,
				BufCap:      prometheus.DefBufCap * 2,
				ConstLabels: labels,
			})
		nxdSummaryMap[zone] = prometheus.NewSummary(
			prometheus.SummaryOpts{
				Namespace:   namespace,
				Name:        "nxd_hits_per_interval_summary",
				Help:        "Number of NXDomain hits per 5 minute interval (per zone)",
				MaxAge:      lookbackDuration,
				BufCap:      prometheus.DefBufCap * 2,
				ConstLabels: labels,
			})
		intervals := lookbackDuration / (time.Minute * 5)
		hitsMapCap = int(intervals)
		dnsHitsMap[zone] = make([]int64, 0, hitsMapCap)
		nxdHitsMap[zone] = make([]int64, 0, hitsMapCap)
	}
}

// Calculate summary window duration based on config and save in lookbackDuration global variable
func calcSummaryWindowDuration(window string) error {

	var datawin int
	var err error
	var multiplier time.Duration = time.Hour * time.Duration(HoursInDay) // assume days

	log.Debugf("Window: %s", window)
	if window == "" {
		return fmt.Errorf("Summary window not set")
	}
	iunit := window[len(window)-1:]
	if !strings.Contains("mhd", strings.ToLower(iunit)) {
		// no units. default days
		datawin, err = strconv.Atoi(window)
	} else {
		len := window[0 : len(window)-1]
		datawin, err = strconv.Atoi(len)
		if strings.ToLower(iunit) == "m" {
			multiplier = time.Minute
			if err == nil && datawin < trafficReportInterval {
				datawin = trafficReportInterval
			}
		} else if strings.ToLower(iunit) == "h" {
			multiplier = time.Hour
		}
	}
	if err != nil {
		log.Warnf("ERROR: %s", err.Error())
		return err
	}
	log.Debugf("multiplier: [%v} units: [%v]", multiplier, datawin)
	lookbackDuration = multiplier * time.Duration(datawin)
	return nil

}

func syncMetricsWorker(e EdgednsTrafficConfig) {
	for {
		for _, zone := range e.Zones {
			fmt.Println(zone)
			log.Debugf("Processing zone %s", zone)
			dnsreport, ratelimit, err := TrafficReportDetail(zone, "/reporting-api/v1/reports/authoritative-dns-queries-by-zone/versions/1/report-data")
			if err != nil {
				log.Warnf("Unable to get traffic report for zone %s: %s", zone, err)
			} else {
				dnsstats.mu.Lock()
				dnsstats.dnsreports[zone] = dnsreport
				dnsstats.mu.Unlock()
			}
			if ratelimit == "0" {
				// add some extra sleep to avoid 429 Rate Limit
				time.Sleep(30 * time.Second)
			} else {
				time.Sleep(2 * time.Second)
			}
			nxdreport, ratelimit, err := TrafficReportDetail(zone, "/reporting-api/v1/reports/authoritative-dns-nxdomains-by-zone/versions/1/report-data")
			if err != nil {
				log.Warnf("Unable to get traffic report for zone %s: %s", zone, err)
			} else {
				dnsstats.mu.Lock()
				dnsstats.nxdreports[zone] = nxdreport
				dnsstats.mu.Unlock()
			}
			if ratelimit == "0" {
				// add some extra sleep to avoid 429 Rate Limit
				time.Sleep(30 * time.Second)
			} else {
				time.Sleep(2 * time.Second)
			}
		}
	}
}

// Describe function
func (e *EdgednsTrafficExporter) Describe(ch chan<- *prometheus.Desc) {

	ch <- prometheus.NewDesc("akamai_edgedns", "Akamai Edgedns", nil, nil)
}

// Collect function
func (e *EdgednsTrafficExporter) Collect(ch chan<- prometheus.Metric) {
	log.Debugf("Entering EdgeDNS Collect")
	dnsstats.mu.Lock()
	for zone, metric := range dnsstats.dnsreports {
		for _, record := range metric.Data {
			var tsLabels = []string{"zone", "record"}
			desc := prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "dns_requests_24h"), "Number of DNS hits last 24h per record (5 minute interval)", tsLabels, nil)
			var dnsmetric prometheus.Metric
			sumhits, _ := strconv.Atoi(record.SumHits)
			dnsmetric = prometheus.MustNewConstMetric(
				desc, prometheus.GaugeValue, float64(sumhits), zone, record.RecordName)
			ch <- dnsmetric
		}
	}
	for zone, metric := range dnsstats.nxdreports {
		for _, record := range metric.Data {
			var tsLabels = []string{"zone", "record"}
			desc := prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "nxd_requests_24h"), "Number of NXDOMAIN hits last 24h per record (5 minute interval)", tsLabels, nil)
			var dnsmetric prometheus.Metric
			sumhits, _ := strconv.Atoi(record.SumHits)
			dnsmetric = prometheus.MustNewConstMetric(
				desc, prometheus.GaugeValue, float64(sumhits), zone, record.RecordName)
			ch <- dnsmetric
		}
	}
	dnsstats.mu.Unlock()
}

func init() {
	prometheus.MustRegister(version.NewCollector("akamai_edgedns_traffic_exporter"))
}

func main() {

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("akamai_edgedns_traffic_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infof("Config file: %s", *configFile)

	log.Info("Starting Edge DNS Traffic exporter", version.Info())
	log.Info("Build context", version.BuildContext())

	edgednsTrafficConfig, err := loadConfig(*configFile) // save?
	if err != nil {
		log.Fatalf("Error loading akamai_edgedns_traffic_exporter config file: %v", err)
	}

	log.Debugf("Exporter configuration: [%v]", edgednsTrafficConfig)

	// Initalize Akamai Edgegrid ...
	err = initAkamaiConfig(edgednsTrafficConfig)
	if err != nil {
		log.Fatalf("Error initializing Akamai Edgegrid config: %s", err.Error())
	}

	zones, err := GetAllZones()
	if err != nil {
		fmt.Println(err)
	}
	edgednsTrafficConfig.Zones = zones
	dnsstats.dnsreports = make(map[string]DNSReport) // init map
	dnsstats.nxdreports = make(map[string]DNSReport) // init map
	go syncMetricsWorker(edgednsTrafficConfig)       // start sync goroutine

	tstart := time.Now().UTC().Add(time.Minute * time.Duration(trafficReportInterval*-1)) // assume start time is Exporter launch less 5 mins
	if edgednsTrafficConfig.SummaryWindow != "" {
		err = calcSummaryWindowDuration(edgednsTrafficConfig.SummaryWindow)
		if err == nil {
			tstart = time.Now().UTC().Add(lookbackDuration * -1)
		} else {
			log.Warnf("Retention window is not valid. Using default (%d days)", lookbackDefaultDays)
		}
	} else {
		log.Warnf("Retention window is not configured. Using default (%d days)", lookbackDefaultDays)
	}
	log.Infof("Edge DNS Traffic exporter start time: %v", tstart)

	lastTimeStamp := make(map[string]time.Time) // index by zone name
	for _, zone := range edgednsTrafficConfig.Zones {
		lastTimeStamp[zone] = tstart
	}

	// Create/register collector
	edgednsTrafficCollector := NewEdgednsTrafficExporter(edgednsTrafficConfig, lastTimeStamp)
	prometheus.MustRegister(edgednsTrafficCollector)

	// Create and register Summaries
	//createZoneMaps(edgednsTrafficConfig.Zones)
	//for _, sum := range dnsSummaryMap {
	//	prometheus.MustRegister(sum)
	//}
	//for _, sum := range nxdSummaryMap {
	//	prometheus.MustRegister(sum)
	//}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>akamai_edgedns_traffic_exporter</title></head>
			<body>
			<h1>akamai_edgedns_traffic_exporter</h1>
			<p><a href="/metrics">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Info("Beginning to serve on address ", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))

}

func loadConfig(configFile string) (EdgednsTrafficConfig, error) {
	if fileExists(configFile) {
		// Load config from file
		configData, err := ioutil.ReadFile(configFile)
		if err != nil {
			return EdgednsTrafficConfig{}, err
		}

		return loadConfigContent(configData)
	}

	log.Infof("Config file %v does not exist, using default values", configFile)
	return EdgednsTrafficConfig{}, nil

}

func loadConfigContent(configData []byte) (EdgednsTrafficConfig, error) {
	config := EdgednsTrafficConfig{}

	err := yaml.Unmarshal(configData, &config)
	if err != nil {
		return config, err
	}

	log.Info("akamai_edgedns_traffic_exporter config loaded")
	return config, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
