package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	splunkclient "github.com/norskhelsenett/dnsstats/pkg/clients/splunk"
	"github.com/norskhelsenett/dnsstats/pkg/models/splunkmodels"
	"go.uber.org/zap"
)

type BenchConfig struct {
	Description   string        `json:"description,omitempty"`    // Optional benchmark name
	Hostname      string        `json:"hostname,omitempty"`       // Hostname of the client
	HostAddress   string        `json:"host_address,omitempty"`   // IP address of the client
	Domain        string        `json:"domain"`                   // Domain to query
	DNSType       string        `json:"dns_type,omitempty"`       // DNS record type to query (A or AAAA)
	Datacenter    string        `json:"datacenter,omitempty"`     // Optional datacenter name
	Platform      string        `json:"platform,omitempty"`       // Optional platform name
	Servers       []string      `json:"servers,omitempty"`        // List of DNS servers (ip:port)
	Protocol      string        `json:"protocol,omitempty"`       // Protocol to use (udp/tcp)
	ActualAddress string        `json:"actual_address,omitempty"` // Client IP address (optional)
	Port          int           `json:"port,omitempty"`           // Port to use for DNS servers
	QPS           int           `json:"qps"`                      // Queries per second per server
	Duration      time.Duration `json:"duration"`                 // Benchmark duration
	Timeout       time.Duration `json:"timeout"`                  // Timeout per request
}

type BenchStats struct {
	sync.Mutex    `json:"-"`      // exclude from JSON serialization
	Server        string          `json:"server"`         // exclude from JSON serialization
	TotalRequests int             `json:"total_requests"` // Total number of requests sent
	TotalSuccess  int             `json:"total_success"`  // Total number of successful responses
	TotalFailed   int             `json:"total_failed"`   // Total number of failed requests
	PacketLoss    float64         `json:"packet_loss"`    // Packet loss percentage
	RTTs          []time.Duration `json:"-"`              // exclude from JSON serialization
	RTTMin        time.Duration   `json:"rtt_min"`        // Minimum RTT
	RTTMax        time.Duration   `json:"rtt_max"`        // Maximum RTT
	RTTAvg        time.Duration   `json:"rtt_avg"`        // Average RTT
}

func main() {

	logger, _ := zap.NewProduction()
	defer func() {
		_ = logger.Sync()
	}()

	// Initialize default configuration
	cfg := NewConfig(logger)

	// Override defaults with custom configuration if fields are set
	OverrideConfigWithCustomJSON(&cfg, logger)

	// Update Config with actual IP address
	if err := GetActualIP(&cfg); err != nil {
		logger.Fatal("Failed to get actual IP address", zap.Error(err))
	}

	logger.Info("Starting DNS benchmark",
		zap.Any("config", cfg),
	)

	// Run DNS benchmark
	stats := runDNSBenchmark(cfg, logger)

	// Update stats
	updateStats(stats)

	// Print benchmark summary
	printBenchmarkSummary(cfg, stats)

	// Send results to Splunk HEC (if configured)
	if err := sendToSplunkHEC(cfg, stats, logger); err != nil {
		logger.Fatal("Failed to send results to Splunk HEC", zap.Error(err))
	}
}

func sendToSplunkHEC(cfg BenchConfig, stats []*BenchStats, logger *zap.Logger) error {

	// Check if Splunk HEC configuration is provided
	var splunkConfiguration splunkclient.SplunkClient
	customConfigurationFile, err := os.ReadFile("splunk.json")
	if err != nil {
		logger.Info("could not find valid splunk.yaml file, skip Splunk integation", zap.Error(err))
		return nil
	} else {
		logger.Info("load configuration from splunk.json")
		if err := json.Unmarshal(customConfigurationFile, &splunkConfiguration); err != nil {
			logger.Info("failed to parse file splunk.json, exit", zap.Error(err))
			return err
		}
	}

	splunkClient := splunkclient.NewSplunkClient(
		splunkclient.WithEndpointUrl(splunkConfiguration.EndPointUrl),
		splunkclient.WithToken(splunkConfiguration.Token),
		splunkclient.WithHECIndex(splunkConfiguration.HECIndex),
		splunkclient.WithHECSource(splunkConfiguration.HECSource),
		splunkclient.WithHECSourcetype(splunkConfiguration.HECSourcetype),
		splunkclient.WithDisableTLS(splunkConfiguration.DisableTLS),
		splunkclient.WithTimeout(splunkConfiguration.Timeout),
	)

	// Prepare Splunk HEC request
	for _, stat := range stats {
		stat.Server = strings.TrimSuffix(stat.Server, ":"+strconv.Itoa(cfg.Port))
		request := splunkmodels.Request{
			Event: stat,
			Fields: map[string]string{
				"description":  cfg.Description,
				"domain":       cfg.Domain,
				"dns_type":     cfg.DNSType,
				"datacenter":   cfg.Datacenter,
				"platform":     cfg.Platform,
				"hostname":     cfg.Hostname,
				"host_address": cfg.HostAddress,
				//"server":       stat.Server,
				"protocol": cfg.Protocol,
				"port":     strconv.Itoa(cfg.Port),
				"qps":      strconv.Itoa(cfg.QPS),
				"timeout":  strconv.Itoa(int(cfg.Timeout.Milliseconds())),
			},
			Time:       time.Now().Unix(),
			Index:      splunkConfiguration.HECIndex,
			Source:     splunkConfiguration.HECSource,
			Sourcetype: splunkConfiguration.HECSourcetype,
		}

		// Send data to Splunk HEC
		if err := splunkClient.Send(context.Background(), request); err != nil {
			return err
		}
	}
	logger.Info("Successfully sent benchmark results to Splunk HEC")

	return nil
}

func NewConfig(logger *zap.Logger) BenchConfig {

	systemResolvers, err := SystemResolversFromResolvConf()
	if err != nil {
		logger.Fatal("No DNS servers specified and failed to get system resolvers", zap.Error(err))
	}

	// Override defaults with custom configuration if fields are set
	hostname, err := os.Hostname()
	if err != nil {
		logger.Fatal("Failed to get hostname", zap.Error(err))
	}

	// Sanity check for DefaultDomain
	var sanityDefaultDomain string
	if !strings.HasSuffix(DefaultDomain, ".") {
		sanityDefaultDomain = DefaultDomain + "."
	}

	return BenchConfig{
		Description:   DefaultDescription,
		Domain:        sanityDefaultDomain,
		DNSType:       DefaultDNSType,
		Hostname:      hostname,
		Servers:       systemResolvers,
		Protocol:      DefaultProtocol,
		Port:          DefaultPort,
		ActualAddress: DefaultActualAddress,
		QPS:           DefaultQPS,
		Duration:      DefaultDuration * time.Second,
		Timeout:       DefaultTimeout * time.Millisecond,
	}
}

func OverrideConfigWithCustomJSON(cfg *BenchConfig, logger *zap.Logger) {

	// Retrieve custom configuration or use defaults
	var customConfiguration BenchConfig
	customConfigurationFile, err := os.ReadFile("config.json")
	if err != nil {
		logger.Info("failed to read config file, continue with defaults", zap.Error(err))
		return
	} else {
		logger.Info("load custom configuration from config.json")
		if err := json.Unmarshal(customConfigurationFile, &customConfiguration); err != nil {
			logger.Info("failed to parse file config.json, continue with defaults", zap.Error(err))
			return
		}
	}

	// Override fields only if they are set in custom configuration
	if customConfiguration.Description != "" {
		cfg.Description = customConfiguration.Description
	}
	if customConfiguration.Domain != "" {
		if !strings.HasSuffix(customConfiguration.Domain, ".") {
			customConfiguration.Domain += "."
		}
		cfg.Domain = customConfiguration.Domain
	}
	if customConfiguration.DNSType != "" {
		cfg.DNSType = strings.ToUpper(customConfiguration.DNSType)
	}
	if customConfiguration.Datacenter != "" {
		cfg.Datacenter = customConfiguration.Datacenter
	}
	if customConfiguration.Platform != "" {
		cfg.Platform = customConfiguration.Platform
	}
	if customConfiguration.Protocol != "" {
		cfg.Protocol = customConfiguration.Protocol
	}
	if customConfiguration.Port != DefaultPort {
		cfg.Port = customConfiguration.Port
	}
	if len(customConfiguration.Servers) > 0 {
		cfg.Servers = []string{}
		for _, server := range customConfiguration.Servers {
			cfg.Servers = append(cfg.Servers, server+":"+strconv.Itoa(cfg.Port))
		}
	}
	if customConfiguration.ActualAddress != "" {
		cfg.ActualAddress = customConfiguration.ActualAddress
	}
	if customConfiguration.QPS > 0 {
		cfg.QPS = customConfiguration.QPS
	}
	if customConfiguration.Duration > 0 {
		cfg.Duration = customConfiguration.Duration * time.Second
	}
	if customConfiguration.Timeout > 0 {
		cfg.Timeout = customConfiguration.Timeout * time.Millisecond
	}
}

func updateStats(s []*BenchStats) {

	for _, stat := range s {

		if stat.TotalRequests > 0 {
			stat.PacketLoss = float64(int((100*float64(stat.TotalFailed)/float64(stat.TotalRequests))*100)) / 100
		}

		if len(stat.RTTs) > 0 {
			min, max, avg := calcRTTStats(stat.RTTs)
			stat.RTTMin = min / time.Millisecond
			stat.RTTMax = max / time.Millisecond
			stat.RTTAvg = avg / time.Millisecond
		}
	}

}

func runDNSBenchmark(cfg BenchConfig, logger *zap.Logger) []*BenchStats {
	var wg sync.WaitGroup
	var statsList []*BenchStats
	var statsListMu sync.Mutex

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	interval := time.Second / time.Duration(cfg.QPS)

	for _, server := range cfg.Servers {
		stats := &BenchStats{Server: server}

		wg.Add(1)
		go func(s string, st *BenchStats) {
			defer wg.Done()

			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					statsListMu.Lock()
					statsList = append(statsList, st)
					statsListMu.Unlock()
					return
				case <-ticker.C:
					go func() {
						rtt, err := singleDNSQuery(s, cfg.Domain, cfg.Timeout, cfg.Protocol, cfg.DNSType)
						st.Lock()
						st.TotalRequests++
						if err != nil {
							st.TotalFailed++
							logger.Warn("DNS request failed", zap.String("server", s), zap.Error(err))
						} else {
							st.TotalSuccess++
							st.RTTs = append(st.RTTs, rtt)
							logger.Debug("DNS OK",
								zap.String("server", s),
								zap.Duration("rtt", rtt),
							)
						}
						st.Unlock()
					}()
				}
			}
		}(server, stats)
	}

	wg.Wait()
	return statsList
}

func singleDNSQuery(server, domain string, timeout time.Duration, protocol string, dnsType string) (time.Duration, error) {
	client := &dns.Client{
		Net:     protocol,
		Timeout: timeout,
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.StringToType[dnsType])

	resp, rtt, err := client.Exchange(m, server)
	if err != nil {
		return 0, err
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return 0, fmt.Errorf("rcode=%v", dns.RcodeToString[resp.Rcode])
	}

	return rtt, nil
}

func printBenchmarkSummary(cfg BenchConfig, s []*BenchStats) {

	for _, server := range s {
		fmt.Println("\n================ DNS Benchmark Result ==================")
		fmt.Printf("Description:       %s\n", cfg.Description)
		fmt.Printf("Domain Queried:    %s\n", cfg.Domain)
		fmt.Printf("DNS Record Type:   %s\n", cfg.DNSType)
		fmt.Printf("Client Hostname:   %s\n", cfg.Hostname)
		fmt.Printf("Client Address:    %s\n", cfg.HostAddress)
		fmt.Printf("Test Duration:     %v\n", cfg.Duration)
		fmt.Printf("Server Tested:     %v\n", strings.TrimSuffix(server.Server, ":"+strconv.Itoa(cfg.Port)))
		fmt.Printf("Server Port:       %d\n", cfg.Port)
		fmt.Printf("Protocol:          %s\n", cfg.Protocol)
		fmt.Printf("Queries/sec:       %d \n", cfg.QPS)
		fmt.Printf("Total Requests:    %d\n", server.TotalRequests)
		fmt.Printf("Total Success:     %d\n", server.TotalSuccess)
		fmt.Printf("Total Failed:      %d\n", server.TotalFailed)
		fmt.Printf("Packet Loss:       %.2f%%\n",
			server.PacketLoss)

		if len(server.RTTs) > 0 {
			fmt.Printf("RTT Min (ms):      %v\n", server.RTTMin.Nanoseconds())
			fmt.Printf("RTT Max (ms):      %v\n", server.RTTMax.Nanoseconds())
			fmt.Printf("RTT Avg (ms):      %v\n", server.RTTAvg.Nanoseconds())
		}

		fmt.Println("========================================================")
	}
}

func calcRTTStats(rtts []time.Duration) (time.Duration, time.Duration, time.Duration) {
	min := rtts[0]
	max := rtts[0]
	var sum time.Duration

	for _, r := range rtts {
		if r < min {
			min = r
		}
		if r > max {
			max = r
		}
		sum += r
	}

	return min, max, sum / time.Duration(len(rtts))
}

func SystemResolversFromResolvConf() ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read resolv.conf: %w", err)
	}
	if len(cfg.Servers) == 0 {
		return nil, fmt.Errorf("no nameservers in resolv.conf")
	}
	out := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port)) // usually port "53"
	}
	return out, nil
}

func GetActualIP(cfg *BenchConfig) error {

	response, err := http.Get(cfg.ActualAddress)
	if err != nil {
		return fmt.Errorf("failed to get actual IP address")

	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body")
	}

	cfg.HostAddress = strings.TrimSpace(string(body))

	return nil

}
