package main

const (
	DefaultDescription   = "DNS Benchmark"         // Default benchmark name
	DefaultDomain        = "example.com"           // Domain to query
	DefaultDNSType       = "A"                     // DNS record type to query (A or AAAA)
	DefaultDuration      = 10                      // Seconds
	DefaultQPS           = 50                      // Queries per second per server
	DefaultTimeout       = 1500                    // Milliseconds
	DefaultProtocol      = "udp"                   // udp or tcp
	DefaultPort          = 53                      // DNS port
	DefaultActualAddress = "https://api.ipify.org" // Service to get actual IP address
)
