package splunkclient

type Option func(*SplunkClient)

func NewsplunkClient(opts ...Option) *SplunkClient {
	config := &SplunkClient{
		Timeout:           10,    // Default timeout of 10 seconds,
		DisableTLS:        false, // Default to TLS verification enabled
		DisableKeepAlives: false, // Default to disable HTTP keep-alives
	}

	for _, opt := range opts {
		opt(config)
	}

	return config
}

func WithToken(token string) Option {
	return func(c *SplunkClient) {
		c.Token = token
	}
}

func WithEndpointUrl(endpointUrl string) Option {
	return func(c *SplunkClient) {
		c.EndPointUrl = endpointUrl
	}
}

func WithHECIndex(index string) Option {
	return func(c *SplunkClient) {
		c.HECIndex = index
	}
}

func WithHECSource(source string) Option {
	return func(c *SplunkClient) {
		c.HECSource = source
	}
}

func WithHECSourcetype(sourcetype string) Option {
	return func(c *SplunkClient) {
		c.HECSourcetype = sourcetype
	}
}

func WithDisableTLS(disable bool) Option {
	return func(c *SplunkClient) {
		c.DisableTLS = disable
	}
}
func WithTimeout(timeout int) Option {
	return func(c *SplunkClient) {
		c.Timeout = timeout
	}
}
