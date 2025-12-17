package splunkmodels

type Request struct {
	Event      any               `json:"event"`                // The event data
	Index      string            `json:"index,omitempty"`      // Index to send the event to (optional)
	Source     string            `json:"source,omitempty"`     // Source of the event (optional)
	Sourcetype string            `json:"sourcetype,omitempty"` // Sourcetype of the event (optional)
	Fields     map[string]string `json:"fields,omitempty"`     // Additional fields (optional)
	Time       int64             `json:"time,omitempty"`       // Event timestamp (optional)
}
type Response struct {
	Text string `json:"text"` // Response text from Splunk HEC
	Code int    `json:"code"` // HTTP status code
}
