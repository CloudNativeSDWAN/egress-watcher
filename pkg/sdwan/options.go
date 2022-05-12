package sdwan

import "time"

const (
	DefaultWaitingWindow time.Duration = time.Minute
)

type Authentication struct {
	Username  string
	Password  string
	SessionID string
	XSRFToken string
}

type Options struct {
	BaseURL        string         `yaml:"baseUrl"`
	Insecure       bool           `yaml:"insecure"`
	WaitingWindow  *time.Duration `yaml:"waitingWindow"`
	Authentication *Authentication
}
