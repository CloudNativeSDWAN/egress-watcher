package sdwan

type Authentication struct {
	Username  string
	Password  string
	SessionID string
	XSRFToken string
}

type Options struct {
	BaseURL  string `yaml:"baseUrl"`
	Insecure bool   `yaml:"insecure"`

	Authentication *Authentication
}
