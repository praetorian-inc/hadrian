package oob

import (
	"context"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

// Config holds OOB client configuration
type Config struct {
	ServerURL   string        // interactsh server (default: oast.live)
	Token       string        // optional auth token
	PollTimeout time.Duration // how long to poll for interactions
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		ServerURL:   "oast.live",
		PollTimeout: 10 * time.Second,
	}
}

// Interaction represents an OOB callback received
type Interaction struct {
	Protocol  string    // http, dns, smtp
	URL       string    // full URL that was accessed
	UniqueID  string    // unique interaction ID
	Timestamp time.Time // when interaction occurred
	RemoteIP  string    // source IP
	RawData   string    // raw request data
}

// Client wraps interactsh for OOB detection
type Client struct {
	interactsh *client.Client
	config     Config
}

// NewClient creates a new OOB client
func NewClient(cfg Config) (*Client, error) {
	opts := &client.Options{
		ServerURL: cfg.ServerURL,
		Token:     cfg.Token,
	}

	c, err := client.New(opts)
	if err != nil {
		return nil, err
	}

	return &Client{
		interactsh: c,
		config:     cfg,
	}, nil
}

// GenerateURL returns a unique callback URL for this session
func (c *Client) GenerateURL() string {
	return c.interactsh.URL()
}

// Poll checks for interactions within the timeout period
func (c *Client) Poll(ctx context.Context) ([]Interaction, error) {
	var interactions []Interaction

	// Create polling context with timeout
	pollCtx, cancel := context.WithTimeout(ctx, c.config.PollTimeout)
	defer cancel()

	// Poll for interactions using callback
	c.interactsh.StartPolling(c.config.PollTimeout, func(i *server.Interaction) {
		interactions = append(interactions, Interaction{
			Protocol:  i.Protocol,
			URL:       i.FullId,
			UniqueID:  i.UniqueID,
			Timestamp: time.Now(),
			RemoteIP:  i.RemoteAddress,
			RawData:   i.RawRequest,
		})
	})

	// Wait for timeout or context cancellation
	<-pollCtx.Done()
	c.interactsh.StopPolling()

	return interactions, nil
}

// Close releases resources
func (c *Client) Close() {
	if c.interactsh != nil {
		c.interactsh.Close()
	}
}
