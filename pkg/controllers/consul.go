package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/CloudNativeSDWAN/egress-watcher/pkg/sdwan"
	"github.com/hashicorp/consul/api"
	"github.com/rs/zerolog"
)

func NewConsulPoller(ctx context.Context, address string, opsChan chan *sdwan.Operation, logger zerolog.Logger) error {
	logger.Info().Msg("starting checking for consul")

	config := func() *api.Config {
		if address == "localhost" {
			return api.DefaultConfig()
		}

		return &api.Config{Address: address}
	}()
	client, err := api.NewClient(config)
	if err != nil {
		return fmt.Errorf("cannot get client: %w", err)
	}

	lastDiscovered := map[string]bool{}
	namesChan := make(chan string, 100)
	ticker := time.NewTicker(2 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			services, _, err := client.Catalog().Services(&api.QueryOptions{})
			if err != nil {
				return fmt.Errorf("error while checking services: %w", err)
			}

			for servName := range services {
				if _, exists := lastDiscovered[servName]; !exists {
					namesChan <- servName
					lastDiscovered[servName] = true
				}
			}
		case servName := <-namesChan:
			serv, _, err := client.Catalog().Service(servName, "", &api.QueryOptions{})
			if err != nil {
				return fmt.Errorf("cannot get service with name %s: %w", servName, err)
			}

			server := serv[0].Address
			logger.Info().Str("address", server).Msg("discovered address")
			if server != "localhost" && server != "127.0.0.1" {
				l := logger.With().Str("service", servName).Logger()
				healthchecks, _, err := client.Health().Service(servName, "", false, &api.QueryOptions{})
				if err != nil {
					l.Err(err).Msg("could not get health checks for service, skipping...")
					continue
				}

				if len(healthchecks) == 0 {
					l.Info().Msg("service has no health checks, skipping...")
					continue
				}

				if len(healthchecks[0].Checks) == 0 {
					l.Info().Msg("service has no checks inside health checks, skipping...")
					continue
				}

				def := healthchecks[0].Checks[0].Definition.HTTP
				l.Info().Str("health-check", def).Msg("found health check for service")
				opsChan <- &sdwan.Operation{
					Type:            sdwan.OperationAdd,
					ApplicationName: servName,
					Servers:         []string{serv[0].Address},
					CustomProbe:     def,
					CustomProbeType: "url",
				}
			}
		}
	}
}
