package main

import (
	//"bufio"
	"crypto/tls"
	//"fmt"
	//"net"
	//"net/http"
	//"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	dependencyLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "service_http_request_processing_duration_seconds",
			Help:       "RPC latency distributions.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"type", "name", "target"},
	)
)

func singleTLSProbe(target, name string, config *tls.Config) error {
	startTime := time.Now()
	conn, err := tls.Dial("tcp", target, config)
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	conn.Close()
	finishTime := time.Now()
	return nil
}
