package main

import (
	//"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	//"fmt"
	//"net"
	//"net/http"
	//"net/url"
	"strings"
	"time"

	"github.com/Symantec/keymaster/lib/authutil"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	dependencyLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "keymaster_dependency_check_duration_seconds",
			Help:       "Dependency latency.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"type", "name", "target"},
	)
	dependencyLastSuccessSecondsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keymaster_dependency_durations_since_last_success_seconds",
			Help: "Seconds since last update",
		},
		[]string{"type", "name"},
	)
	lastSuccessLDAPPasswordTime time.Time
	lastSuccessLDAPUserInfoTime time.Time
)

const timeoutSecs = 5

func init() {
	prometheus.MustRegister(dependencyLatency)
	prometheus.MustRegister(dependencyLastSuccessSecondsGauge)
}

func singleTLSProbe(target, name string, config *tls.Config) error {
	// TODO: add timeout
	startTime := time.Now()
	conn, err := tls.Dial("tcp", target, config)
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	conn.Close()
	finishTime := time.Now()
	ElapsedTime := finishTime.Sub(startTime)
	dependencyLatency.WithLabelValues("tls", name, target).Observe(ElapsedTime.Seconds())
	return nil
}

func checkCheckLDAPURLs(ldapURLs string, name string, rootCAs *x509.CertPool) error {
	if len(ldapURLs) <= 0 {
		return errors.New("No data to check")
	}
	//var ldapURL []*url.URL
	urlList := strings.Split(ldapURLs, ",")
	for _, stringURL := range urlList {
		url, err := authutil.ParseLDAPURL(stringURL)
		if err != nil {
			return err
		}
		startTime := time.Now()
		err = authutil.CheckLDAPConnection(*url, timeoutSecs, rootCAs)
		if err != nil {
			continue
		}
		dependencyLatency.WithLabelValues("ldap", name, stringURL).Observe(time.Now().Sub(startTime).Seconds())
		return nil
	}
	return errors.New("Check Failed")
}

func checkLDAPConfigs(config AppConfigFile, rootCAs *x509.CertPool) {
	if len(config.Ldap.LDAPTargetURLs) > 0 {
		err := checkCheckLDAPURLs(config.Ldap.LDAPTargetURLs, "passwd", rootCAs)
		if err != nil {
			logger.Debugf(1, "password LDAP check Failed %s", err)
		} else {
			lastSuccessLDAPPasswordTime = time.Now()
		}
		dependencyLastSuccessSecondsGauge.WithLabelValues("ldap", "passwd").
			Set(time.Now().Sub(lastSuccessLDAPPasswordTime).Seconds())
	}
	ldapConfig := config.UserInfo.Ldap
	if len(ldapConfig.LDAPTargetURLs) > 0 {
		err := checkCheckLDAPURLs(ldapConfig.LDAPTargetURLs, "userinfo", rootCAs)
		if err != nil {
			logger.Debugf(1, "userinfo LDAP check Failed %s", err)
		} else {
			lastSuccessLDAPUserInfoTime = time.Now()
		}
		dependencyLastSuccessSecondsGauge.WithLabelValues("ldap", "userinfo").
			Set(time.Now().Sub(lastSuccessLDAPUserInfoTime).Seconds())
	}
}

func (state *RuntimeState) doDependencyMonitoring(secsBetweenChecks int) {
	for {
		checkLDAPConfigs(state.Config, nil)
		time.Sleep(time.Duration(secsBetweenChecks) * time.Second)
	}
}
