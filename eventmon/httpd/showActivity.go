package httpd

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/Symantec/Dominator/lib/format"
	"github.com/Symantec/Dominator/lib/html"
	"github.com/Symantec/keymaster/eventmon/eventrecorder"
)

const (
	durationDay   = time.Hour * 24
	durationWeek  = durationDay * 7
	durationMonth = durationDay * 31
)

type counterType struct {
	authPassword    uint64
	authSymantecVIP uint64
	authU2F         uint64
	ssh             uint64
	webLogin        uint64
	x509            uint64
}

func (s state) showActivityHandler(w http.ResponseWriter, req *http.Request) {
	writer := bufio.NewWriter(w)
	defer writer.Flush()
	fmt.Fprintln(writer, "<title>keymaster-eventmond activity report</title>")
	fmt.Fprintln(writer, `<style>
                          table, th, td {
                          border-collapse: collapse;
                          }
                          </style>`)
	fmt.Fprintln(writer, "<body>")
	fmt.Fprintln(writer, "<center>")
	fmt.Fprintln(writer, "<h1>keymaster-eventmond activity report</h1>")
	fmt.Fprintln(writer, "</center>")
	s.writeActivity(writer)
	fmt.Fprintln(writer, "<hr>")
	html.WriteFooter(writer)
	fmt.Fprintln(writer, "</body>")
}

func (s state) writeActivity(writer io.Writer) {
	fmt.Fprintln(writer, "SSH/Web/X509 Password/SymantecVIP/U2F")
	fmt.Fprintln(writer, `<table border="1" style="width:100%">`)
	fmt.Fprintln(writer, "  <tr>")
	fmt.Fprintln(writer, "    <th>Username</th>")
	fmt.Fprintln(writer, "    <th>Last Day</th>")
	fmt.Fprintln(writer, "    <th>Last Week</th>")
	fmt.Fprintln(writer, "    <th>Last Month</th>")
	fmt.Fprintln(writer, "    <th>Min Lifetime</th>")
	fmt.Fprintln(writer, "    <th>Med Lifetime</th>")
	fmt.Fprintln(writer, "    <th>Max Lifetime</th>")
	fmt.Fprintln(writer, "  </tr>")
	eventsChannel := make(chan eventrecorder.Events, 1)
	s.eventRecorder.RequestEventsChannel <- eventsChannel
	eventsMap := <-eventsChannel
	startTime := time.Now()
	usernames := make([]string, 0, len(eventsMap.Events))
	for username := range eventsMap.Events {
		if len(eventsMap.Events[username]) > 0 {
			usernames = append(usernames, username)
		}
	}
	sort.Strings(usernames)
	for _, username := range usernames {
		writeUser(writer, username, eventsMap.Events[username])
	}
	fmt.Fprintln(writer, "</table>")
	renderTime := time.Since(startTime)
	fmt.Fprintf(writer,
		"<br><font color=\"grey\">Fetch time: %s render time: %s</font>\n",
		format.Duration(eventsMap.ComputeTime), format.Duration(renderTime))
}

func writeUser(writer io.Writer, username string,
	events []eventrecorder.EventType) {
	var countOverLastDay, countOverLastWeek, countOverLastMonth counterType
	now := time.Now()
	minLifetime := durationMonth * 120
	maxLifetime := time.Duration(-1)
	lifetimes := make([]int, 0, len(events))
	for _, event := range events {
		if event.LifetimeSeconds > 0 {
			lifetime := time.Duration(event.LifetimeSeconds) * time.Second
			lifetimes = append(lifetimes, int(event.LifetimeSeconds))
			if lifetime < minLifetime {
				minLifetime = lifetime
			}
			if lifetime > maxLifetime {
				maxLifetime = lifetime
			}
		}
		age := now.Sub(time.Unix(int64(event.CreateTime), 0))
		if age <= durationDay {
			countOverLastDay.increment(event)
		}
		if age <= durationWeek {
			countOverLastWeek.increment(event)
		}
		if age <= durationMonth {
			countOverLastMonth.increment(event)
		}
	}
	fmt.Fprintf(writer, "  <tr>\n")
	fmt.Fprintf(writer, "    <td>%s</td>\n", username)
	fmt.Fprintf(writer, "    <td>%s</td>\n", countOverLastDay.string())
	fmt.Fprintf(writer, "    <td>%s</td>\n", countOverLastWeek.string())
	fmt.Fprintf(writer, "    <td>%s</td>\n", countOverLastMonth.string())
	if len(lifetimes) > 0 {
		sort.Ints(lifetimes)
		medLifetime := time.Duration(lifetimes[len(lifetimes)/2]) * time.Second
		fmt.Fprintf(writer, "    <td>%s</td>\n", format.Duration(minLifetime))
		fmt.Fprintf(writer, "    <td>%s</td>\n", format.Duration(medLifetime))
		fmt.Fprintf(writer, "    <td>%s</td>\n", format.Duration(maxLifetime))
	} else {
		fmt.Fprintln(writer, "    <td></td>")
		fmt.Fprintln(writer, "    <td></td>")
		fmt.Fprintln(writer, "    <td></td>")
	}
	fmt.Fprintf(writer, "  </tr>\n")
}

func (counter *counterType) increment(event eventrecorder.EventType) {
	if authInfo := event.AuthInfo; authInfo != nil {
		switch authInfo.AuthType {
		case eventrecorder.AuthTypePassword:
			counter.authPassword++
		case eventrecorder.AuthTypeSymantecVIP:
			counter.authSymantecVIP++
		case eventrecorder.AuthTypeU2F:
			counter.authU2F++
		}
	}
	if event.Ssh {
		counter.ssh++
	}
	if event.WebLogin {
		counter.webLogin++
	}
	if event.X509 {
		counter.x509++
	}
}

func (counter *counterType) string() string {
	return fmt.Sprintf("%d/%d/%d %d/%d/%d",
		counter.ssh, counter.webLogin, counter.x509,
		counter.authPassword, counter.authSymantecVIP, counter.authU2F)
}
